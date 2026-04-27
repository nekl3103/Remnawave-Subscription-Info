package main

import (
	"bufio"
	"crypto/ed25519"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestParseServersFromServersList(t *testing.T) {
	body := []byte(`{
		"servers": [
			{"name": "NL-1", "server": "nl.example.com", "port": 443, "type": "vless"},
			{"remarks": "DE-1", "address": "de.example.com", "port": "8443", "protocol": "vmess"}
		]
	}`)

	servers, err := parseServers(body)
	if err != nil {
		t.Fatalf("parseServers returned error: %v", err)
	}

	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}

	if servers[0].Name != "NL-1" || servers[0].Address != "nl.example.com" || servers[0].Port != "443" || servers[0].Protocol != "vless" {
		t.Fatalf("unexpected first server: %+v", servers[0])
	}

	if servers[1].Name != "DE-1" || servers[1].Address != "de.example.com" || servers[1].Port != "8443" || servers[1].Protocol != "vmess" {
		t.Fatalf("unexpected second server: %+v", servers[1])
	}
}

func TestParseServersFromNestedProxies(t *testing.T) {
	body := []byte(`{
		"subscription": {
			"proxies": [
				{"ps": "US-1", "add": "us.example.com", "port": 2053}
			]
		}
	}`)

	servers, err := parseServers(body)
	if err != nil {
		t.Fatalf("parseServers returned error: %v", err)
	}

	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}

	if servers[0].Name != "US-1" || servers[0].Address != "us.example.com" || servers[0].Port != "2053" {
		t.Fatalf("unexpected server: %+v", servers[0])
	}
}

func TestParseServersFromBase64Subscription(t *testing.T) {
	body := []byte("dmxlc3M6Ly91c2VyQG5sLmV4YW1wbGUuY29tOjQ0Mz90eXBlPXRjcCNOTC0xCnRyb2phbjovL3Bhc3NAZGUuZXhhbXBsZS5jb206ODQ0Mz9zZWN1cml0eT10bHMjREUtMQ==")

	servers, err := parseServers(body)
	if err != nil {
		t.Fatalf("parseServers returned error: %v", err)
	}

	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}

	if servers[0].Name != "NL-1" || servers[0].Address != "nl.example.com" || servers[0].Port != "443" || servers[0].Protocol != "vless" {
		t.Fatalf("unexpected first server: %+v", servers[0])
	}

	if servers[1].Name != "DE-1" || servers[1].Address != "de.example.com" || servers[1].Port != "8443" || servers[1].Protocol != "trojan" {
		t.Fatalf("unexpected second server: %+v", servers[1])
	}
}

func TestParseHysteriaServer(t *testing.T) {
	body := []byte(`{
		"outbounds": [
			{
				"type": "hysteria2",
				"tag": "HY2-1",
				"server": "hy.example.com",
				"server_port": 443,
				"password": "secret",
				"tls": {
					"enabled": true,
					"server_name": "example.com"
				}
			}
		]
	}`)

	servers, err := parseServers(body)
	if err != nil {
		t.Fatalf("parseServers returned error: %v", err)
	}

	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}

	if servers[0].Name != "HY2-1" || servers[0].Address != "hy.example.com" || servers[0].Port != "443" || servers[0].Protocol != "hysteria2" {
		t.Fatalf("unexpected server: %+v", servers[0])
	}

	if servers[0].Details["password"] != "secret" || servers[0].Details["tls.server_name"] != "example.com" {
		t.Fatalf("unexpected details: %+v", servers[0].Details)
	}
}

func TestParseAllServersKeepsSameNameDifferentAddress(t *testing.T) {
	bodyA := []byte(`{"servers":[{"name":"NL","server":"nl1.example.com","port":443,"type":"vless"}]}`)
	bodyB := []byte(`{"servers":[{"name":"NL","server":"nl2.example.com","port":443,"type":"vless"}]}`)

	servers, err := parseAllServers([][]byte{bodyA, bodyB})
	if err != nil {
		t.Fatalf("parseAllServers returned error: %v", err)
	}

	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d: %+v", len(servers), servers)
	}
}

func TestParseAllServersFiltersInvalidServers(t *testing.T) {
	body := []byte(`{"servers":[
		{"name":"OK","server":"ok.example.com","port":443,"type":"vless"},
		{"name":"No address","port":443,"type":"vless"},
		{"name":"No port","server":"no-port.example.com","type":"trojan"},
		{"name":"Unsupported","server":"vmess.example.com","port":443,"type":"vmess"}
	]}`)

	servers, err := parseAllServers([][]byte{body})
	if err != nil {
		t.Fatalf("parseAllServers returned error: %v", err)
	}

	if len(servers) != 1 || servers[0].Name != "OK" {
		t.Fatalf("expected only valid server, got %+v", servers)
	}
}

func TestFetchSubscriptionsFallsBackAfterFirstRequestFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.Header.Get("User-Agent") {
		case "singbox":
			http.Error(writer, "singbox failed", http.StatusInternalServerError)
		case "Happ/1.0":
			_, _ = writer.Write([]byte("happ-body"))
		default:
			_, _ = writer.Write([]byte("fallback-body"))
		}
	}))
	defer server.Close()

	bodies, err := fetchSubscriptions(server.URL)
	if err != nil {
		t.Fatalf("fetchSubscriptions returned error: %v", err)
	}
	if len(bodies) != 2 || string(bodies[0]) != "happ-body" || string(bodies[1]) != "fallback-body" {
		t.Fatalf("unexpected bodies: %q", bodies)
	}
}

func TestVlessShareLinkRealityOutbound(t *testing.T) {
	server, ok := parseShareLink("vless://uuid@example.com:443?security=reality&sni=example.com&pbk=pub&sid=abc&fp=chrome&type=grpc&serviceName=svc&flow=xtls-rprx-vision#NL")
	if !ok {
		t.Fatal("parseShareLink returned false")
	}

	outbound, err := singBoxOutbound(server)
	if err != nil {
		t.Fatalf("singBoxOutbound returned error: %v", err)
	}

	tls := outbound["tls"].(map[string]any)
	reality := tls["reality"].(map[string]any)
	transport := outbound["transport"].(map[string]any)

	if outbound["type"] != "vless" || outbound["uuid"] != "uuid" || outbound["flow"] != "xtls-rprx-vision" {
		t.Fatalf("unexpected outbound: %+v", outbound)
	}
	if tls["server_name"] != "example.com" || reality["public_key"] != "pub" || reality["short_id"] != "abc" {
		t.Fatalf("unexpected tls: %+v", tls)
	}
	if transport["type"] != "grpc" || transport["service_name"] != "svc" {
		t.Fatalf("unexpected transport: %+v", transport)
	}
}

func TestVlessOutboundFromDetailsAddsRealityAndTransport(t *testing.T) {
	outbound, err := singBoxOutbound(Server{
		Address:  "example.com",
		Port:     "443",
		Protocol: "vless",
		Details: map[string]string{
			"uuid":                 "uuid",
			"flow":                 "xtls-rprx-vision",
			"security":             "reality",
			"sni":                  "sni.example.com",
			"pbk":                  "pub",
			"sid":                  "abc",
			"fp":                   "chrome",
			"network":              "grpc",
			"grpcSettings.service": "ignored",
			"serviceName":          "svc",
		},
	})
	if err != nil {
		t.Fatalf("singBoxOutbound returned error: %v", err)
	}

	tls := outbound["tls"].(map[string]any)
	reality := tls["reality"].(map[string]any)
	utls := tls["utls"].(map[string]any)
	transport := outbound["transport"].(map[string]any)

	if outbound["uuid"] != "uuid" || outbound["flow"] != "xtls-rprx-vision" {
		t.Fatalf("unexpected outbound: %+v", outbound)
	}
	if tls["server_name"] != "sni.example.com" || reality["public_key"] != "pub" || reality["short_id"] != "abc" || utls["fingerprint"] != "chrome" {
		t.Fatalf("unexpected tls: %+v", tls)
	}
	if transport["type"] != "grpc" || transport["service_name"] != "svc" {
		t.Fatalf("unexpected transport: %+v", transport)
	}
}

func TestTrojanShareLinkTLSOutbound(t *testing.T) {
	server, ok := parseShareLink("trojan://secret@example.com:443?security=tls&sni=sni.example.com&type=ws&path=%2Fws&host=cdn.example.com#TR")
	if !ok {
		t.Fatal("parseShareLink returned false")
	}

	outbound, err := singBoxOutbound(server)
	if err != nil {
		t.Fatalf("singBoxOutbound returned error: %v", err)
	}

	tls := outbound["tls"].(map[string]any)
	transport := outbound["transport"].(map[string]any)
	headers := transport["headers"].(map[string]any)

	if outbound["type"] != "trojan" || outbound["password"] != "secret" {
		t.Fatalf("unexpected outbound: %+v", outbound)
	}
	if tls["server_name"] != "sni.example.com" {
		t.Fatalf("unexpected tls: %+v", tls)
	}
	if transport["type"] != "ws" || transport["path"] != "/ws" || headers["Host"] != "cdn.example.com" {
		t.Fatalf("unexpected transport: %+v", transport)
	}
}

func TestTrojanOutboundFromDetailsAddsTLSAndWebSocket(t *testing.T) {
	outbound, err := singBoxOutbound(Server{
		Address:  "example.com",
		Port:     "443",
		Protocol: "trojan",
		Details: map[string]string{
			"password": "secret",
			"security": "tls",
			"sni":      "sni.example.com",
			"alpn":     "h2, http/1.1",
			"network":  "ws",
			"path":     "/ws",
			"host":     "cdn.example.com",
		},
	})
	if err != nil {
		t.Fatalf("singBoxOutbound returned error: %v", err)
	}

	tls := outbound["tls"].(map[string]any)
	alpn := tls["alpn"].([]string)
	transport := outbound["transport"].(map[string]any)
	headers := transport["headers"].(map[string]any)

	if outbound["password"] != "secret" || tls["server_name"] != "sni.example.com" || len(alpn) != 2 || alpn[0] != "h2" || alpn[1] != "http/1.1" {
		t.Fatalf("unexpected tls/outbound: %+v", outbound)
	}
	if transport["type"] != "ws" || transport["path"] != "/ws" || headers["Host"] != "cdn.example.com" {
		t.Fatalf("unexpected transport: %+v", transport)
	}
}

func TestParseShadowsocksBase64UserInfo(t *testing.T) {
	server, ok := parseShareLink("ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388#SS")
	if !ok {
		t.Fatal("parseShareLink returned false")
	}

	if server.Protocol != "shadowsocks" || server.Details["method"] != "aes-256-gcm" || server.Details["password"] != "secret" {
		t.Fatalf("unexpected server: %+v", server)
	}
}

func TestParseShadowsocksPlainUserInfo(t *testing.T) {
	server, ok := parseShareLink("ss://chacha20-ietf-poly1305:secret@example.com:8388#SS")
	if !ok {
		t.Fatal("parseShareLink returned false")
	}

	if server.Protocol != "shadowsocks" || server.Details["method"] != "chacha20-ietf-poly1305" || server.Details["password"] != "secret" {
		t.Fatalf("unexpected server: %+v", server)
	}
}

func TestParseHysteria2ShareLink(t *testing.T) {
	server, ok := parseShareLink("hysteria2://secret@example.com:443?sni=sni.example.com&alpn=h3,h2#HY2")
	if !ok {
		t.Fatal("parseShareLink returned false")
	}

	outbound, err := singBoxOutbound(server)
	if err != nil {
		t.Fatalf("singBoxOutbound returned error: %v", err)
	}

	tls := outbound["tls"].(map[string]any)
	alpn := tls["alpn"].([]string)
	if outbound["password"] != "secret" || tls["server_name"] != "sni.example.com" || len(alpn) != 2 || alpn[0] != "h3" || alpn[1] != "h2" {
		t.Fatalf("unexpected outbound: %+v", outbound)
	}
}

func TestFormatPingResult(t *testing.T) {
	result := formatPingResult(pingResult{Latency: 42 * time.Millisecond, OK: true})
	if result != "42 ms" {
		t.Fatalf("expected 42 ms, got %q", result)
	}

	result = formatPingResult(pingResult{})
	if result != "timeout" {
		t.Fatalf("expected timeout, got %q", result)
	}

	result = formatPingResult(pingResult{Skipped: true})
	if result != "-" {
		t.Fatalf("expected -, got %q", result)
	}
}

func TestPingServerSkipsEmptyAddressOrPort(t *testing.T) {
	result := pingServer(Server{Address: "example.com"}, time.Millisecond)
	if !result.Skipped || result.OK {
		t.Fatalf("expected skipped ping, got %+v", result)
	}

	result = pingServer(Server{Port: "443"}, time.Millisecond)
	if !result.Skipped || result.OK {
		t.Fatalf("expected skipped ping, got %+v", result)
	}
}

func TestPingServerAvailableLocalListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen returned error: %v", err)
	}
	defer listener.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort returned error: %v", err)
	}

	result := pingServer(Server{Address: host, Port: port}, time.Second)
	if !result.OK {
		t.Fatalf("expected successful ping, got %+v", result)
	}
	<-done
}

func TestPingServerUnavailable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen returned error: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("SplitHostPort returned error: %v", err)
	}

	result := pingServer(Server{Address: host, Port: port}, 50*time.Millisecond)
	if result.OK || result.Skipped {
		t.Fatalf("expected unavailable ping, got %+v", result)
	}
}

func TestPingServerChecksHysteriaWithHTTPGet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			t.Fatalf("expected GET request, got %s", request.Method)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	previousURL := hysteriaPingURL
	hysteriaPingURL = server.URL
	defer func() {
		hysteriaPingURL = previousURL
	}()

	result := pingServer(Server{Address: "hy.example.com", Port: "443", Protocol: "hysteria2"}, time.Second)
	if !result.OK || result.Skipped {
		t.Fatalf("expected successful hysteria HTTP ping, got %+v", result)
	}
}

func TestPingLabelUsesStoredValue(t *testing.T) {
	server := Server{Name: "NL", Address: "example.com", Port: "443", Protocol: "vless"}
	pings := map[string]string{
		serverPingKey(server): "12 ms",
	}

	if got := pingLabel(server, pings); got != "12 ms" {
		t.Fatalf("expected stored ping, got %q", got)
	}

	if got := pingLabel(Server{Name: "DE", Address: "example.com", Port: "443", Protocol: "vless"}, pings); got != "-" {
		t.Fatalf("expected missing ping, got %q", got)
	}
}

func TestServerLabelWithPing(t *testing.T) {
	server := Server{Name: "NL", Address: "example.com", Port: "443", Protocol: "vless"}
	pings := map[string]string{
		serverPingKey(server): "12 ms",
	}

	if got := serverLabelWithPing(server, pings); got != "NL [vless] | Пинг: 12 ms" {
		t.Fatalf("unexpected label: %q", got)
	}

	if got := serverLabelWithPing(server, nil); got != "NL [vless]" {
		t.Fatalf("unexpected label without ping: %q", got)
	}
}

func TestHysteriaOutboundAddsAlpnAndObfs(t *testing.T) {
	outbound, err := singBoxOutbound(Server{
		Address:  "hy.example.com",
		Port:     "443",
		Protocol: "hysteria2",
		Details: map[string]string{
			"password":      "secret",
			"alpn":          "h3, h2",
			"obfs-password": "obfs-secret",
		},
	})
	if err != nil {
		t.Fatalf("singBoxOutbound returned error: %v", err)
	}

	tls := outbound["tls"].(map[string]any)
	alpn := tls["alpn"].([]string)
	obfs := outbound["obfs"].(map[string]any)

	if len(alpn) != 2 || alpn[0] != "h3" || alpn[1] != "h2" {
		t.Fatalf("unexpected alpn: %+v", alpn)
	}
	if obfs["type"] != "salamander" || obfs["password"] != "obfs-secret" {
		t.Fatalf("unexpected obfs: %+v", obfs)
	}
}

func TestServerHostPort(t *testing.T) {
	cases := []struct {
		name   string
		server Server
		want   string
	}{
		{name: "domain", server: Server{Address: "example.com", Port: "443"}, want: "example.com:443"},
		{name: "ipv4", server: Server{Address: "127.0.0.1", Port: "443"}, want: "127.0.0.1:443"},
		{name: "ipv6", server: Server{Address: "2001:db8::1", Port: "443"}, want: "[2001:db8::1]:443"},
		{name: "no port", server: Server{Address: "example.com"}, want: "example.com"},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := serverHostPort(test.server); got != test.want {
				t.Fatalf("expected %q, got %q", test.want, got)
			}
		})
	}
}

func TestFetchRejectsTooLargeSubscription(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(strings.Repeat("x", maxSubscriptionBodySize+1)))
	}))
	defer server.Close()

	_, err := fetch(server.URL, "", "*/*")
	if err == nil {
		t.Fatal("expected error for too large subscription")
	}
}

func TestReleaseWorkflowTargets(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	text := string(body)

	expected := []string{
		"goos: linux\n            goarch: amd64\n            name: terminal-linux-amd64",
		"goos: darwin\n            goarch: amd64\n            name: terminal-macos-intel",
		"goos: darwin\n            goarch: arm64\n            name: terminal-macos-apple-silicon",
		"goos: windows\n            goarch: amd64\n            name: terminal-windows-amd64.exe",
	}

	for _, value := range expected {
		if !strings.Contains(text, value) {
			t.Fatalf("release workflow does not contain %q", value)
		}
	}
}

func TestUpdateSingBoxConfigReplacesOnlyProxy(t *testing.T) {
	config := map[string]any{
		"outbounds": []any{
			map[string]any{"type": "direct", "tag": "direct"},
			map[string]any{"type": "vless", "tag": "proxy", "server": "old.example.com"},
			map[string]any{"type": "block", "tag": "block"},
		},
	}
	outbound := map[string]any{"type": "trojan", "tag": "proxy", "server": "new.example.com"}

	updateSingBoxConfig(config, outbound)

	outbounds := config["outbounds"].([]any)
	if len(outbounds) != 3 {
		t.Fatalf("expected 3 outbounds, got %d", len(outbounds))
	}
	if outbounds[0].(map[string]any)["tag"] != "direct" || outbounds[1].(map[string]any)["server"] != "new.example.com" || outbounds[2].(map[string]any)["tag"] != "block" {
		t.Fatalf("unexpected outbounds: %+v", outbounds)
	}
}

func TestUpdateSingBoxConfigAddsProxy(t *testing.T) {
	config := map[string]any{
		"outbounds": []any{
			map[string]any{"type": "direct", "tag": "direct"},
		},
	}
	outbound := map[string]any{"type": "trojan", "tag": "proxy", "server": "new.example.com"}

	updateSingBoxConfig(config, outbound)

	outbounds := config["outbounds"].([]any)
	if len(outbounds) != 2 || outbounds[1].(map[string]any)["tag"] != "proxy" {
		t.Fatalf("unexpected outbounds: %+v", outbounds)
	}
}

func TestReadRouterCredentialsUsesDefaultAddress(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("\nsecret\n"))

	credentials, err := readRouterCredentials(reader)
	if err != nil {
		t.Fatalf("readRouterCredentials returned error: %v", err)
	}

	if credentials.Address != defaultRouterAddress || credentials.User != "root" || credentials.Host != "192.168.1.1" || credentials.DialAddress != "192.168.1.1:22" || credentials.Password != "secret" {
		t.Fatalf("unexpected credentials: %+v", credentials)
	}
}

func TestReadRouterCredentialsParsesCustomAddress(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("admin@192.168.8.1:2222\nsecret\n"))

	credentials, err := readRouterCredentials(reader)
	if err != nil {
		t.Fatalf("readRouterCredentials returned error: %v", err)
	}

	if credentials.User != "admin" || credentials.Host != "192.168.8.1:2222" || credentials.DialAddress != "192.168.8.1:2222" || credentials.Password != "secret" {
		t.Fatalf("unexpected credentials: %+v", credentials)
	}
}

func TestAppendKnownHostAndRejectMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	keyA := testPublicKey(t)
	keyB := testPublicKeyFromSeed(t, 2)

	if err := appendKnownHost(path, "example.com:22", keyA); err != nil {
		t.Fatalf("appendKnownHost returned error: %v", err)
	}

	callback, err := knownhosts.New(path)
	if err != nil {
		t.Fatalf("knownhosts.New returned error: %v", err)
	}
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}

	if err := callback("example.com:22", remote, keyA); err != nil {
		t.Fatalf("expected stored key to pass, got %v", err)
	}
	if err := callback("example.com:22", remote, keyB); err == nil {
		t.Fatal("expected mismatched key to fail")
	}
}

func TestTimestampedRouterBackupPath(t *testing.T) {
	got := timestampedRouterBackupPath(time.Date(2026, 4, 28, 1, 15, 30, 0, time.UTC))
	want := routerBackupPath + ".20260428-011530"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestFirstBackupPathSupportsTimestampAndLegacyBackup(t *testing.T) {
	timestamped := routerBackupPath + ".20260428-011530"
	if got := firstBackupPath(timestamped + "\n" + routerBackupPath + "\n"); got != timestamped {
		t.Fatalf("expected timestamped backup, got %q", got)
	}

	if got := firstBackupPath("\n" + routerBackupPath + "\n"); got != routerBackupPath {
		t.Fatalf("expected legacy backup, got %q", got)
	}
}

func TestReadMenuChoiceReturnsInvalidChoiceForEmptyInput(t *testing.T) {
	choice, err := readMenuChoice(bufio.NewReader(strings.NewReader("\n")))
	if err != nil {
		t.Fatalf("readMenuChoice returned error: %v", err)
	}
	if choice != emptyMenuChoice {
		t.Fatalf("expected empty choice %d, got %d", emptyMenuChoice, choice)
	}
}

func TestReadMenuChoiceReturnsErrorForNonNumericInput(t *testing.T) {
	if _, err := readMenuChoice(bufio.NewReader(strings.NewReader("abc\n"))); err == nil {
		t.Fatal("expected error for non-numeric input")
	}
}

func testPublicKey(t *testing.T) ssh.PublicKey {
	return testPublicKeyFromSeed(t, 1)
}

func testPublicKeyFromSeed(t *testing.T, seed byte) ssh.PublicKey {
	t.Helper()

	publicKey, _, err := ed25519.GenerateKey(zeroReader(seed))
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	sshKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatalf("NewPublicKey returned error: %v", err)
	}
	return sshKey
}

type zeroReader byte

func (reader zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(reader)
	}
	return len(p), nil
}
