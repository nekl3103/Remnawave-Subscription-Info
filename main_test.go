package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
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
		{"name":"VMess","server":"vmess.example.com","port":443,"type":"vmess","uuid":"uuid"}
	]}`)

	servers, err := parseAllServers([][]byte{body})
	if err != nil {
		t.Fatalf("parseAllServers returned error: %v", err)
	}

	if len(servers) != 2 || servers[0].Name != "OK" || servers[1].Name != "VMess" {
		t.Fatalf("expected valid vless and vmess servers, got %+v", servers)
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

func TestVMessOutboundAndConnectionLink(t *testing.T) {
	server := Server{
		Name:     "VM",
		Address:  "vm.example.com",
		Port:     "443",
		Protocol: "vmess",
		Details: map[string]string{
			"id":   "uuid",
			"aid":  "0",
			"scy":  "auto",
			"net":  "ws",
			"path": "/ws",
			"host": "cdn.example.com",
			"tls":  "tls",
			"sni":  "sni.example.com",
		},
	}

	outbound, err := singBoxOutbound(server)
	if err != nil {
		t.Fatalf("singBoxOutbound returned error: %v", err)
	}

	tls := outbound["tls"].(map[string]any)
	transport := outbound["transport"].(map[string]any)
	headers := transport["headers"].(map[string]any)

	if outbound["type"] != "vmess" || outbound["uuid"] != "uuid" || outbound["security"] != "auto" {
		t.Fatalf("unexpected outbound: %+v", outbound)
	}
	if tls["server_name"] != "sni.example.com" {
		t.Fatalf("unexpected tls: %+v", tls)
	}
	if transport["type"] != "ws" || transport["path"] != "/ws" || headers["Host"] != "cdn.example.com" {
		t.Fatalf("unexpected transport: %+v", transport)
	}

	link, err := connectionLink(server)
	if err != nil {
		t.Fatalf("connectionLink returned error: %v", err)
	}
	if !strings.HasPrefix(link, "vmess://") {
		t.Fatalf("expected vmess link, got %q", link)
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

func TestPingAndSortServers(t *testing.T) {
	servers := []Server{
		{Name: "timeout", Address: "timeout.example.com", Port: "443", Protocol: "vless"},
		{Name: "fast", Address: "fast.example.com", Port: "443", Protocol: "vless"},
		{Name: "missing", Protocol: "vless"},
		{Name: "slow", Address: "slow.example.com", Port: "443", Protocol: "vless"},
	}
	pings := map[string]string{
		serverPingKey(servers[0]): unavailablePing,
		serverPingKey(servers[1]): "10 ms",
		serverPingKey(servers[2]): missingPingTarget,
		serverPingKey(servers[3]): "50 ms",
	}

	servers = sortServersByPing(servers, pings)

	got := []string{servers[0].Name, servers[1].Name, servers[2].Name, servers[3].Name}
	want := []string{"fast", "slow", "timeout", "missing"}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("expected order %v, got %v", want, got)
		}
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

func TestSimpleDiffShowsBeforeAndAfter(t *testing.T) {
	diff := simpleDiff("{\n  \"server\": \"old\"\n}", "{\n  \"server\": \"new\"\n}")
	if !strings.Contains(diff, "-   \"server\": \"old\"") || !strings.Contains(diff, "+   \"server\": \"new\"") {
		t.Fatalf("unexpected diff: %s", diff)
	}
}

func TestSingBoxCheckCommandQuotesPath(t *testing.T) {
	got := singBoxCheckCommand("/tmp/sing-box config.json")
	want := "sing-box check -c '/tmp/sing-box config.json'"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestFullSingBoxConfigText(t *testing.T) {
	body, err := fullSingBoxConfigText(Server{
		Name:     "NL",
		Address:  "nl.example.com",
		Port:     "443",
		Protocol: "vless",
		Details:  map[string]string{"uuid": "uuid"},
	})
	if err != nil {
		t.Fatalf("fullSingBoxConfigText returned error: %v", err)
	}

	var config map[string]any
	if err := json.Unmarshal([]byte(body), &config); err != nil {
		t.Fatalf("config is not json: %v", err)
	}
	if config["log"] == nil || config["dns"] == nil || config["inbounds"] == nil || config["route"] == nil {
		t.Fatalf("config missing required sections: %+v", config)
	}
	outbounds := config["outbounds"].([]any)
	if len(outbounds) != 3 || outbounds[0].(map[string]any)["tag"] != "proxy" || outbounds[1].(map[string]any)["tag"] != "direct" || outbounds[2].(map[string]any)["tag"] != "block" {
		t.Fatalf("unexpected outbounds: %+v", outbounds)
	}
}

func TestInstallHistoryUsesTempDir(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("TMPDIR", tempDir)
	t.Setenv("TEMP", tempDir)
	t.Setenv("TMP", tempDir)

	path := installHistoryPath()
	if !strings.HasPrefix(path, tempDir) {
		t.Fatalf("expected temp history path under %q, got %q", tempDir, path)
	}

	now := time.Date(2026, 4, 28, 1, 2, 3, 0, time.UTC)
	err := appendInstallHistory(Server{Name: "NL", Address: "nl.example.com", Port: "443", Protocol: "vless"}, "root@192.168.1.1", "/etc/sing-box/config.json.bak.20260428-010203", now)
	if err != nil {
		t.Fatalf("appendInstallHistory returned error: %v", err)
	}

	entries, err := readInstallHistory()
	if err != nil {
		t.Fatalf("readInstallHistory returned error: %v", err)
	}
	if len(entries) != 1 || entries[0].ServerName != "NL" || entries[0].BackupPath == "" {
		t.Fatalf("unexpected entries: %+v", entries)
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

func TestParseOpenWrtReleasesHTMLFiltersStableReleases(t *testing.T) {
	body := `<a href="24.10.6/">24.10.6/</a>
<a href="25.12.0-rc1/">25.12.0-rc1/</a>
<a href="packages-24.10/">packages-24.10/</a>
<a href="25.12.2/">25.12.2/</a>
<a href="23.05.6/">23.05.6/</a>`

	releases := parseOpenWrtReleasesHTML(body)
	want := []string{"25.12.2", "24.10.6", "23.05.6"}
	if strings.Join(releases, ",") != strings.Join(want, ",") {
		t.Fatalf("expected %v, got %v", want, releases)
	}
}

func TestParseOpenWrtBoardInfoAndReleaseVars(t *testing.T) {
	info := parseOpenWrtBoardInfo(`{
		"hostname": "OpenWrt",
		"model": "Xiaomi Mi Router 3G",
		"board_name": "xiaomi,mi-router-3g",
		"release": {
			"distribution": "OpenWrt",
			"version": "24.10.6",
			"target": "ramips/mt7621"
		}
	}`)

	if !info.Detected || info.Model != "Xiaomi Mi Router 3G" || info.BoardName != "xiaomi,mi-router-3g" || info.Target != "ramips/mt7621" {
		t.Fatalf("unexpected board info: %+v", info)
	}

	info.Release = ""
	info.Target = ""
	mergeOpenWrtReleaseVars(&info, "DISTRIB_RELEASE='23.05.6'\nDISTRIB_TARGET='ath79/generic'\n")
	if info.Release != "23.05.6" || info.Target != "ath79/generic" {
		t.Fatalf("unexpected release vars: %+v", info)
	}
}

func TestParseRouterResources(t *testing.T) {
	resources := parseRouterDF(`Filesystem           1K-blocks      Used Available Use% Mounted on
/dev/root                 5120      5120         0 100% /rom
overlayfs:/overlay       20480      8000     12480  39% /overlay
tmpfs                    62344       104     62240   1% /tmp`)

	if resources.OverlayFreeKB != 12480 || resources.TmpFreeKB != 62240 {
		t.Fatalf("unexpected resources: %+v", resources)
	}
}

func TestDNSMasqConfigForDomains(t *testing.T) {
	got := dnsmasqConfigForDomains([]string{"Example.com", "https://terraform.io/docs", "example.com"})
	want := "nftset=/example.com/4#inet#fw4#vpn_domains\nnftset=/terraform.io/4#inet#fw4#vpn_domains\n"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestParseProxyDomainFileDomainsSupportsListAndDNSMasq(t *testing.T) {
	body := `example.com
nftset=/youtube.com/googlevideo.com/4#inet#fw4#vpn_domains
# ignored.example.com
nftset=/telegram.org/6#inet#fw4#vpn_domains`

	domains := parseProxyDomainFileDomains(body)
	want := []string{"example.com", "youtube.com", "googlevideo.com", "telegram.org"}
	if strings.Join(domains, ",") != strings.Join(want, ",") {
		t.Fatalf("expected %v, got %v", want, domains)
	}
}

func TestParseAndUpdateDHCPVPNDomains(t *testing.T) {
	body := `config dnsmasq
	option domainneeded '1'

config ipset
	list name 'vpn_domains'
	list domain 'discord.com'
	list domain 'youtube.com'

config host
	option name 'router'`

	domains := parseDHCPVPNDomains(body)
	if strings.Join(domains, ",") != "discord.com,youtube.com" {
		t.Fatalf("unexpected domains: %v", domains)
	}

	updated := updateDHCPVPNDomains(body, []string{"telegram.org", "discord.com"})
	if !strings.Contains(updated, "list name 'vpn_domains'") || !strings.Contains(updated, "list domain 'telegram.org'") || strings.Contains(updated, "list domain 'youtube.com'") || !strings.Contains(updated, "config host") {
		t.Fatalf("unexpected updated dhcp config:\n%s", updated)
	}
}

func TestProxyDomainAddRemoveNormalizesAndDeduplicates(t *testing.T) {
	domains := addProxyDomain(nil, "https://Example.com/path")
	domains = addProxyDomain(domains, "*.example.com")
	domains = addProxyDomain(domains, "terraform.io")
	domains = removeProxyDomain(domains, "EXAMPLE.COM")

	if strings.Join(domains, ",") != "terraform.io" {
		t.Fatalf("unexpected domains: %v", domains)
	}
}

func TestParsePackageFeedFindsPackageURL(t *testing.T) {
	body := `Package: sing-box
Version: 1.10.0-1
Size: 12345
Filename: sing-box_1.10.0-1_mipsel_24kc.ipk

Package: stubby
Version: 1.0
Filename: stubby.ipk
`

	versions := parsePackageFeed(body, "https://downloads.openwrt.org/releases/24.10.6/packages/mipsel_24kc/packages/", "sing-box")
	if len(versions) != 1 || versions[0].Version != "1.10.0-1" || !strings.HasSuffix(versions[0].URL, "sing-box_1.10.0-1_mipsel_24kc.ipk") {
		t.Fatalf("unexpected versions: %+v", versions)
	}
}

func TestParseInstalledPackages(t *testing.T) {
	installed := parseInstalledPackages("dnsmasq-full - 2.90-r4\nstubby - 1.6.0-r1\n")
	if installed["dnsmasq-full"].Version != "2.90-r4" || installed["stubby"].Version != "1.6.0-r1" {
		t.Fatalf("unexpected installed packages: %+v", installed)
	}
}

func TestPrimaryInstalledDNSOptionUsesMenuOrder(t *testing.T) {
	options := []dnsPackageOption{
		{Name: "dnsmasq-full", Title: "dnsmasq-full"},
		{Name: "dnscrypt-proxy2", Title: "dnscrypt-proxy2"},
		{Name: "stubby", Title: "stubby"},
	}
	installed := map[string]installedPackage{
		"stubby":       {Name: "stubby", Version: "1"},
		"dnsmasq-full": {Name: "dnsmasq-full", Version: "2"},
	}

	option, ok := primaryInstalledDNSOption(options, installed)
	if !ok || option.Name != "dnsmasq-full" {
		t.Fatalf("unexpected primary option ok=%v option=%+v", ok, option)
	}
}

func TestParseProxyDomainFilesDeduplicatesAndLabels(t *testing.T) {
	files := parseProxyDomainFiles(proxyDomainsPath + "\n" + proxyDomainsDnsmasqPath + "\n/etc/config/dhcp\n/tmp/dnsmasq.d/discord-voice-ip-list.txt\n/etc/dnsmasq.d/custom.conf\n" + proxyDomainsPath + "\n")
	if len(files) != 5 {
		t.Fatalf("expected 5 files, got %+v", files)
	}
	if files[0].Kind != "список доменов" || !files[0].Editable || !files[0].Deletable {
		t.Fatalf("unexpected first file: %+v", files[0])
	}
	if files[1].Kind != "dnsmasq nftset" || files[2].Kind != "dhcp ipset vpn_domains" || files[2].Deletable || files[3].Kind != "discord voice ip list" || files[4].Kind != "dnsmasq" {
		t.Fatalf("unexpected file kinds: %+v", files)
	}
}

func TestDownloadCommandQuotesURLAndPath(t *testing.T) {
	got := downloadCommand("https://example.com/firmware.bin", "/tmp/firmware.bin")
	for _, value := range []string{"wget -O '/tmp/firmware.bin' 'https://example.com/firmware.bin'", "curl -L -o '/tmp/firmware.bin' 'https://example.com/firmware.bin'"} {
		if !strings.Contains(got, value) {
			t.Fatalf("expected command to contain %q, got %q", value, got)
		}
	}
}

func TestHandleMainMenuSubscriptionExitKeepsOldZeroExit(t *testing.T) {
	state := newAppState()
	reader := bufio.NewReader(strings.NewReader("0\n"))
	if !handleMainMenu(reader, state) {
		t.Fatal("expected main menu 0 to exit")
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
