package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func printSingBoxOutbounds(server Server) error {
	body, err := singBoxOutboundsText(server)
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Println(colorBlue + body + colorReset)
	return nil
}

func singBoxOutboundsText(server Server) (string, error) {
	outbound, err := singBoxOutbound(server)
	if err != nil {
		return "", err
	}

	config := map[string]any{
		"outbounds": []any{outbound},
	}

	body, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func printConnectionLink(server Server) error {
	link, err := connectionLink(server)
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Println(colorBlue + link + colorReset)
	return nil
}

func connectionLink(server Server) (string, error) {
	switch server.Protocol {
	case "vless":
		return vlessLink(server), nil
	case "shadowsocks":
		return shadowsocksLink(server)
	case "trojan":
		return trojanLink(server), nil
	case "hysteria", "hysteria2":
		return hysteria2Link(server), nil
	default:
		return "", fmt.Errorf("протокол %q не поддержан для генерации ссылки", server.Protocol)
	}
}

func displayLinkProtocol(protocol string) string {
	switch protocol {
	case "shadowsocks":
		return "ss"
	case "hysteria":
		return "hysteria2"
	default:
		return protocol
	}
}

func vlessLink(server Server) string {
	query := url.Values{}
	addQuery(query, "encryption", firstNonEmpty(server.Details["encryption"], "none"))
	addQuery(query, "flow", server.Details["flow"])
	addQuery(query, "type", firstNonEmpty(server.Details["network"], server.Details["type"], "tcp"))

	tlsEnabled := firstNonEmpty(server.Details["tls.enabled"], server.Details["security"])
	if tlsEnabled == "true" || tlsEnabled == "tls" || tlsEnabled == "reality" {
		if tlsEnabled == "reality" || server.Details["tls.reality.enabled"] == "true" || server.Details["tls.reality.public_key"] != "" {
			addQuery(query, "security", "reality")
			addQuery(query, "pbk", firstNonEmpty(server.Details["tls.reality.public_key"], server.Details["pbk"]))
			addQuery(query, "sid", firstNonEmpty(server.Details["tls.reality.short_id"], server.Details["sid"]))
			addQuery(query, "sni", firstNonEmpty(server.Details["tls.server_name"], server.Details["sni"]))
			addQuery(query, "fp", firstNonEmpty(server.Details["tls.utls.fingerprint"], server.Details["fp"]))
		} else {
			addQuery(query, "security", "tls")
			addQuery(query, "sni", firstNonEmpty(server.Details["tls.server_name"], server.Details["sni"]))
		}
	}

	return buildLink("vless", firstNonEmpty(server.Details["uuid"], server.Details["user"]), server, query)
}

func shadowsocksLink(server Server) (string, error) {
	method := server.Details["method"]
	password := server.Details["password"]
	if method == "" || password == "" {
		return "", errors.New("не хватает method/password для Shadowsocks")
	}

	userInfo := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + password))
	return fmt.Sprintf("ss://%s@%s#%s", userInfo, serverHostPort(server), url.QueryEscape(server.Name)), nil
}

func trojanLink(server Server) string {
	query := url.Values{}
	addQuery(query, "security", firstNonEmpty(server.Details["security"], "tls"))
	addQuery(query, "sni", firstNonEmpty(server.Details["sni"], server.Details["server_name"], server.Details["tls.server_name"]))
	addQuery(query, "type", firstNonEmpty(server.Details["network"], server.Details["type"]))

	return buildLink("trojan", firstNonEmpty(server.Details["password"], server.Details["user"]), server, query)
}

func hysteria2Link(server Server) string {
	query := url.Values{}
	addQuery(query, "sni", firstNonEmpty(server.Details["sni"], server.Details["server_name"], server.Details["tls.server_name"], server.Details["streamSettings.tlsSettings.serverName"]))
	addQuery(query, "alpn", firstNonEmpty(server.Details["alpn"], server.Details["streamSettings.tlsSettings.alpn"]))

	return buildLink("hysteria2", firstNonEmpty(
		server.Details["password"],
		server.Details["auth"],
		server.Details["streamSettings.hysteriaSettings.auth"],
	), server, query)
}

func buildLink(scheme string, user string, server Server, query url.Values) string {
	parsed := url.URL{
		Scheme:   scheme,
		User:     url.User(user),
		Host:     serverHostPort(server),
		RawQuery: query.Encode(),
		Fragment: server.Name,
	}

	return parsed.String()
}

func addQuery(query url.Values, key string, value string) {
	if value != "" {
		query.Set(key, value)
	}
}

func serverHostPort(server Server) string {
	if server.Port == "" {
		return server.Address
	}

	return net.JoinHostPort(server.Address, server.Port)
}

func shareLinkToSingBox(parsed *url.URL) map[string]any {
	protocol := normalizeProtocol(parsed.Scheme)
	query := parsed.Query()

	switch protocol {
	case "hysteria2", "hysteria":
		outbound := map[string]any{
			"type":        "hysteria2",
			"tag":         "proxy",
			"server":      parsed.Hostname(),
			"server_port": numberOrString(parsed.Port()),
			"password":    firstNonEmpty(query.Get("password"), query.Get("auth"), parsed.User.Username()),
			"tls": map[string]any{
				"enabled": true,
			},
		}
		tls := outbound["tls"].(map[string]any)
		if serverName := firstNonEmpty(query.Get("sni"), query.Get("peer"), query.Get("server_name")); serverName != "" {
			tls["server_name"] = serverName
		}
		if alpn := query.Get("alpn"); alpn != "" {
			tls["alpn"] = splitCommaValues(alpn)
		}
		if obfsPassword := firstNonEmpty(query.Get("obfs-password"), query.Get("obfs_password")); obfsPassword != "" {
			outbound["obfs"] = map[string]any{
				"type":     firstNonEmpty(query.Get("obfs"), "salamander"),
				"password": obfsPassword,
			}
		}
		return outbound
	case "vless":
		outbound := map[string]any{
			"type":        "vless",
			"tag":         "proxy",
			"server":      parsed.Hostname(),
			"server_port": numberOrString(parsed.Port()),
			"uuid":        parsed.User.Username(),
		}
		if flow := query.Get("flow"); flow != "" {
			outbound["flow"] = flow
		}
		addTLSFromQuery(outbound, query)
		addTransportFromQuery(outbound, query)
		return outbound
	case "trojan":
		outbound := map[string]any{
			"type":        "trojan",
			"tag":         "proxy",
			"server":      parsed.Hostname(),
			"server_port": numberOrString(parsed.Port()),
			"password":    parsed.User.Username(),
		}
		addTLSFromQuery(outbound, query)
		addTransportFromQuery(outbound, query)
		return outbound
	default:
		return nil
	}
}

func addTLSFromQuery(outbound map[string]any, query url.Values) {
	security := query.Get("security")
	if security == "" || security == "none" {
		return
	}

	tls := map[string]any{"enabled": true}
	if serverName := firstNonEmpty(query.Get("sni"), query.Get("server_name"), query.Get("peer")); serverName != "" {
		tls["server_name"] = serverName
	}
	if alpn := query.Get("alpn"); alpn != "" {
		tls["alpn"] = strings.Split(alpn, ",")
	}
	if fingerprint := firstNonEmpty(query.Get("fp"), query.Get("fingerprint")); fingerprint != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fingerprint}
	}
	if security == "reality" {
		tls["reality"] = map[string]any{
			"enabled":    true,
			"public_key": query.Get("pbk"),
			"short_id":   query.Get("sid"),
		}
	}

	outbound["tls"] = tls
}

func addTransportFromQuery(outbound map[string]any, query url.Values) {
	network := firstNonEmpty(query.Get("type"), query.Get("network"))
	if network == "" || network == "tcp" {
		return
	}

	transport := map[string]any{"type": network}
	switch network {
	case "ws":
		if path := query.Get("path"); path != "" {
			transport["path"] = path
		}
		if host := query.Get("host"); host != "" {
			transport["headers"] = map[string]any{"Host": host}
		}
	case "grpc":
		if serviceName := query.Get("serviceName"); serviceName != "" {
			transport["service_name"] = serviceName
		}
	case "http":
		if host := query.Get("host"); host != "" {
			transport["host"] = strings.Split(host, ",")
		}
		if path := query.Get("path"); path != "" {
			transport["path"] = path
		}
	}
	outbound["transport"] = transport
}

func addTLSFromDetails(outbound map[string]any, details map[string]string) {
	security := strings.ToLower(firstNonEmpty(
		details["security"],
		details["tls"],
		details["tls.enabled"],
		details["streamSettings.security"],
	))
	realityPublicKey := firstNonEmpty(
		details["pbk"],
		details["reality.public_key"],
		details["tls.reality.public_key"],
		details["streamSettings.realitySettings.publicKey"],
	)

	if security == "" && realityPublicKey == "" {
		return
	}
	if security == "none" || security == "false" {
		return
	}

	tls := map[string]any{"enabled": true}
	if serverName := firstNonEmpty(
		details["sni"],
		details["server_name"],
		details["tls.server_name"],
		details["streamSettings.tlsSettings.serverName"],
	); serverName != "" {
		tls["server_name"] = serverName
	}
	if alpn := firstNonEmpty(details["alpn"], details["tls.alpn"], details["streamSettings.tlsSettings.alpn"]); alpn != "" {
		tls["alpn"] = splitCommaValues(alpn)
	}
	if fingerprint := firstNonEmpty(
		details["fp"],
		details["fingerprint"],
		details["tls.utls.fingerprint"],
		details["streamSettings.tlsSettings.fingerprint"],
	); fingerprint != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fingerprint}
	}
	if security == "reality" || realityPublicKey != "" {
		tls["reality"] = map[string]any{
			"enabled":    true,
			"public_key": realityPublicKey,
			"short_id": firstNonEmpty(
				details["sid"],
				details["reality.short_id"],
				details["tls.reality.short_id"],
				details["streamSettings.realitySettings.shortId"],
			),
		}
	}

	outbound["tls"] = tls
}

func addTransportFromDetails(outbound map[string]any, details map[string]string) {
	network := strings.ToLower(firstNonEmpty(
		details["network"],
		details["type"],
		details["transport.type"],
		details["streamSettings.network"],
	))
	if network == "" || network == "tcp" {
		return
	}

	transport := map[string]any{"type": network}
	switch network {
	case "ws":
		if path := firstNonEmpty(details["path"], details["transport.path"], details["streamSettings.wsSettings.path"]); path != "" {
			transport["path"] = path
		}
		if host := firstNonEmpty(details["host"], details["transport.headers.Host"], details["streamSettings.wsSettings.headers.Host"]); host != "" {
			transport["headers"] = map[string]any{"Host": host}
		}
	case "grpc":
		if serviceName := firstNonEmpty(details["serviceName"], details["service_name"], details["transport.service_name"], details["streamSettings.grpcSettings.serviceName"]); serviceName != "" {
			transport["service_name"] = serviceName
		}
	case "http":
		if host := firstNonEmpty(details["host"], details["transport.host"], details["streamSettings.httpSettings.host"]); host != "" {
			transport["host"] = splitCommaValues(host)
		}
		if path := firstNonEmpty(details["path"], details["transport.path"], details["streamSettings.httpSettings.path"]); path != "" {
			transport["path"] = path
		}
	default:
		return
	}

	outbound["transport"] = transport
}

func singBoxOutbound(server Server) (map[string]any, error) {
	if server.Raw != nil {
		outbound := cloneMap(server.Raw)
		outbound["tag"] = "proxy"
		return outbound, nil
	}

	switch server.Protocol {
	case "hysteria2", "hysteria":
		outbound := map[string]any{
			"type":        "hysteria2",
			"tag":         "proxy",
			"server":      server.Address,
			"server_port": numberOrString(server.Port),
			"tls": map[string]any{
				"enabled": true,
			},
		}
		if password := firstNonEmpty(server.Details["password"], server.Details["auth"]); password != "" {
			outbound["password"] = password
		}
		if serverName := firstNonEmpty(server.Details["sni"], server.Details["server_name"], server.Details["peer"]); serverName != "" {
			outbound["tls"].(map[string]any)["server_name"] = serverName
		}
		if alpn := firstNonEmpty(server.Details["alpn"], server.Details["tls.alpn"], server.Details["streamSettings.tlsSettings.alpn"]); alpn != "" {
			outbound["tls"].(map[string]any)["alpn"] = splitCommaValues(alpn)
		}
		if obfsPassword := firstNonEmpty(server.Details["obfs-password"], server.Details["obfs_password"], server.Details["obfs.password"]); obfsPassword != "" {
			outbound["obfs"] = map[string]any{
				"type":     firstNonEmpty(server.Details["obfs"], server.Details["obfs.type"], "salamander"),
				"password": obfsPassword,
			}
		}
		return outbound, nil
	case "vless":
		outbound := map[string]any{
			"type":        "vless",
			"tag":         "proxy",
			"server":      server.Address,
			"server_port": numberOrString(server.Port),
			"uuid":        firstNonEmpty(server.Details["uuid"], server.Details["user"]),
			"flow":        server.Details["flow"],
		}
		addTLSFromDetails(outbound, server.Details)
		addTransportFromDetails(outbound, server.Details)
		return outbound, nil
	case "shadowsocks":
		return map[string]any{
			"type":        "shadowsocks",
			"tag":         "proxy",
			"server":      server.Address,
			"server_port": numberOrString(server.Port),
			"method":      server.Details["method"],
			"password":    server.Details["password"],
		}, nil
	case "trojan":
		outbound := map[string]any{
			"type":        "trojan",
			"tag":         "proxy",
			"server":      server.Address,
			"server_port": numberOrString(server.Port),
			"password":    firstNonEmpty(server.Details["password"], server.Details["user"]),
		}
		addTLSFromDetails(outbound, server.Details)
		addTransportFromDetails(outbound, server.Details)
		return outbound, nil
	default:
		return nil, fmt.Errorf("протокол %q не поддержан для генерации sing-box", server.Protocol)
	}
}

func cloneMap(source map[string]any) map[string]any {
	cloned := make(map[string]any, len(source))
	for key, value := range source {
		switch nested := value.(type) {
		case map[string]any:
			cloned[key] = cloneMap(nested)
		case []any:
			cloned[key] = cloneSlice(nested)
		default:
			cloned[key] = value
		}
	}

	return cloned
}

func cloneSlice(source []any) []any {
	cloned := make([]any, len(source))
	for i, value := range source {
		switch nested := value.(type) {
		case map[string]any:
			cloned[i] = cloneMap(nested)
		case []any:
			cloned[i] = cloneSlice(nested)
		default:
			cloned[i] = value
		}
	}
	return cloned
}

func numberOrString(value string) any {
	if number, err := strconv.Atoi(value); err == nil {
		return number
	}

	return value
}
