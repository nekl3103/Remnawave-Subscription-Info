package main

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
)

func normalizeProtocol(protocol string) string {
	switch strings.ToLower(protocol) {
	case "ss":
		return "shadowsocks"
	case "hy2":
		return "hysteria2"
	default:
		return strings.ToLower(protocol)
	}
}

func parseServers(body []byte) ([]Server, error) {
	var data any
	if err := json.Unmarshal(body, &data); err != nil {
		return parseBase64Subscription(body)
	}

	servers := make([]Server, 0)
	collectServers(data, &servers)

	return servers, nil
}

func parseBase64Subscription(body []byte) ([]Server, error) {
	text := strings.TrimSpace(string(body))
	text = strings.TrimPrefix(text, "subscription-userinfo:")
	text = strings.TrimSpace(text)

	decoded, err := decodeBase64(text)
	if err != nil {
		return nil, err
	}

	servers := make([]Server, 0)
	for _, line := range strings.Fields(string(decoded)) {
		server, ok := parseShareLink(line)
		if ok {
			servers = append(servers, server)
		}
	}

	return servers, nil
}

func decodeBase64(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimRight(value, "\n\r")

	decoders := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}

	var lastErr error
	for _, decoder := range decoders {
		decoded, err := decoder.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
		lastErr = err
	}

	return nil, lastErr
}

func parseShareLink(raw string) (Server, bool) {
	if strings.HasPrefix(raw, "ss://") {
		return parseShadowsocksLink(raw)
	}

	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" {
		return Server{}, false
	}

	switch parsed.Scheme {
	case "vless", "vmess", "trojan", "hysteria", "hysteria2", "hy2":
	default:
		return Server{}, false
	}

	if parsed.Scheme == "vmess" && parsed.Host == "" {
		return parseVMessLink(parsed)
	}

	server := Server{
		Name:     firstNonEmpty(parsed.Fragment, parsed.Query().Get("remarks"), parsed.Query().Get("name")),
		Address:  parsed.Hostname(),
		Port:     parsed.Port(),
		Protocol: normalizeProtocol(parsed.Scheme),
		Details:  detailsFromURL(parsed),
		Raw:      shareLinkToSingBox(parsed),
	}

	return server, true
}

func parseShadowsocksLink(raw string) (Server, bool) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return Server{}, false
	}

	if parsed.Host == "" {
		decoded, ok := decodeLegacyShadowsocks(raw)
		if !ok {
			return Server{}, false
		}
		parsed, err = url.Parse(decoded)
		if err != nil {
			return Server{}, false
		}
	}

	method, password, ok := shadowsocksCredentials(parsed)
	if !ok || parsed.Hostname() == "" {
		return Server{}, false
	}

	details := detailsFromURL(parsed)
	details["method"] = method
	details["password"] = password

	return Server{
		Name:     firstNonEmpty(parsed.Fragment, parsed.Query().Get("remarks"), parsed.Query().Get("name")),
		Address:  parsed.Hostname(),
		Port:     parsed.Port(),
		Protocol: "shadowsocks",
		Details:  details,
		Raw: map[string]any{
			"type":        "shadowsocks",
			"tag":         "proxy",
			"server":      parsed.Hostname(),
			"server_port": numberOrString(parsed.Port()),
			"method":      method,
			"password":    password,
		},
	}, true
}

func decodeLegacyShadowsocks(raw string) (string, bool) {
	body := strings.TrimPrefix(raw, "ss://")
	fragment := ""
	if before, after, ok := strings.Cut(body, "#"); ok {
		body = before
		fragment = after
	}
	if before, _, ok := strings.Cut(body, "?"); ok {
		body = before
	}

	decoded, err := decodeBase64(body)
	if err != nil {
		return "", false
	}

	result := "ss://" + string(decoded)
	if fragment != "" {
		result += "#" + fragment
	}
	return result, true
}

func shadowsocksCredentials(parsed *url.URL) (string, string, bool) {
	if parsed.User == nil {
		return "", "", false
	}

	if password, ok := parsed.User.Password(); ok {
		return parsed.User.Username(), password, true
	}

	decoded, err := decodeBase64(parsed.User.Username())
	if err != nil {
		return "", "", false
	}

	method, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return "", "", false
	}

	return method, password, true
}

func parseVMessLink(parsed *url.URL) (Server, bool) {
	decoded, err := decodeBase64(parsed.Opaque)
	if err != nil {
		return Server{}, false
	}

	var data map[string]any
	if err := json.Unmarshal(decoded, &data); err != nil {
		return Server{}, false
	}

	server, ok := mapToServer(data)
	if !ok {
		return Server{}, false
	}

	server.Protocol = "vmess"
	return server, true
}

func collectServers(data any, servers *[]Server) {
	switch value := data.(type) {
	case []any:
		for _, item := range value {
			collectServers(item, servers)
		}
	case map[string]any:
		if server, ok := mapXrayConfigToServer(value); ok {
			*servers = append(*servers, server)
			return
		}

		if list, ok := getList(value, "servers", "proxies", "outbounds", "nodes"); ok {
			collectServers(list, servers)
			return
		}

		server, ok := mapToServer(value)
		if ok {
			*servers = append(*servers, server)
			return
		}

		for _, item := range value {
			collectServers(item, servers)
		}
	}
}

func mapXrayConfigToServer(data map[string]any) (Server, bool) {
	name := firstString(data, "remarks", "name", "tag")
	if name == "" {
		return Server{}, false
	}

	outbounds, ok := data["outbounds"].([]any)
	if !ok {
		return Server{}, false
	}

	for _, item := range outbounds {
		outbound, ok := item.(map[string]any)
		if !ok || firstString(outbound, "tag") != "proxy" {
			continue
		}

		protocol := normalizeProtocol(firstString(outbound, "protocol", "type"))
		address, port := xrayOutboundAddress(outbound)
		if address == "" {
			return Server{}, false
		}

		details := detailsFromMap(outbound)
		details["remarks"] = name

		return Server{
			Name:     name,
			Address:  address,
			Port:     port,
			Protocol: protocol,
			Details:  details,
			Raw:      xrayOutboundToSingBox(outbound),
		}, true
	}

	return Server{}, false
}

func xrayOutboundAddress(outbound map[string]any) (string, string) {
	settings, _ := outbound["settings"].(map[string]any)
	if settings == nil {
		return firstString(outbound, "server", "address"), firstString(outbound, "server_port", "port")
	}

	address := firstString(settings, "address", "server", "host")
	port := firstString(settings, "port", "server_port")
	if address != "" {
		return address, port
	}

	if vnext, ok := settings["vnext"].([]any); ok && len(vnext) > 0 {
		if first, ok := vnext[0].(map[string]any); ok {
			return firstString(first, "address", "server", "host"), firstString(first, "port", "server_port")
		}
	}

	if servers, ok := settings["servers"].([]any); ok && len(servers) > 0 {
		if first, ok := servers[0].(map[string]any); ok {
			return firstString(first, "address", "server", "host"), firstString(first, "port", "server_port")
		}
	}

	return "", ""
}

func mapToServer(data map[string]any) (Server, bool) {
	address := firstString(data, "server", "address", "host", "hostname", "ip", "add")
	port := firstString(data, "port", "server_port")

	if address == "" {
		return Server{}, false
	}

	return Server{
		Name:     firstString(data, "name", "remarks", "ps", "tag"),
		Address:  address,
		Port:     port,
		Protocol: normalizeProtocol(firstString(data, "type", "protocol", "network")),
		Details:  detailsFromMap(data),
		Raw:      data,
	}, true
}

func xrayOutboundToSingBox(outbound map[string]any) map[string]any {
	protocol := normalizeProtocol(firstString(outbound, "protocol", "type"))
	address, port := xrayOutboundAddress(outbound)
	if address == "" {
		return nil
	}

	switch protocol {
	case "hysteria":
		settings, _ := outbound["settings"].(map[string]any)
		streamSettings, _ := outbound["streamSettings"].(map[string]any)
		hysteriaSettings, _ := streamSettings["hysteriaSettings"].(map[string]any)
		tlsSettings, _ := streamSettings["tlsSettings"].(map[string]any)

		result := map[string]any{
			"type":        "hysteria2",
			"tag":         "proxy",
			"server":      address,
			"server_port": numberOrString(port),
			"tls": map[string]any{
				"enabled": true,
			},
		}

		if password := firstString(hysteriaSettings, "auth", "password"); password != "" {
			result["password"] = password
		}
		if password := firstString(settings, "password"); password != "" {
			result["password"] = password
		}

		tls := result["tls"].(map[string]any)
		if serverName := firstString(tlsSettings, "serverName", "server_name"); serverName != "" {
			tls["server_name"] = serverName
		}
		if alpn, ok := tlsSettings["alpn"].([]any); ok && len(alpn) > 0 {
			tls["alpn"] = alpn
		}

		return result
	default:
		return nil
	}
}
