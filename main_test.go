package main

import "testing"

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
