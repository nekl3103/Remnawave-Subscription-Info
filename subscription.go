package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxSubscriptionBodySize = 10 * 1024 * 1024

func validateSubscriptionURL(value string) error {
	if value == "" {
		return errors.New("ссылка не указана")
	}

	parsed, err := url.ParseRequestURI(value)
	if err != nil {
		return errors.New("введите полную ссылку, например https://example.com/subscription")
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("ссылка должна начинаться с http:// или https://")
	}

	if parsed.Host == "" {
		return errors.New("в ссылке нет домена")
	}

	return nil
}

func fetchSubscriptions(url string) ([][]byte, error) {
	requests := []struct {
		userAgent string
		accept    string
	}{
		{userAgent: "singbox", accept: "application/json"},
		{userAgent: "Happ/1.0", accept: "application/json"},
		{accept: "*/*"},
	}

	bodies := make([][]byte, 0, len(requests))
	var errors []string
	for _, request := range requests {
		body, err := fetch(url, request.userAgent, request.accept)
		if err != nil {
			label := request.userAgent
			if label == "" {
				label = "fallback"
			}
			errors = append(errors, fmt.Sprintf("%s: %v", label, err))
			continue
		}
		if !containsBody(bodies, body) {
			bodies = append(bodies, body)
		}
	}

	if len(bodies) == 0 {
		return nil, fmt.Errorf("все запросы подписки завершились ошибкой: %s", strings.Join(errors, "; "))
	}

	return bodies, nil
}

func fetch(url string, userAgent string, accept string) ([]byte, error) {
	client := &http.Client{Timeout: 15 * time.Second}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSubscriptionBodySize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxSubscriptionBodySize {
		return nil, fmt.Errorf("ответ подписки больше %d MB", maxSubscriptionBodySize/1024/1024)
	}

	return body, nil
}

func sameBody(left []byte, right []byte) bool {
	return strings.TrimSpace(string(left)) == strings.TrimSpace(string(right))
}

func containsBody(bodies [][]byte, body []byte) bool {
	for _, existing := range bodies {
		if sameBody(existing, body) {
			return true
		}
	}

	return false
}

func parseAllServers(bodies [][]byte) ([]Server, error) {
	servers := make([]Server, 0)
	seen := make(map[string]bool)

	var lastErr error
	for _, body := range bodies {
		parsed, err := parseServers(body)
		if err != nil {
			lastErr = err
			continue
		}

		for _, server := range parsed {
			if !isValidServer(server) {
				continue
			}
			key := serverKey(server)
			if seen[key] {
				continue
			}
			seen[key] = true
			servers = append(servers, server)
		}
	}

	if len(servers) == 0 && lastErr != nil {
		return nil, lastErr
	}

	return servers, nil
}

func serverKey(server Server) string {
	return strings.Join([]string{server.Protocol, server.Address, server.Port, server.Name}, "\x00")
}

func isValidServer(server Server) bool {
	if strings.TrimSpace(server.Address) == "" || strings.TrimSpace(server.Port) == "" {
		return false
	}

	switch normalizeProtocol(server.Protocol) {
	case "vless", "vmess", "trojan", "shadowsocks", "hysteria", "hysteria2":
		return true
	default:
		return false
	}
}
