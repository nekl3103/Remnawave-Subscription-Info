package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const (
	pingTimeout         = 2 * time.Second
	hysteriaPingTimeout = 12 * time.Second
	pingConcurrency     = 20
	unavailablePing     = "timeout"
	pingNoSingBox       = "no sing-box"
	pingUnavailable     = "error"
	missingPingTarget   = "-"
	hysteriaProbeURL    = "https://www.gstatic.com/generate_204"
)

type pingResult struct {
	Latency time.Duration
	OK      bool
	Skipped bool
	Label   string
}

func pingServers(servers []Server) []string {
	results := make([]string, len(servers))
	jobs := make(chan int)

	workerCount := pingConcurrency
	if len(servers) < workerCount {
		workerCount = len(servers)
	}

	var wg sync.WaitGroup
	for range workerCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				results[index] = formatPingResult(pingServer(servers[index], pingTimeout))
			}
		}()
	}

	for index := range servers {
		jobs <- index
	}
	close(jobs)
	wg.Wait()

	return results
}

func pingServer(server Server, timeout time.Duration) pingResult {
	if server.Address == "" || server.Port == "" {
		return pingResult{Skipped: true}
	}

	if isHysteriaProtocol(server.Protocol) {
		return pingHysteriaServer(server, hysteriaPingTimeout)
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", serverHostPort(server), timeout)
	if err != nil {
		return pingResult{}
	}
	_ = conn.Close()

	return pingResult{Latency: time.Since(start), OK: true}
}

func pingHysteriaServer(server Server, timeout time.Duration) pingResult {
	singBoxPath, err := findSingBox()
	if err != nil {
		return pingResult{Label: pingNoSingBox}
	}

	proxyHost, proxyPort, err := freeLocalProxyAddress()
	if err != nil {
		return pingResult{Label: pingUnavailable}
	}

	config, err := hysteriaPingConfig(server, proxyHost, proxyPort)
	if err != nil {
		return pingResult{Label: pingUnavailable}
	}

	dir, err := os.MkdirTemp("", "terminal-hysteria-ping-*")
	if err != nil {
		return pingResult{Label: pingUnavailable}
	}
	defer os.RemoveAll(dir)

	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		return pingResult{Label: pingUnavailable}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	command := exec.CommandContext(ctx, singBoxPath, "run", "-c", configPath)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return pingResult{Label: pingUnavailable}
	}
	defer func() {
		cancel()
		_ = command.Wait()
	}()

	proxyAddress := net.JoinHostPort(proxyHost, strconv.Itoa(proxyPort))
	if !waitForTCP(proxyAddress, 3*time.Second) {
		return pingResult{Label: pingUnavailable}
	}

	proxyURL := "http://" + proxyAddress
	transport := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			return url.Parse(proxyURL)
		},
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	start := time.Now()
	resp, err := client.Get(hysteriaProbeURL)
	if err != nil {
		return pingResult{}
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 399 {
		return pingResult{}
	}

	return pingResult{Latency: time.Since(start), OK: true}
}

func findSingBox() (string, error) {
	if path, err := exec.LookPath("sing-box"); err == nil {
		return path, nil
	}

	executable, err := os.Executable()
	if err != nil {
		return "", err
	}

	candidates := []string{
		filepath.Join(filepath.Dir(executable), "sing-box"),
		filepath.Join(filepath.Dir(executable), "sing-box.exe"),
	}
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return candidate, nil
		}
	}

	return "", os.ErrNotExist
}

func freeLocalProxyAddress() (string, int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", 0, err
	}
	defer listener.Close()

	address := listener.Addr().(*net.TCPAddr)
	return "127.0.0.1", address.Port, nil
}

func hysteriaPingConfig(server Server, proxyHost string, proxyPort int) ([]byte, error) {
	outbound, err := singBoxOutbound(server)
	if err != nil {
		return nil, err
	}

	config := map[string]any{
		"log": map[string]any{
			"disabled": true,
		},
		"inbounds": []any{
			map[string]any{
				"type":        "mixed",
				"tag":         "mixed-in",
				"listen":      proxyHost,
				"listen_port": proxyPort,
			},
		},
		"outbounds": []any{
			outbound,
			map[string]any{
				"type": "direct",
				"tag":  "direct",
			},
		},
		"route": map[string]any{
			"rules": []any{
				map[string]any{
					"inbound":  []string{"mixed-in"},
					"outbound": "proxy",
				},
			},
			"final": "direct",
		},
	}

	return json.Marshal(config)
}

func waitForTCP(address string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func formatPingResult(result pingResult) string {
	if result.Label != "" {
		return result.Label
	}
	if result.Skipped {
		return missingPingTarget
	}
	if !result.OK {
		return unavailablePing
	}

	ms := result.Latency.Round(time.Millisecond).Milliseconds()
	if ms < 1 {
		ms = 1
	}
	return strconv.FormatInt(ms, 10) + " ms"
}

func pingTargetLabel(server Server) string {
	if server.Address == "" || server.Port == "" {
		return missingPingTarget
	}
	return serverHostPort(server)
}

func pingLabel(server Server, pings map[string]string) string {
	if pings == nil {
		return missingPingTarget
	}
	if value := pings[serverPingKey(server)]; value != "" {
		return value
	}
	return missingPingTarget
}

func serverLabelWithPing(server Server, pings map[string]string) string {
	ping := pingLabel(server, pings)
	if ping == missingPingTarget {
		return serverLabel(server)
	}
	return serverLabel(server) + " | Пинг: " + ping
}

func serverPingKey(server Server) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%s", server.Protocol, server.Address, server.Port, server.Name)
}

func isHysteriaProtocol(protocol string) bool {
	protocol = normalizeProtocol(protocol)
	return protocol == "hysteria" || protocol == "hysteria2"
}
