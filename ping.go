package main

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	pingTimeout       = 2 * time.Second
	pingConcurrency   = 20
	unavailablePing   = "timeout"
	missingPingTarget = "-"
)

var hysteriaPingURL = "https://www.gstatic.com/generate_204"

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

func pingAndSortServers(servers []Server, pings map[string]string) []Server {
	results := pingServers(servers)
	for index, server := range servers {
		pings[serverPingKey(server)] = results[index]
	}

	return sortServersByPing(servers, pings)
}

func sortServersByPing(servers []Server, pings map[string]string) []Server {
	sorted := append([]Server(nil), servers...)
	sort.SliceStable(sorted, func(i, j int) bool {
		left := pingSortRank(pings[serverPingKey(sorted[i])])
		right := pingSortRank(pings[serverPingKey(sorted[j])])
		if left.rank != right.rank {
			return left.rank < right.rank
		}
		if left.latency != right.latency {
			return left.latency < right.latency
		}
		return serverLabel(sorted[i]) < serverLabel(sorted[j])
	})
	return sorted
}

type pingRank struct {
	rank    int
	latency int64
}

func pingSortRank(value string) pingRank {
	if value == missingPingTarget || value == "" {
		return pingRank{rank: 2}
	}
	if value == unavailablePing {
		return pingRank{rank: 1}
	}
	msText := strings.TrimSuffix(value, " ms")
	ms, err := strconv.ParseInt(msText, 10, 64)
	if err != nil {
		return pingRank{rank: 1}
	}
	return pingRank{rank: 0, latency: ms}
}

func pingServer(server Server, timeout time.Duration) pingResult {
	if server.Address == "" || server.Port == "" {
		return pingResult{Skipped: true}
	}

	if isHysteriaProtocol(server.Protocol) {
		return pingHTTP(hysteriaPingURL, timeout)
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", serverHostPort(server), timeout)
	if err != nil {
		return pingResult{}
	}
	_ = conn.Close()

	return pingResult{Latency: time.Since(start), OK: true}
}

func pingHTTP(url string, timeout time.Duration) pingResult {
	client := http.Client{Timeout: timeout}
	start := time.Now()

	response, err := client.Get(url)
	if err != nil {
		return pingResult{}
	}
	_ = response.Body.Close()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return pingResult{}
	}

	return pingResult{Latency: time.Since(start), OK: true}
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

func serverLabelWithColoredPing(server Server, pings map[string]string) string {
	ping := pingLabel(server, pings)
	if ping == missingPingTarget {
		return serverLabel(server)
	}
	return serverLabel(server) + " | Пинг: " + colorPing(ping)
}

func colorPing(ping string) string {
	if ping == unavailablePing {
		return colorRed + ping + colorReset
	}

	msText := strings.TrimSuffix(ping, " ms")
	ms, err := strconv.ParseInt(msText, 10, 64)
	if err != nil {
		return ping
	}
	switch {
	case ms <= 90:
		return colorGreen + ping + colorReset
	case ms <= 200:
		return colorYellow + ping + colorReset
	default:
		return colorRed + ping + colorReset
	}
}

func serverPingKey(server Server) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%s", server.Protocol, server.Address, server.Port, server.Name)
}

func isHysteriaProtocol(protocol string) bool {
	protocol = normalizeProtocol(protocol)
	return protocol == "hysteria" || protocol == "hysteria2"
}
