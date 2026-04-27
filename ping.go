package main

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	pingTimeout       = 2 * time.Second
	pingConcurrency   = 20
	unavailablePing   = "timeout"
	missingPingTarget = "-"
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
		return pingResult{Skipped: true}
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", serverHostPort(server), timeout)
	if err != nil {
		return pingResult{}
	}
	_ = conn.Close()

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

func serverPingKey(server Server) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%s", server.Protocol, server.Address, server.Port, server.Name)
}

func isHysteriaProtocol(protocol string) bool {
	protocol = normalizeProtocol(protocol)
	return protocol == "hysteria" || protocol == "hysteria2"
}
