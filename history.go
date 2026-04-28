package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const installHistoryDirName = "remnawave-subscription-info"
const installHistoryFileName = "install-history.json"

func installHistoryPath() string {
	return filepath.Join(os.TempDir(), installHistoryDirName, installHistoryFileName)
}

func appendInstallHistory(server Server, router string, backupPath string, now time.Time) error {
	entries, err := readInstallHistory()
	if err != nil {
		return err
	}

	entries = append(entries, installHistoryEntry{
		Time:       now.Format(time.RFC3339),
		ServerName: server.Name,
		Protocol:   server.Protocol,
		Address:    server.Address,
		Port:       server.Port,
		Router:     router,
		BackupPath: backupPath,
	})

	body, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')

	path := installHistoryPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, body, 0600)
}

func readInstallHistory() ([]installHistoryEntry, error) {
	path := installHistoryPath()
	body, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, nil
	}

	var entries []installHistoryEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func installHistoryText(entries []installHistoryEntry) string {
	if len(entries) == 0 {
		return "История установок пуста"
	}

	var builder strings.Builder
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		builder.WriteString(entry.Time)
		builder.WriteString(" | ")
		builder.WriteString(valueOrDash(entry.ServerName))
		builder.WriteString(" [")
		builder.WriteString(valueOrDash(entry.Protocol))
		builder.WriteString("] | ")
		builder.WriteString(valueOrDash(entry.Address))
		if entry.Port != "" {
			builder.WriteString(":")
			builder.WriteString(entry.Port)
		}
		builder.WriteString(" | router: ")
		builder.WriteString(valueOrDash(entry.Router))
		builder.WriteString(" | backup: ")
		builder.WriteString(valueOrDash(entry.BackupPath))
		if i > 0 {
			builder.WriteString("\n")
		}
	}

	return builder.String()
}
