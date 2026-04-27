package main

import (
	"errors"
	"fmt"
	"net/url"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

func clearTerminal() {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return
	}

	fmt.Print("\033[H\033[2J")
}

func printInfo(message string) {
	fmt.Println(colorBlue + message + colorReset)
}

func printSuccess(message string) {
	fmt.Println(colorGreen + message + colorReset)
}

func printWarning(message string) {
	fmt.Println(colorYellow + message + colorReset)
}

func printError(message string) {
	fmt.Println(colorRed + message + colorReset)
}

func printTitle(message string) {
	fmt.Println(colorBold + message + colorReset)
}

func serverLabel(server Server) string {
	name := valueOrDash(server.Name)
	if server.Protocol == "" {
		return name
	}

	return fmt.Sprintf("%s [%s]", name, server.Protocol)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func detailsFromMap(data map[string]any) map[string]string {
	details := make(map[string]string)
	for key, value := range data {
		addDetail(details, key, value)
	}

	return details
}

func addDetail(details map[string]string, key string, value any) {
	switch typed := value.(type) {
	case map[string]any:
		for nestedKey, nestedValue := range typed {
			addDetail(details, key+"."+nestedKey, nestedValue)
		}
	case []any:
		if len(typed) == 0 {
			return
		}

		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			part, err := stringify(item)
			if err == nil && part != "" {
				parts = append(parts, part)
			}
		}

		if len(parts) > 0 {
			details[key] = strings.Join(parts, ", ")
		}
	default:
		text, err := stringify(value)
		if err == nil && text != "" {
			details[key] = text
		}
	}
}

func detailsFromURL(parsed *url.URL) map[string]string {
	details := map[string]string{
		"protocol": parsed.Scheme,
		"address":  parsed.Hostname(),
		"port":     parsed.Port(),
	}

	if parsed.User != nil {
		details["user"] = parsed.User.Username()
		if password, ok := parsed.User.Password(); ok {
			details["password"] = password
		}
	}

	for key, values := range parsed.Query() {
		if len(values) > 0 {
			details[key] = strings.Join(values, ", ")
		}
	}

	return details
}

func printServerDetails(server Server) {
	printTitle("Детальная информация")
	fmt.Println()
	fmt.Println(serverDetailsText(server))
}

func serverDetailsText(server Server) string {
	var builder strings.Builder

	builder.WriteString(fmt.Sprintf("Название: %s\n", valueOrDash(server.Name)))
	builder.WriteString(fmt.Sprintf("Протокол: %s\n", valueOrDash(server.Protocol)))
	builder.WriteString(fmt.Sprintf("Адрес: %s\n", valueOrDash(server.Address)))
	builder.WriteString(fmt.Sprintf("Порт: %s\n", valueOrDash(server.Port)))

	keys := make([]string, 0, len(server.Details))
	for key := range server.Details {
		if isMainDetail(key) {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		builder.WriteString(fmt.Sprintf("%s: %s\n", key, server.Details[key]))
	}

	return strings.TrimRight(builder.String(), "\n")
}

func isMainDetail(key string) bool {
	switch key {
	case "name", "remarks", "ps", "tag", "server", "address", "host", "hostname", "ip", "add", "port", "server_port", "type", "protocol", "network":
		return true
	default:
		return false
	}
}

func getList(data map[string]any, keys ...string) (any, bool) {
	for _, key := range keys {
		value, ok := data[key]
		if ok {
			return value, true
		}
	}

	return nil, false
}

func firstString(data map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := data[key]
		if !ok {
			continue
		}

		result, err := stringify(value)
		if err == nil && result != "" {
			return result
		}
	}

	return ""
}

func stringify(value any) (string, error) {
	switch typed := value.(type) {
	case string:
		return typed, nil
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10), nil
		}
		return strconv.FormatFloat(typed, 'f', -1, 64), nil
	case bool:
		return strconv.FormatBool(typed), nil
	default:
		return "", errors.New("value is not scalar")
	}
}

func valueOrDash(value string) string {
	if value == "" {
		return "-"
	}

	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}

	return ""
}

func splitCommaValues(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}
