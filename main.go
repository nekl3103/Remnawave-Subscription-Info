package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type Server struct {
	Name     string
	Address  string
	Port     string
	Protocol string
	Details  map[string]string
	Raw      map[string]any
}

const (
	defaultRouterAddress = "root@192.168.1.1"
	colorGreen           = "\033[32m"
	colorRed             = "\033[31m"
	colorBold            = "\033[1m"
	colorReset           = "\033[0m"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Введите ссылку подписки: ")
	url, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка чтения ссылки: %v\n", err)
		os.Exit(1)
	}

	url = strings.TrimSpace(url)
	if url == "" {
		fmt.Fprintln(os.Stderr, "Ссылка не указана")
		os.Exit(1)
	}

	bodies, err := fetchSubscriptions(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка загрузки подписки: %v\n", err)
		os.Exit(1)
	}

	servers, err := parseAllServers(bodies)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка парсинга подписки: %v\n", err)
		os.Exit(1)
	}

	if len(servers) == 0 {
		fmt.Println("Серверы не найдены")
		return
	}

	for {
		server, ok := selectServer(reader, servers)
		if !ok {
			return
		}

		if handleServerActions(reader, server) {
			return
		}
	}
}

func selectServer(reader *bufio.Reader, servers []Server) (Server, bool) {
	printTitle("Список серверов:")
	for i, server := range servers {
		fmt.Printf("%d. %s", i+1, valueOrDash(server.Name))
		if server.Protocol != "" {
			fmt.Printf(" [%s]", server.Protocol)
		}
		if server.Address != "" || server.Port != "" {
			fmt.Printf(" - %s", valueOrDash(server.Address))
			if server.Port != "" {
				fmt.Printf(":%s", server.Port)
			}
		}
		fmt.Println()
	}
	fmt.Println("0. Выйти")

	for {
		fmt.Print("Выберите номер сервера: ")
		choiceText, err := reader.ReadString('\n')
		if err != nil {
			printError(fmt.Sprintf("Ошибка чтения номера: %v", err))
			return Server{}, false
		}

		choice, err := strconv.Atoi(strings.TrimSpace(choiceText))
		if err == nil && choice == 0 {
			return Server{}, false
		}
		if err == nil && choice >= 1 && choice <= len(servers) {
			server := servers[choice-1]
			printServerDetails(server)
			return server, true
		}

		fmt.Println("Неверный номер сервера")
	}
}

func handleServerActions(reader *bufio.Reader, server Server) bool {
	for {
		fmt.Println()
		printTitle("Что сделать дальше?")
		fmt.Println("1. Показать настройки для sing-box")
		fmt.Println("2. Заполнить данные сервера на роутер")
		fmt.Println("3. Посмотреть логи sing-box")
		fmt.Println("4. Сменить сервер")
		fmt.Println("0. Выйти")
		fmt.Print("Выберите пункт: ")

		choice, err := readMenuChoice(reader)
		if err != nil {
			printError(fmt.Sprintf("Ошибка чтения пункта: %v", err))
			return true
		}

		switch choice {
		case 0:
			return true
		case 1:
			if err := printSingBoxOutbounds(server); err != nil {
				printError(fmt.Sprintf("Ошибка генерации sing-box outbound: %v", err))
			}
		case 2:
			router, err := connectRouter(reader)
			if err != nil {
				printError(fmt.Sprintf("Ошибка подключения к роутеру: %v", err))
				continue
			}
			if err := installRouterConfig(router, server); err != nil {
				router.Close()
				printError(fmt.Sprintf("Ошибка настройки роутера: %v", err))
				continue
			}
			printInfo("Конфиг сохранен, sing-box перезагружен")
			if handleRouterPostActions(reader, router) {
				router.Close()
				return true
			}
			router.Close()
			return false
		case 3:
			router, err := connectRouter(reader)
			if err != nil {
				printError(fmt.Sprintf("Ошибка подключения к роутеру: %v", err))
				continue
			}
			printSingBoxLogs(router)
			router.Close()
		case 4:
			return false
		default:
			fmt.Println("Неверный пункт меню")
		}
	}
}

func handleRouterPostActions(reader *bufio.Reader, router *ssh.Client) bool {
	for {
		fmt.Println()
		printTitle("Что сделать дальше?")
		fmt.Println("1. Посмотреть логи sing-box")
		fmt.Println("2. Сменить сервер")
		fmt.Println("0. Выйти")
		fmt.Print("Выберите пункт: ")

		choice, err := readMenuChoice(reader)
		if err != nil {
			printError(fmt.Sprintf("Ошибка чтения пункта: %v", err))
			return true
		}

		switch choice {
		case 0:
			return true
		case 1:
			printSingBoxLogs(router)
		case 2:
			return false
		default:
			fmt.Println("Неверный пункт меню")
		}
	}
}

func readMenuChoice(reader *bufio.Reader) (int, error) {
	text, err := reader.ReadString('\n')
	if err != nil {
		return 0, err
	}

	return strconv.Atoi(strings.TrimSpace(text))
}

func fetchSubscriptions(url string) ([][]byte, error) {
	singBoxBody, err := fetch(url, "singbox", "application/json")
	if err != nil {
		return nil, err
	}

	bodies := [][]byte{singBoxBody}

	happBody, err := fetch(url, "Happ/1.0", "application/json")
	if err == nil && !containsBody(bodies, happBody) {
		bodies = append(bodies, happBody)
	}

	fallbackBody, err := fetch(url, "", "*/*")
	if err == nil && !containsBody(bodies, fallbackBody) {
		bodies = append(bodies, fallbackBody)
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

	return io.ReadAll(resp.Body)
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
	if server.Name != "" {
		return server.Name
	}

	return strings.Join([]string{server.Name, server.Protocol, server.Address, server.Port}, "\x00")
}

func normalizeProtocol(protocol string) string {
	switch strings.ToLower(protocol) {
	case "ss":
		return "shadowsocks"
	case "hy2":
		return "hysteria2"
	default:
		return protocol
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
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" {
		return Server{}, false
	}

	switch parsed.Scheme {
	case "vless", "vmess", "trojan", "ss", "hysteria", "hysteria2", "hy2":
	default:
		return Server{}, false
	}

	if parsed.Scheme == "vmess" && parsed.Host == "" {
		return parseVMessLink(parsed)
	}

	return Server{
		Name:     firstNonEmpty(parsed.Fragment, parsed.Query().Get("remarks"), parsed.Query().Get("name")),
		Address:  parsed.Hostname(),
		Port:     parsed.Port(),
		Protocol: normalizeProtocol(parsed.Scheme),
		Details:  detailsFromURL(parsed),
		Raw:      shareLinkToSingBox(parsed),
	}, true
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
		if serverName := firstNonEmpty(query.Get("sni"), query.Get("peer"), query.Get("server_name")); serverName != "" {
			outbound["tls"].(map[string]any)["server_name"] = serverName
		}
		if alpn := query.Get("alpn"); alpn != "" {
			outbound["tls"].(map[string]any)["alpn"] = strings.Split(alpn, ",")
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
		return outbound
	case "trojan":
		return map[string]any{
			"type":        "trojan",
			"tag":         "proxy",
			"server":      parsed.Hostname(),
			"server_port": numberOrString(parsed.Port()),
			"password":    parsed.User.Username(),
		}
	default:
		return nil
	}
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
		return "", ""
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

func printSingBoxOutbounds(server Server) error {
	outbound, err := singBoxOutbound(server)
	if err != nil {
		return err
	}

	config := map[string]any{
		"outbounds": []any{outbound},
	}

	body, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Println(string(body))
	return nil
}

func connectRouter(reader *bufio.Reader) (*ssh.Client, error) {
	fmt.Printf("Введите SSH адрес роутера или нажмите Enter для %s: ", defaultRouterAddress)
	addressText, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	address := strings.TrimSpace(addressText)
	if address == "" {
		address = defaultRouterAddress
	}

	user, host, err := parseSSHAddress(address)
	if err != nil {
		return nil, err
	}

	fmt.Printf("Введите пароль %s@%s: ", user, host)
	password, err := readPassword(reader)
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	if !strings.Contains(host, ":") {
		host += ":22"
	}

	return ssh.Dial("tcp", host, config)
}

func parseSSHAddress(address string) (string, string, error) {
	user := "root"
	host := address

	if strings.Contains(address, "@") {
		parts := strings.SplitN(address, "@", 2)
		user = strings.TrimSpace(parts[0])
		host = strings.TrimSpace(parts[1])
	}

	if user == "" || host == "" {
		return "", "", errors.New("неверный SSH адрес")
	}

	return user, host, nil
}

func readPassword(reader *bufio.Reader) (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", err
		}
		return string(password), nil
	}

	text, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(text), nil
}

func installRouterConfig(router *ssh.Client, server Server) error {
	outbound, err := singBoxOutbound(server)
	if err != nil {
		return err
	}

	const configPath = "/etc/sing-box/config.json"

	body, err := runRemote(router, "cat "+shellQuote(configPath))
	if err != nil {
		return err
	}

	var config map[string]any
	if err := json.Unmarshal([]byte(body), &config); err != nil {
		return err
	}

	config["outbounds"] = []any{outbound}

	updated, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	updated = append(updated, '\n')

	backupPath := configPath + ".bak"
	if _, err := runRemote(router, "cp "+shellQuote(configPath)+" "+shellQuote(backupPath)); err != nil {
		return err
	}

	if err := writeRemote(router, configPath, updated); err != nil {
		return err
	}

	return restartSingBox(router)
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
		return outbound, nil
	case "vless":
		return map[string]any{
			"type":        "vless",
			"tag":         "proxy",
			"server":      server.Address,
			"server_port": numberOrString(server.Port),
			"uuid":        firstNonEmpty(server.Details["uuid"], server.Details["user"]),
			"flow":        server.Details["flow"],
		}, nil
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
		return map[string]any{
			"type":        "trojan",
			"tag":         "proxy",
			"server":      server.Address,
			"server_port": numberOrString(server.Port),
			"password":    firstNonEmpty(server.Details["password"], server.Details["user"]),
		}, nil
	default:
		return nil, fmt.Errorf("протокол %q не поддержан для генерации sing-box", server.Protocol)
	}
}

func cloneMap(source map[string]any) map[string]any {
	cloned := make(map[string]any, len(source))
	for key, value := range source {
		if nested, ok := value.(map[string]any); ok {
			cloned[key] = cloneMap(nested)
			continue
		}
		cloned[key] = value
	}

	return cloned
}

func numberOrString(value string) any {
	if number, err := strconv.Atoi(value); err == nil {
		return number
	}

	return value
}

func restartSingBox(router *ssh.Client) error {
	commands := [][]string{
		{"/etc/init.d/sing-box", "restart"},
		{"service", "sing-box", "restart"},
	}

	var lastErr error
	for _, command := range commands {
		output, err := runRemote(router, strings.Join(command, " "))
		if err == nil {
			return nil
		}
		lastErr = fmt.Errorf("%s: %w: %s", strings.Join(command, " "), err, strings.TrimSpace(output))
	}

	return lastErr
}

func printSingBoxLogs(router *ssh.Client) {
	printInfo("Логи sing-box в реальном времени. Нажмите Enter, чтобы остановить просмотр.")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- streamRemote(ctx, router, "logread -f -e sing-box")
	}()

	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	cancel()

	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		printError(fmt.Sprintf("Не удалось прочитать логи sing-box: %v", err))
	}
}

func printInfo(message string) {
	fmt.Println(colorGreen + message + colorReset)
}

func printError(message string) {
	fmt.Println(colorRed + message + colorReset)
}

func printTitle(message string) {
	fmt.Println(colorBold + message + colorReset)
}

func runRemote(router *ssh.Client, command string) (string, error) {
	session, err := router.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	return string(output), err
}

func streamRemote(ctx context.Context, router *ssh.Client, command string) error {
	session, err := router.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		return err
	}

	if err := session.Start(command); err != nil {
		return err
	}

	done := make(chan error, 1)
	go func() {
		_, stdoutErr := io.Copy(os.Stdout, stdout)
		_, stderrErr := io.Copy(os.Stderr, stderr)
		if stdoutErr != nil {
			done <- stdoutErr
			return
		}
		done <- stderrErr
	}()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGTERM)
		_ = session.Close()
		<-done
		return ctx.Err()
	case err := <-done:
		if err != nil {
			return err
		}
		return session.Wait()
	}
}

func writeRemote(router *ssh.Client, path string, body []byte) error {
	session, err := router.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}

	if err := session.Start("cat > " + shellQuote(path)); err != nil {
		return err
	}

	if _, err := stdin.Write(body); err != nil {
		_ = stdin.Close()
		return err
	}
	if err := stdin.Close(); err != nil {
		return err
	}

	return session.Wait()
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
	fmt.Println()
	fmt.Println("Детальная информация:")
	fmt.Printf("Название: %s\n", valueOrDash(server.Name))
	fmt.Printf("Протокол: %s\n", valueOrDash(server.Protocol))
	fmt.Printf("Адрес: %s\n", valueOrDash(server.Address))
	fmt.Printf("Порт: %s\n", valueOrDash(server.Port))

	keys := make([]string, 0, len(server.Details))
	for key := range server.Details {
		if isMainDetail(key) {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		fmt.Printf("%s: %s\n", key, server.Details[key])
	}
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
