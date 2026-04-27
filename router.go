package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

type routerClient interface {
	Close() error
	NewSession() (*ssh.Session, error)
}

type routerCredentials struct {
	Address     string
	User        string
	Host        string
	DialAddress string
	Password    string
}

type routerCredentialCache struct {
	credentials *routerCredentials
}

func (cache *routerCredentialCache) clear() {
	cache.credentials = nil
}

func (cache *routerCredentialCache) label() string {
	if cache.credentials == nil {
		return defaultRouterAddress
	}

	return cache.credentials.Address
}

func connectRouter(reader *bufio.Reader, cache *routerCredentialCache) (*ssh.Client, error) {
	credentials := cache.credentials
	if credentials == nil {
		var err error
		credentials, err = readRouterCredentials(reader)
		if err != nil {
			return nil, err
		}
	} else {
		printInfo(fmt.Sprintf("Подключаюсь к %s...", credentials.Address))
	}

	client, err := dialRouter(reader, credentials)
	if err != nil {
		cache.clear()
		return nil, err
	}

	cache.credentials = credentials
	return client, nil
}

func readRouterCredentials(reader *bufio.Reader) (*routerCredentials, error) {
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

	dialAddress := host
	if !strings.Contains(dialAddress, ":") {
		dialAddress += ":22"
	}

	fmt.Printf("Введите пароль %s@%s: ", user, host)
	password, err := readPassword(reader)
	if err != nil {
		return nil, err
	}

	return &routerCredentials{
		Address:     address,
		User:        user,
		Host:        host,
		DialAddress: dialAddress,
		Password:    password,
	}, nil
}

func dialRouter(reader *bufio.Reader, credentials *routerCredentials) (*ssh.Client, error) {
	hostKeyCallback, err := tofuHostKeyCallback(reader, credentials.DialAddress)
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User:            credentials.User,
		Auth:            []ssh.AuthMethod{ssh.Password(credentials.Password)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}

	return ssh.Dial("tcp", credentials.DialAddress, config)
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

func tofuHostKeyCallback(reader *bufio.Reader, dialAddress string) (ssh.HostKeyCallback, error) {
	path, err := appKnownHostsPath()
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}

	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
	}

	knownCallback, err := knownhosts.New(path)
	if err != nil {
		return nil, err
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := knownCallback(hostname, remote, key)
		if err == nil {
			return nil
		}

		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) {
			return err
		}
		if len(keyErr.Want) > 0 {
			return fmt.Errorf("SSH host key изменился для %s; подключение остановлено", hostname)
		}

		fingerprint := ssh.FingerprintSHA256(key)
		fmt.Printf("Новый SSH host key для %s: %s\n", dialAddress, fingerprint)
		if !confirmYN(reader, "Доверять этому ключу? Продолжить? Введите y/n: ") {
			return errors.New("SSH host key не подтвержден")
		}

		return appendKnownHost(path, hostname, key)
	}, nil
}

func appKnownHostsPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, appConfigDirName, "known_hosts"), nil
}

func appendKnownHost(path string, hostname string, key ssh.PublicKey) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = fmt.Fprintln(file, knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key))
	return err
}

func installRouterConfig(router routerClient, server Server) error {
	outbound, err := singBoxOutbound(server)
	if err != nil {
		return err
	}

	body, err := runRemote(router, "cat "+shellQuote(routerConfigPath))
	if err != nil {
		return err
	}

	var config map[string]any
	if err := json.Unmarshal([]byte(body), &config); err != nil {
		return err
	}

	updateSingBoxConfig(config, outbound)

	updated, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	updated = append(updated, '\n')

	if _, err := backupRouterConfig(router); err != nil {
		return err
	}

	tmpPath := fmt.Sprintf("/tmp/sing-box-config-%d.json", time.Now().UnixNano())
	if err := writeRemote(router, tmpPath, updated); err != nil {
		return err
	}
	defer runRemote(router, "rm -f "+shellQuote(tmpPath))

	if _, err := runRemote(router, "mv "+shellQuote(tmpPath)+" "+shellQuote(routerConfigPath)); err != nil {
		return err
	}

	return restartSingBox(router)
}

func backupRouterConfig(router routerClient) (string, error) {
	path := timestampedRouterBackupPath(time.Now())
	_, err := runRemote(router, "cp "+shellQuote(routerConfigPath)+" "+shellQuote(path))
	return path, err
}

func restoreRouterConfig(router routerClient) error {
	backupPath, err := latestRouterBackupPath(router)
	if err != nil {
		return err
	}

	if _, err := runRemote(router, "cp "+shellQuote(backupPath)+" "+shellQuote(routerConfigPath)); err != nil {
		return err
	}
	return restartSingBox(router)
}

func timestampedRouterBackupPath(now time.Time) string {
	return routerBackupPath + "." + now.Format("20060102-150405")
}

func latestRouterBackupPath(router routerClient) (string, error) {
	command := "sh -c " + shellQuote("ls -1t "+routerBackupPath+".* "+routerBackupPath+" 2>/dev/null | head -n 1")
	output, err := runRemote(router, command)
	if err != nil {
		return "", err
	}

	path := firstBackupPath(output)
	if path == "" {
		return "", errors.New("backup sing-box не найден")
	}
	return path, nil
}

func firstBackupPath(output string) string {
	for _, line := range strings.Split(output, "\n") {
		path := strings.TrimSpace(line)
		if path != "" {
			return path
		}
	}
	return ""
}

func updateSingBoxConfig(config map[string]any, outbound map[string]any) {
	outbounds, _ := config["outbounds"].([]any)
	updated := make([]any, 0, len(outbounds)+1)
	replaced := false

	for _, item := range outbounds {
		existing, ok := item.(map[string]any)
		if ok && firstString(existing, "tag") == "proxy" {
			updated = append(updated, outbound)
			replaced = true
			continue
		}
		updated = append(updated, item)
	}

	if !replaced {
		updated = append(updated, outbound)
	}

	config["outbounds"] = updated
}

func restartSingBox(router routerClient) error {
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

func singBoxStatus(router routerClient) (string, error) {
	commands := [][]string{
		{"/etc/init.d/sing-box", "status"},
		{"service", "sing-box", "status"},
	}

	var lastErr error
	for _, command := range commands {
		output, err := runRemote(router, strings.Join(command, " "))
		if err == nil {
			return strings.TrimSpace(output), nil
		}
		lastErr = fmt.Errorf("%s: %w: %s", strings.Join(command, " "), err, strings.TrimSpace(output))
	}

	return "", lastErr
}

func checkRouterConnection(router routerClient) error {
	output, err := runRemote(router, "echo ok")
	if err != nil {
		return err
	}
	if strings.TrimSpace(output) != "ok" {
		return fmt.Errorf("неожиданный ответ роутера: %s", strings.TrimSpace(output))
	}
	return nil
}

func currentRouterProxy(router routerClient) (string, error) {
	body, err := runRemote(router, "cat "+shellQuote(routerConfigPath))
	if err != nil {
		return "", err
	}

	var config map[string]any
	if err := json.Unmarshal([]byte(body), &config); err != nil {
		return "", err
	}

	outbounds, _ := config["outbounds"].([]any)
	for _, item := range outbounds {
		outbound, ok := item.(map[string]any)
		if !ok || firstString(outbound, "tag") != "proxy" {
			continue
		}

		body, err := json.MarshalIndent(outbound, "", "  ")
		if err != nil {
			return "", err
		}
		return string(body), nil
	}

	return "", errors.New("outbound с tag proxy не найден")
}

func printSingBoxLogs(router routerClient) {
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

func runRemote(router routerClient, command string) (string, error) {
	session, err := router.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	return string(output), err
}

func streamRemote(ctx context.Context, router routerClient, command string) error {
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

func writeRemote(router routerClient, path string, body []byte) error {
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
