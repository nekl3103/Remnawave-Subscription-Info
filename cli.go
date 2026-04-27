package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type appState struct {
	subscriptionURL string
	allServers      []Server
	visibleServers  []Server
	pings           map[string]string
	routerCache     routerCredentialCache
}

func newAppState() *appState {
	return &appState{
		pings: make(map[string]string),
	}
}

func printWelcome() {
	printTitle(" ____                                      ____        _                   _       _   _               ___        __       ")
	printTitle("|  _ \\ ___ _ __ ___  _ __   __ ___      _/ ___| _   _| |__  ___  ___ _ __(_)_ __ | |_(_) ___  _ __   |_ _|_ __  / _| ___  ")
	printTitle("| |_) / _ \\ '_ ` _ \\| '_ \\ / _` \\ \\ /\\ / /\\___ \\| | | | '_ \\/ __|/ __| '__| | '_ \\| __| |/ _ \\| '_ \\   | || '_ \\| |_ / _ \\ ")
	printTitle("|  _ <  __/ | | | | | | | | (_| |\\ V  V /  ___) | |_| | |_) \\__ \\ (__| |  | | |_) | |_| | (_) | | | |  | || | | |  _| (_) |")
	printTitle("|_| \\_\\___|_| |_| |_|_| |_|\\__,_| \\_/\\_/  |____/ \\__,_|_.__/|___/\\___|_|  |_| .__/ \\__|_|\\___/|_| |_| |___|_| |_|_|  \\___/ ")
	printTitle("                                                                            |_|                                            ")
	fmt.Println()
	printInfo("Версия: " + appVersion)
	fmt.Println("Remnawave Subscription Info")
	fmt.Println("GitHub: https://github.com/nekl3103/Remnawave-Subscription-Info")
	fmt.Println("Telegram: @snek173")
	fmt.Println()
}

func (state *appState) loadSubscription(reader *bufio.Reader) {
	for {
		fmt.Print("Введите ссылку подписки или 0 для выхода: ")
		subscriptionURL, err := reader.ReadString('\n')
		if err != nil {
			printError(fmt.Sprintf("Ошибка чтения ссылки: %v", err))
			os.Exit(1)
		}

		subscriptionURL = strings.TrimSpace(subscriptionURL)
		if subscriptionURL == "0" {
			os.Exit(0)
		}

		servers, err := loadServers(subscriptionURL)
		if err != nil {
			printError(err.Error())
			continue
		}

		state.subscriptionURL = subscriptionURL
		state.allServers = servers
		state.visibleServers = servers
		clearTerminal()
		printSuccess(fmt.Sprintf("Загружено серверов: %d", len(servers)))
		return
	}
}

func loadServers(subscriptionURL string) ([]Server, error) {
	if err := validateSubscriptionURL(subscriptionURL); err != nil {
		return nil, fmt.Errorf("Некорректная ссылка: %v", err)
	}

	bodies, err := fetchSubscriptions(subscriptionURL)
	if err != nil {
		return nil, fmt.Errorf("Ошибка загрузки подписки: %v", err)
	}

	servers, err := parseAllServers(bodies)
	if err != nil {
		return nil, fmt.Errorf("Ошибка парсинга подписки: %v", err)
	}

	if len(servers) == 0 {
		return nil, fmt.Errorf("Серверы не найдены")
	}

	return servers, nil
}

func selectServer(reader *bufio.Reader, state *appState) (Server, bool) {
	for {
		printServerList(state.visibleServers)
		fmt.Println("0. Выйти | s. Поиск сервера по названию | f. Фильтр по протоколу | r. Обновить список серверов")
		fmt.Print("Выберите номер сервера: ")

		choiceValue, err := readServerChoice(reader)
		if err != nil {
			printError(fmt.Sprintf("Ошибка чтения номера: %v", err))
			return Server{}, false
		}

		switch choiceValue {
		case "s":
			clearTerminal()
			printSelectedMenu("Поиск сервера по названию")
			searchServers(reader, state)
			continue
		case "f":
			clearTerminal()
			printSelectedMenu("Фильтр по протоколу")
			filterServers(reader, state)
			continue
		case "r":
			clearTerminal()
			printSelectedMenu("Обновить список серверов")
			refreshServers(state)
			continue
		}

		choice, err := strconv.Atoi(choiceValue)
		if err == nil && choice == 0 {
			return Server{}, false
		}
		if err == nil && choice >= 1 && choice <= len(state.visibleServers) {
			server := state.visibleServers[choice-1]
			clearTerminal()
			return server, true
		}

		clearTerminal()
		printSelectedMenu("Неверный номер сервера")
		printWarning("Неверный номер сервера")
	}
}

func readServerChoice(reader *bufio.Reader) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		choiceText, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(strings.ToLower(choiceText)), nil
	}

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	var digits []byte
	buffer := make([]byte, 1)
	for {
		if _, err := os.Stdin.Read(buffer); err != nil {
			return "", err
		}

		key := buffer[0]
		switch {
		case key == 3:
			fmt.Println()
			return "0", nil
		case key == 's' || key == 'S' || key == 'f' || key == 'F' || key == 'r' || key == 'R' || key == '0':
			fmt.Printf("%c\n", key)
			return strings.ToLower(string(key)), nil
		case key >= '1' && key <= '9':
			digits = append(digits, key)
			fmt.Printf("%c", key)
		case key == '\r' || key == '\n':
			if len(digits) == 0 {
				fmt.Println()
				continue
			}
			fmt.Println()
			return string(digits), nil
		case key == 127 || key == 8:
			if len(digits) > 0 {
				digits = digits[:len(digits)-1]
				fmt.Print("\b \b")
			}
		}
	}
}

func printServerList(servers []Server) {
	if len(servers) == 0 {
		printWarning("Список серверов пуст. Обновите подписку или сбросьте фильтр.")
		return
	}

	printTitle("Список серверов:")
	fmt.Printf("%-4s %-32s %-14s %-32s %-6s\n", "№", "Название", "Протокол", "Адрес", "Порт")
	fmt.Printf("%-4s %-32s %-14s %-32s %-6s\n", "--", "--------", "--------", "-----", "----")
	for i, server := range servers {
		fmt.Printf(
			"%-4d %-32s %-14s %-32s %-6s\n",
			i+1,
			shortText(valueOrDash(server.Name), 32),
			shortText(valueOrDash(server.Protocol), 14),
			shortText(valueOrDash(server.Address), 32),
			shortText(valueOrDash(server.Port), 6),
		)
	}
}

func handleServerActions(reader *bufio.Reader, state *appState, server Server) bool {
	refreshServerPing(state, server)

	for {
		fmt.Println()
		printTitle("Сервер: " + serverLabelWithPing(server, state.pings))
		fmt.Println("1. Проверить пинг")
		fmt.Println("2. Сменить сервер")
		fmt.Printf("3. Получить ссылку подключения (%s://)\n", displayLinkProtocol(server.Protocol))
		fmt.Println("4. Установить на роутер")
		fmt.Println("5. Посмотреть логи роутера (sing-box)")
		fmt.Println("6. Показать текущие настройки sing-box")
		fmt.Println("7. Показать новые настройки для sing-box")
		fmt.Println("8. Проверить статус sing-box на роутере")
		fmt.Println("9. Показать детальную информацию")
		fmt.Println("10. Проверить подключение к роутеру")
		fmt.Println("11. Сделать backup sing-box (config) вручную")
		fmt.Println("12. Восстановить sing-box (config) из backup")
		fmt.Println("13. Экспортировать sing-box outbound в файл")
		fmt.Println("14. Сбросить сохраненные SSH данные")
		fmt.Println("0. Выйти")
		fmt.Print("Выберите пункт: ")

		choice, err := readMenuChoice(reader)
		if err != nil {
			printError(fmt.Sprintf("Ошибка чтения пункта: %v", err))
			return true
		}
		if choice == emptyMenuChoice {
			clearTerminal()
			continue
		}

		if choice != 0 {
			clearTerminal()
		}
		if shouldShowSelectedServerAction(choice) {
			printSelectedMenu(serverActionTitle(choice, server))
		}

		switch choice {
		case 0:
			return true
		case 1:
			refreshServerPing(state, server)
		case 2:
			return false
		case 3:
			if err := printConnectionLink(server); err != nil {
				printError(fmt.Sprintf("Ошибка генерации ссылки: %v", err))
			}
		case 4:
			if installServerOnRouter(reader, state, server) {
				return true
			}
			return false
		case 5:
			withRouter(reader, state, func(router *sshClientWrapper) {
				printSingBoxLogs(router.client)
			})
		case 6:
			withRouter(reader, state, func(router *sshClientWrapper) {
				body, err := currentRouterProxy(router.client)
				if err != nil {
					printRouterError("Не удалось прочитать текущие настройки sing-box", err)
					return
				}
				showInfoWithBack(reader, "Текущие настройки sing-box", body)
			})
		case 7:
			body, err := singBoxOutboundsText(server)
			if err != nil {
				printError(fmt.Sprintf("Ошибка генерации sing-box outbound: %v", err))
				break
			}
			showInfoWithBack(reader, "Новые настройки для sing-box", body)
		case 8:
			withRouter(reader, state, func(router *sshClientWrapper) {
				printRouterStatus(router.client)
			})
		case 9:
			showInfoWithBack(reader, "Детальная информация", serverDetailsText(server))
		case 10:
			withRouter(reader, state, func(router *sshClientWrapper) {
				if err := checkRouterConnection(router.client); err != nil {
					printRouterError("Подключение не прошло", err)
					return
				}
				printSuccess("[OK] Подключение к роутеру работает")
			})
		case 11:
			withRouter(reader, state, func(router *sshClientWrapper) {
				path, err := backupRouterConfig(router.client)
				if err != nil {
					printRouterError("Backup не создан", err)
					return
				}
				printSuccess("Backup создан: " + path)
			})
		case 12:
			restoreBackup(reader, state)
		case 13:
			if err := exportSingBoxOutbound(reader, server); err != nil {
				printError(fmt.Sprintf("Ошибка экспорта: %v", err))
			}
		case 14:
			state.routerCache.clear()
			printSuccess("SSH данные сброшены")
		default:
			printWarning("Неверный пункт меню")
		}
	}
}

func showInfoWithBack(reader *bufio.Reader, title string, body string) {
	for {
		clearTerminal()
		printTitle(title)
		fmt.Println()
		fmt.Println(body)
		fmt.Println()
		fmt.Println("0. Назад")
		fmt.Print("Выберите пункт: ")

		choice, err := readMenuChoice(reader)
		if err != nil {
			printError(fmt.Sprintf("Ошибка чтения пункта: %v", err))
			return
		}
		if choice == emptyMenuChoice {
			continue
		}
		if choice == 0 {
			clearTerminal()
			return
		}
		printWarning("Неверный пункт меню")
	}
}

func printSelectedMenu(title string) {
	if title == "" {
		return
	}
	printTitle("Выбрано: " + title)
	fmt.Println()
}

func shouldShowSelectedServerAction(choice int) bool {
	switch choice {
	case 0, 1, 2, 6, 7, 9:
		return false
	default:
		return true
	}
}

func serverActionTitle(choice int, server Server) string {
	switch choice {
	case 1:
		return "Проверить пинг"
	case 2:
		return "Сменить сервер"
	case 3:
		return "Получить ссылку подключения (" + displayLinkProtocol(server.Protocol) + "://)"
	case 4:
		return "Установить на роутер"
	case 5:
		return "Посмотреть логи роутера (sing-box)"
	case 6:
		return "Показать текущие настройки sing-box"
	case 7:
		return "Показать новые настройки для sing-box"
	case 8:
		return "Проверить статус sing-box на роутере"
	case 9:
		return "Показать детальную информацию"
	case 10:
		return "Проверить подключение к роутеру"
	case 11:
		return "Сделать backup sing-box (config) вручную"
	case 12:
		return "Восстановить sing-box (config) из backup"
	case 13:
		return "Экспортировать sing-box outbound в файл"
	case 14:
		return "Сбросить сохраненные SSH данные"
	default:
		return "Неверный пункт меню"
	}
}

type sshClientWrapper struct {
	client *ssh.Client
}

func withRouter(reader *bufio.Reader, state *appState, action func(*sshClientWrapper)) {
	router, err := connectRouter(reader, &state.routerCache)
	if err != nil {
		printRouterError("Ошибка подключения к роутеру", err)
		return
	}
	defer router.Close()

	action(&sshClientWrapper{client: router})
}

func installServerOnRouter(reader *bufio.Reader, state *appState, server Server) bool {
	router, err := connectRouter(reader, &state.routerCache)
	if err != nil {
		printRouterError("Ошибка подключения к роутеру", err)
		return false
	}
	defer router.Close()

	fmt.Println()
	printWarning("Перед записью будет изменен конфиг роутера.")
	fmt.Println("Сервер: " + serverLabel(server))
	fmt.Println("Роутер: " + state.routerCache.label())
	fmt.Println("Файл: " + routerConfigPath)
	if !confirmYNDefaultYes(reader, "Продолжить? Введите y/n: ") {
		printWarning("Запись отменена")
		return false
	}

	if err := installRouterConfig(router, server); err != nil {
		printRouterError("Ошибка настройки роутера", err)
		return false
	}
	printSuccess("Конфиг сохранен, sing-box перезагружен")
	return handleRouterPostActions(reader, router)
}

func handleRouterPostActions(reader *bufio.Reader, router routerClient) bool {
	for {
		fmt.Println()
		printTitle("Что сделать дальше?")
		fmt.Println("1. Посмотреть логи sing-box")
		fmt.Println("2. Проверить статус sing-box")
		fmt.Println("3. Сменить сервер")
		fmt.Println("0. Выйти")
		fmt.Print("Выберите пункт: ")

		choice, err := readMenuChoice(reader)
		if err != nil {
			printError(fmt.Sprintf("Ошибка чтения пункта: %v", err))
			return true
		}
		if choice == emptyMenuChoice {
			clearTerminal()
			continue
		}

		if choice != 0 {
			clearTerminal()
			printSelectedMenu(routerPostActionTitle(choice))
		}

		switch choice {
		case 0:
			return true
		case 1:
			printSingBoxLogs(router)
		case 2:
			printRouterStatus(router)
		case 3:
			return false
		default:
			printWarning("Неверный пункт меню")
		}
	}
}

func routerPostActionTitle(choice int) string {
	switch choice {
	case 1:
		return "Посмотреть логи sing-box"
	case 2:
		return "Проверить статус sing-box"
	case 3:
		return "Сменить сервер"
	default:
		return "Неверный пункт меню"
	}
}

func restoreBackup(reader *bufio.Reader, state *appState) {
	withRouter(reader, state, func(router *sshClientWrapper) {
		backupPath, err := latestRouterBackupPath(router.client)
		if err != nil {
			printRouterError("Backup не найден", err)
			return
		}

		printWarning("Будет восстановлен backup: " + backupPath)
		if !confirmYN(reader, "Продолжить? Введите y/n: ") {
			printWarning("Восстановление отменено")
			return
		}
		if err := restoreRouterConfig(router.client); err != nil {
			printRouterError("Не удалось восстановить backup", err)
			return
		}
		printSuccess("Backup восстановлен, sing-box перезагружен")
	})
}

func printRouterStatus(router routerClient) {
	status, err := singBoxStatus(router)
	if err != nil {
		printRouterError("Не удалось получить статус sing-box", err)
		return
	}
	if status == "" {
		printSuccess("sing-box работает")
		return
	}
	fmt.Println()
	printSuccess(status)
}

func searchServers(reader *bufio.Reader, state *appState) {
	fmt.Print("Введите текст для поиска или пустую строку для сброса: ")
	queryText, err := reader.ReadString('\n')
	if err != nil {
		printError(fmt.Sprintf("Ошибка чтения поиска: %v", err))
		return
	}

	query := strings.TrimSpace(strings.ToLower(queryText))
	if query == "" {
		state.visibleServers = state.allServers
		printSuccess(fmt.Sprintf("Фильтр сброшен. Серверов: %d", len(state.visibleServers)))
		return
	}

	filtered := make([]Server, 0)
	for _, server := range state.allServers {
		text := strings.ToLower(strings.Join([]string{server.Name, server.Protocol, server.Address, server.Port}, " "))
		if strings.Contains(text, query) {
			filtered = append(filtered, server)
		}
	}

	state.visibleServers = filtered
	printSuccess(fmt.Sprintf("Найдено серверов: %d", len(filtered)))
}

func filterServers(reader *bufio.Reader, state *appState) {
	protocols := uniqueProtocols(state.allServers)
	fmt.Println("Доступные протоколы: " + strings.Join(protocols, ", "))
	fmt.Print("Введите протокол или пустую строку для сброса: ")
	protocolText, err := reader.ReadString('\n')
	if err != nil {
		printError(fmt.Sprintf("Ошибка чтения протокола: %v", err))
		return
	}

	protocol := strings.TrimSpace(strings.ToLower(protocolText))
	if protocol == "" {
		state.visibleServers = state.allServers
		printSuccess(fmt.Sprintf("Фильтр сброшен. Серверов: %d", len(state.visibleServers)))
		return
	}

	filtered := make([]Server, 0)
	for _, server := range state.allServers {
		if strings.ToLower(server.Protocol) == protocol {
			filtered = append(filtered, server)
		}
	}

	state.visibleServers = filtered
	printSuccess(fmt.Sprintf("Серверов с протоколом %s: %d", protocol, len(filtered)))
}

func refreshServers(state *appState) {
	servers, err := loadServers(state.subscriptionURL)
	if err != nil {
		printError(err.Error())
		return
	}

	state.allServers = servers
	state.visibleServers = servers
	printSuccess(fmt.Sprintf("Список серверов обновлен. Серверов: %d", len(servers)))
}

func refreshServerPing(state *appState, server Server) string {
	ping := formatPingResult(pingServer(server, pingTimeout))
	state.pings[serverPingKey(server)] = ping
	return ping
}

func exportSingBoxOutbound(reader *bufio.Reader, server Server) error {
	outbound, err := singBoxOutbound(server)
	if err != nil {
		return err
	}

	body, err := json.MarshalIndent(map[string]any{"outbounds": []any{outbound}}, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')

	fmt.Print("Введите путь файла или нажмите Enter для sing-box-outbound.json: ")
	pathText, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	path := strings.TrimSpace(pathText)
	if path == "" {
		path = "sing-box-outbound.json"
	}

	if err := os.WriteFile(path, body, 0600); err != nil {
		return err
	}
	printSuccess("Файл сохранен: " + path)
	return nil
}

func confirmYN(reader *bufio.Reader, prompt string) bool {
	for {
		fmt.Print(prompt)
		answer, err := reader.ReadString('\n')
		if err != nil {
			printError(fmt.Sprintf("Ошибка чтения подтверждения: %v", err))
			return false
		}

		switch strings.TrimSpace(strings.ToLower(answer)) {
		case "y":
			return true
		case "n":
			return false
		default:
			printWarning("Введите y или n")
		}
	}
}

func confirmYNDefaultYes(reader *bufio.Reader, prompt string) bool {
	for {
		fmt.Print(prompt)
		answer, err := reader.ReadString('\n')
		if err != nil {
			printError(fmt.Sprintf("Ошибка чтения подтверждения: %v", err))
			return false
		}

		switch strings.TrimSpace(strings.ToLower(answer)) {
		case "", "y":
			return true
		case "n":
			return false
		default:
			printWarning("Введите y или n")
		}
	}
}

const emptyMenuChoice = -1

func readMenuChoice(reader *bufio.Reader) (int, error) {
	text, err := reader.ReadString('\n')
	if err != nil {
		return 0, err
	}

	text = strings.TrimSpace(text)
	if text == "" {
		return emptyMenuChoice, nil
	}

	return strconv.Atoi(text)
}

func shortText(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	if limit <= 3 {
		return string(runes[:limit])
	}
	return string(runes[:limit-3]) + "..."
}

func uniqueProtocols(servers []Server) []string {
	seen := make(map[string]bool)
	protocols := make([]string, 0)
	for _, server := range servers {
		protocol := strings.TrimSpace(strings.ToLower(server.Protocol))
		if protocol == "" || seen[protocol] {
			continue
		}
		seen[protocol] = true
		protocols = append(protocols, protocol)
	}
	sort.Strings(protocols)
	return protocols
}

func printRouterError(message string, err error) {
	printError(fmt.Sprintf("%s: %v", message, err))
	printWarning("Проверьте SSH адрес, пароль, доступность роутера и установлен ли sing-box.")
}
