package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	openWrtReleasesURL      = "https://downloads.openwrt.org/releases/"
	openWrtBackupPrefix     = "openwrt-backup"
	proxyDomainsPath        = "/etc/remnawave-proxy-domains.list"
	proxyDomainsDnsmasqPath = "/etc/dnsmasq.d/remnawave-proxy-domains.conf"
)

type openWrtRouterInfo struct {
	Detected    bool
	Hostname    string
	Model       string
	BoardName   string
	Release     string
	Target      string
	Arch        string
	Archs       []string
	PackageList string
}

type routerResources struct {
	OverlayFreeKB  int64
	TmpFreeKB      int64
	MemAvailableKB int64
}

type openWrtReleaseProfile struct {
	ID     string
	Title  string
	Target string
}

type openWrtImage struct {
	Name string
	Type string
	URL  string
	Size int64
	SHA  string
}

type openWrtPackageVersion struct {
	Package  string
	Version  string
	Filename string
	Size     int64
	URL      string
}

type dnsPackageOption struct {
	Name        string
	Title       string
	Description string
	MinSpaceKB  int64
	MinMemoryKB int64
}

type installedPackage struct {
	Name    string
	Version string
}

type proxyDomainFile struct {
	Path      string
	Kind      string
	Editable  bool
	Deletable bool
}

func handleOpenWrtMenu(reader *bufio.Reader, state *appState) {
	for {
		clearTerminal()
		printTitle("Роутер OpenWrt")
		printSelectedMenu("Роутер OpenWrt")
		fmt.Println("1. Создать backup роутера и скачать")
		fmt.Println("2. Восстановить backup роутера")
		fmt.Println("3. OpenWrt")
		fmt.Println("4. sing-box")
		fmt.Println("5. DNS")
		fmt.Println("6. Домены для прокси")
		fmt.Println("0. Назад")
		fmt.Print("Выберите пункт: ")

		choice, err := readMenuChoice(reader)
		if err != nil {
			printError(fmt.Sprintf("Ошибка чтения пункта: %v", err))
			return
		}
		if choice == emptyMenuChoice {
			clearTerminal()
			continue
		}

		clearTerminal()
		switch choice {
		case 0:
			return
		case 1:
			openWrtBackupAction(reader, state)
		case 2:
			openWrtRestoreAction(reader, state)
		case 3:
			openWrtInstallUpdateAction(reader, state)
		case 4:
			openWrtSingBoxMenu(reader, state)
		case 5:
			openWrtDNSMenu(reader, state)
		case 6:
			openWrtDomainsMenu(reader, state)
		default:
			printWarning("Неверный пункт меню")
		}
	}
}

func openWrtBackupAction(reader *bufio.Reader, state *appState) {
	withRouter(reader, state, func(router *sshClientWrapper) {
		path, err := createAndDownloadOpenWrtBackup(router.client)
		if err != nil {
			printRouterError("Backup роутера не создан", err)
			waitEnter(reader)
			return
		}
		printSuccess("Backup скачан: " + path)
		metadataPath := path + ".metadata.json"
		if _, err := os.Stat(metadataPath); err == nil {
			printSuccess("Metadata сохранен: " + metadataPath)
		}
		showOpenWrtBackupResultMenu(reader, path)
	})
}

func openWrtRestoreAction(reader *bufio.Reader, state *appState) {
	withRouter(reader, state, func(router *sshClientWrapper) {
		path, ok := chooseLocalOpenWrtBackup(reader)
		if !ok {
			return
		}
		if !confirmYN(reader, "Будет восстановлен backup OpenWrt: "+path+". Продолжить? Введите y/n: ") {
			printWarning("Восстановление отменено")
			return
		}
		if err := restoreOpenWrtBackup(router.client, path); err != nil {
			printRouterError("Backup OpenWrt не восстановлен", err)
			return
		}
		printSuccess("Backup OpenWrt восстановлен")
	})
}

func openWrtInstallUpdateAction(reader *bufio.Reader, state *appState) {
	withRouter(reader, state, func(router *sshClientWrapper) {
		info, err := detectOpenWrtRouter(router.client)
		if err != nil {
			printWarning("OpenWrt не определен: " + err.Error())
		}

		releases, err := fetchOpenWrtReleases()
		if err != nil {
			printRouterError("Не удалось получить релизы OpenWrt", err)
			return
		}
		if info.Detected {
			printInfo("Ищу версии, совместимые с " + valueOrDash(info.Model) + " (" + valueOrDash(info.BoardName) + ")...")
			releases = compatibleOpenWrtReleases(releases, info, "sysupgrade")
			if len(releases) == 0 {
				printWarning("Совместимые версии OpenWrt для этого роутера не найдены")
				return
			}
		}
		release, ok := chooseRelease(reader, releases, info.Release)
		if !ok {
			return
		}

		if !info.Detected {
			downloadFactoryImageAction(reader, release)
			return
		}

		image, err := findCompatibleOpenWrtImage(release, info, "sysupgrade")
		if err != nil {
			printRouterError("Совместимый sysupgrade образ не найден", err)
			return
		}
		resources, _ := readRouterResources(router.client)
		printOpenWrtInstallSummary(info, resources, image)
		if !confirmYN(reader, "Запустить sysupgrade? Роутер перезагрузится. Введите y/n: ") {
			printWarning("Установка отменена")
			return
		}
		if err := installOpenWrtSysupgrade(router.client, image); err != nil {
			printRouterError("OpenWrt не установлен", err)
			return
		}
		printSuccess("Команда sysupgrade запущена")
	})
}

func openWrtSingBoxMenu(reader *bufio.Reader, state *appState) {
	version := ""
	router, err := connectRouter(reader, &state.routerCache)
	if err != nil {
		printRouterError("Ошибка подключения к роутеру", err)
		return
	}
	version = installedPackageVersion(router, "sing-box")
	_ = router.Close()

	for {
		clearTerminal()
		if version == "" {
			printTitle("sing-box " + colorYellow + "(не установлен)" + colorReset)
			fmt.Println("1. Установить")
		} else {
			printTitle("sing-box " + colorGreen + version + colorReset)
			fmt.Println("1. Обновить")
			fmt.Println("2. Выбрать версию")
			fmt.Println("3. Удалить")
		}
		fmt.Println("0. Назад")
		fmt.Print("Выберите пункт: ")

		choice, err := readMenuChoice(reader)
		if err != nil {
			printError(fmt.Sprintf("Ошибка чтения пункта: %v", err))
			return
		}
		if choice == emptyMenuChoice {
			clearTerminal()
			continue
		}
		clearTerminal()
		if choice == 0 {
			return
		}

		withRouter(reader, state, func(router *sshClientWrapper) {
			info, _ := detectOpenWrtRouter(router.client)
			resources, _ := readRouterResources(router.client)
			printPackageResourceAdvice(resources, 24000, 64000, "sing-box занимает около 20-25 MB после установки.")
			switch choice {
			case 1:
				if version == "" {
					if !confirmYNDefaultYes(reader, "Установить sing-box через opkg? Введите y/n: ") {
						break
					}
					runPackageInstall(router.client, []string{"sing-box"})
					configureSingBoxService(router.client)
					version = installedPackageVersion(router.client, "sing-box")
					break
				}
				if chooseAndInstallSingBoxPackageVersion(reader, router.client, info) {
					configureSingBoxService(router.client)
					version = installedPackageVersion(router.client, "sing-box")
				}
			case 2:
				if version == "" {
					printWarning("sing-box не установлен. Сначала установите пакет.")
					waitEnter(reader)
					break
				}
				if chooseAndInstallSingBoxPackageVersion(reader, router.client, info) {
					configureSingBoxService(router.client)
					version = installedPackageVersion(router.client, "sing-box")
				}
			case 3:
				if version == "" {
					printWarning("sing-box не установлен")
					waitEnter(reader)
					break
				}
				if confirmYN(reader, "Удалить sing-box? Введите y/n: ") {
					backupPath, err := backupSingBoxBeforePackageChange(router.client)
					if err != nil {
						printWarning("Backup sing-box не создан: " + err.Error())
					} else if backupPath != "" {
						printSuccess("Backup sing-box создан: " + backupPath)
					}
					runPackageRemove(router.client, []string{"sing-box"})
					version = ""
				}
			default:
				printWarning("Неверный пункт меню")
			}
		})
	}
}

func openWrtDNSMenu(reader *bufio.Reader, state *appState) {
	options := []dnsPackageOption{
		{Name: "dnsmasq-full", Title: "dnsmasq-full + nftset", Description: "Рекомендуется для точечной маршрутизации доменов через vpn_domains и tun0.", MinSpaceKB: 1200, MinMemoryKB: 16000},
		{Name: "dnscrypt-proxy2", Title: "dnscrypt-proxy2 / DoH-DNSCrypt", Description: "Шифрованный DNS через DNSCrypt/DoH. Вариант из скрипта ITDog.", MinSpaceKB: 2400, MinMemoryKB: 32000},
		{Name: "stubby", Title: "stubby / DoT", Description: "DNS over TLS. Легкий клиент DoT, но требует настройки upstream DNS.", MinSpaceKB: 1200, MinMemoryKB: 24000},
	}

	router, err := connectRouter(reader, &state.routerCache)
	if err != nil {
		printRouterError("Ошибка подключения к роутеру", err)
		return
	}
	defer router.Close()

	for {
		clearTerminal()
		info, _ := detectOpenWrtRouter(router)
		resources, _ := readRouterResources(router)
		installed := installedDNSPackages(router, options)
		current, hasCurrent := primaryInstalledDNSOption(options, installed)

		printTitle("DNS")
		if hasCurrent {
			fmt.Println("Установлено: " + colorGreen + current.Title + " " + installed[current.Name].Version + colorReset)
		} else {
			fmt.Println("Установлено: " + colorYellow + "не найдено" + colorReset)
		}
		if hasCurrent {
			fmt.Println("1. Заменить на другой вариант")
			fmt.Println("2. Обновить")
			fmt.Println("3. Выбрать версию пакета")
			fmt.Println("4. Удалить")
		} else {
			fmt.Println("1. Установить / выбрать вариант")
			fmt.Println("2. Выбрать версию пакета")
		}
		fmt.Println("0. Назад")
		fmt.Print("Выберите пункт: ")

		choice, err := readMenuChoice(reader)
		if err != nil {
			printError(fmt.Sprintf("Ошибка чтения пункта: %v", err))
			return
		}
		if choice == emptyMenuChoice {
			clearTerminal()
			continue
		}
		clearTerminal()
		if choice == 0 {
			return
		}

		switch choice {
		case 1:
			option, ok := chooseDNSOption(reader, options, resources, installed)
			if !ok {
				continue
			}
			prompt := "Установить выбранный DNS пакет? Введите y/n: "
			if hasCurrent {
				prompt = "Заменить текущий DNS вариант на " + option.Title + "? Введите y/n: "
			}
			if confirmYNDefaultYes(reader, prompt) {
				if hasCurrent && current.Name != option.Name {
					removeDNSPackage(router, current.Name)
				}
				installDNSPackage(router, option.Name)
			}
			waitEnter(reader)
		case 2:
			if hasCurrent {
				if confirmYNDefaultYes(reader, "Обновить "+current.Title+"? Введите y/n: ") {
					runPackageUpgrade(router, current.Name)
					configureDNSPackage(router, current.Name)
				}
				waitEnter(reader)
				continue
			}
			option, ok := chooseDNSOption(reader, options, resources, installed)
			if !ok {
				continue
			}
			chooseAndInstallPackageVersion(reader, router, info, option.Name)
			configureDNSPackage(router, option.Name)
			waitEnter(reader)
		case 3:
			if !hasCurrent {
				printWarning("Неверный пункт меню")
				waitEnter(reader)
				continue
			}
			chooseAndInstallPackageVersion(reader, router, info, current.Name)
			configureDNSPackage(router, current.Name)
			waitEnter(reader)
		case 4:
			if !hasCurrent {
				printWarning("Неверный пункт меню")
				waitEnter(reader)
				continue
			}
			if confirmYN(reader, "Удалить "+current.Title+"? Введите y/n: ") {
				removeDNSPackage(router, current.Name)
			}
			waitEnter(reader)
		default:
			printWarning("Неверный пункт меню")
			waitEnter(reader)
		}
	}
}

func openWrtDomainsMenu(reader *bufio.Reader, state *appState) {
	router, err := connectRouter(reader, &state.routerCache)
	if err != nil {
		printRouterError("Ошибка подключения к роутеру", err)
		return
	}
	defer router.Close()

	for {
		clearTerminal()
		printTitle("Домены для прокси")
		files, err := findProxyDomainFiles(router)
		if err != nil {
			printWarning("Файлы доменов не найдены: " + err.Error())
		}
		file, ok := chooseProxyDomainFile(reader, files)
		if !ok {
			return
		}
		if !file.Editable {
			printWarning("Этот файл нельзя редактировать из программы")
			waitEnter(reader)
			continue
		}
		handleProxyDomainFileMenu(reader, router, file)
	}
}

func handleProxyDomainFileMenu(reader *bufio.Reader, router routerClient, file proxyDomainFile) {
	for {
		clearTerminal()
		printTitle("Файл доменов: " + file.Path)
		domains, err := readProxyDomainsFromFile(router, file)
		if err != nil {
			printRouterError("Не удалось прочитать файл", err)
			waitEnter(reader)
			return
		}
		fmt.Println(proxyDomainsText(domains))
		fmt.Println()
		fmt.Println("1. Редактировать домены")
		fmt.Println("2. Показать файл")
		fmt.Println("3. Открыть файл в редакторе")
		fmt.Println("4. Применить изменения")
		fmt.Println("5. Удалить файл")
		fmt.Println("0. Выбрать другой файл")
		fmt.Print("Выберите пункт: ")

		choice, err := readMenuChoice(reader)
		if err != nil {
			printError(fmt.Sprintf("Ошибка чтения пункта: %v", err))
			return
		}
		switch choice {
		case 0:
			return
		case 1:
			handleProxyDomainEditor(reader, router, file, domains)
		case 2:
			body, err := readRemoteFile(router, file.Path)
			if err != nil {
				printRouterError("Файл не прочитан", err)
				waitEnter(reader)
				break
			}
			showInfoWithBack(reader, file.Path, body)
		case 3:
			if err := editProxyDomainFileManually(reader, router, file); err != nil {
				printRouterError("Файл не сохранен", err)
				waitEnter(reader)
				break
			}
			printSuccess("Файл сохранен")
			waitEnter(reader)
		case 4:
			if err := applyProxyDomains(router, domains); err != nil {
				printRouterError("Домены не применены", err)
				waitEnter(reader)
				break
			}
			printSuccess("Домены применены")
			waitEnter(reader)
		case 5:
			if !file.Deletable {
				printWarning("Этот файл удалять нельзя")
				waitEnter(reader)
				break
			}
			if !confirmYN(reader, "Удалить "+file.Path+"? Введите y/n: ") {
				printWarning("Удаление отменено")
				waitEnter(reader)
				break
			}
			if _, err := runRemote(router, "rm -f "+shellQuote(file.Path)); err != nil {
				printRouterError("Файл не удален", err)
				waitEnter(reader)
				break
			}
			printSuccess("Файл удален")
			waitEnter(reader)
			return
		default:
			printWarning("Неверный пункт меню")
			waitEnter(reader)
		}
	}
}

func handleProxyDomainEditor(reader *bufio.Reader, router routerClient, file proxyDomainFile, domains []string) {
	for {
		clearTerminal()
		printTitle("Редактирование: " + file.Path)
		if len(domains) == 0 {
			printWarning("Список доменов пуст")
		}
		for i, domain := range domains {
			fmt.Printf("%d. %s\n", i+1, domain)
		}
		fmt.Printf("%d. Добавить домен\n", len(domains)+1)
		fmt.Println("0. Назад")
		fmt.Print("Выберите домен: ")

		choice, err := readMenuChoice(reader)
		if err != nil {
			printError(fmt.Sprintf("Ошибка чтения пункта: %v", err))
			return
		}
		if choice == 0 {
			return
		}
		if choice == len(domains)+1 {
			domain := readDomainInput(reader, "Введите домен: ")
			if domain == "" {
				printWarning("Домен не указан")
				waitEnter(reader)
				continue
			}
			domains = addProxyDomain(domains, domain)
			if err := writeProxyDomainsToFile(router, file, domains); err != nil {
				printRouterError("Домен не сохранен", err)
				waitEnter(reader)
				continue
			}
			printSuccess("Домен добавлен")
			waitEnter(reader)
			continue
		}
		if choice < 1 || choice > len(domains) {
			printWarning("Неверный пункт меню")
			waitEnter(reader)
			continue
		}
		domains = handleSingleProxyDomain(reader, router, file, domains, choice-1)
	}
}

func handleSingleProxyDomain(reader *bufio.Reader, router routerClient, file proxyDomainFile, domains []string, index int) []string {
	for {
		clearTerminal()
		printTitle("Домен: " + domains[index])
		fmt.Println("1. Отредактировать")
		fmt.Println("2. Удалить")
		fmt.Println("0. Назад")
		fmt.Print("Выберите пункт: ")

		choice, err := readMenuChoice(reader)
		if err != nil {
			printError(fmt.Sprintf("Ошибка чтения пункта: %v", err))
			return domains
		}
		switch choice {
		case 0:
			return domains
		case 1:
			domain := readDomainInput(reader, "Введите новый домен: ")
			if domain == "" {
				printWarning("Домен не указан")
				waitEnter(reader)
				continue
			}
			domains[index] = domain
			domains = parseProxyDomains(strings.Join(domains, "\n"))
			if err := writeProxyDomainsToFile(router, file, domains); err != nil {
				printRouterError("Домен не сохранен", err)
				waitEnter(reader)
				return domains
			}
			printSuccess("Домен обновлен")
			waitEnter(reader)
			return domains
		case 2:
			removed := domains[index]
			domains = append(domains[:index], domains[index+1:]...)
			if err := writeProxyDomainsToFile(router, file, domains); err != nil {
				printRouterError("Домен не удален", err)
				waitEnter(reader)
				return domains
			}
			printSuccess("Домен удален: " + removed)
			waitEnter(reader)
			return domains
		default:
			printWarning("Неверный пункт меню")
			waitEnter(reader)
		}
	}
}

func editProxyDomainFileManually(reader *bufio.Reader, router routerClient, file proxyDomainFile) error {
	if !file.Editable {
		return errors.New("этот файл нельзя редактировать из программы")
	}
	clearTerminal()
	printTitle("Открываю редактор: " + file.Path)
	command := "sh -c " + shellQuote("if command -v nano >/dev/null 2>&1; then nano "+shellQuote(file.Path)+"; else vi "+shellQuote(file.Path)+"; fi")
	return runRemoteInteractive(router, command)
}

func createAndDownloadOpenWrtBackup(router routerClient) (string, error) {
	now := time.Now()
	name := openWrtBackupPrefix + "-" + now.Format("20060102-150405") + ".tar.gz"
	remotePath := "/tmp/" + name
	if _, err := runRemote(router, "sysupgrade -b "+shellQuote(remotePath)); err != nil {
		return "", err
	}
	if output, err := runRemote(router, "test -s "+shellQuote(remotePath)+" && ls -lh "+shellQuote(remotePath)); err != nil {
		return "", fmt.Errorf("backup на роутере не найден или пустой: %w: %s", err, strings.TrimSpace(output))
	}

	body, err := runRemoteOutput(router, "cat "+shellQuote(remotePath))
	if err != nil {
		return "", err
	}

	localPath, err := saveLocalBackupFile(name, body)
	if err != nil {
		return "", err
	}

	metadata, err := openWrtBackupMetadata(router)
	if err == nil {
		_ = os.WriteFile(localPath+".metadata.json", []byte(metadata), 0600)
	}
	return localPath, nil
}

func saveLocalBackupFile(name string, body []byte) (string, error) {
	dir, err := backupOutputDir()
	if err != nil {
		return "", err
	}
	localPath := filepath.Join(dir, name)
	if err := os.WriteFile(localPath, body, 0600); err != nil {
		cwd, cwdErr := os.Getwd()
		if cwdErr != nil {
			return "", err
		}
		localPath = filepath.Join(cwd, name)
		if writeErr := os.WriteFile(localPath, body, 0600); writeErr != nil {
			return "", fmt.Errorf("не удалось сохранить backup рядом с программой (%v) и в текущую папку (%w)", err, writeErr)
		}
	}
	return localPath, nil
}

func backupOutputDir() (string, error) {
	cwd, err := os.Getwd()
	if err == nil && cwd != "" {
		return cwd, nil
	}
	return executableDir()
}

func restoreOpenWrtBackup(router routerClient, localPath string) error {
	if !strings.HasSuffix(localPath, ".tar.gz") {
		return errors.New("backup должен быть .tar.gz")
	}
	body, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return errors.New("backup файл пустой")
	}
	remotePath := "/tmp/" + filepath.Base(localPath)
	if err := writeRemote(router, remotePath, body); err != nil {
		return err
	}
	if output, err := runRemote(router, "gzip -t "+shellQuote(remotePath)); err != nil {
		return fmt.Errorf("backup не похож на gzip tar: %w: %s", err, strings.TrimSpace(output))
	}
	if output, err := runRemote(router, "sysupgrade -r "+shellQuote(remotePath)); err != nil {
		return fmt.Errorf("sysupgrade -r failed: %w: %s", err, strings.TrimSpace(output))
	}
	return nil
}

func executableDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return os.Getwd()
	}
	if strings.Contains(exe, string(filepath.Separator)+"go-build") {
		return os.Getwd()
	}
	return filepath.Dir(exe), nil
}

func chooseLocalOpenWrtBackup(reader *bufio.Reader) (string, bool) {
	backups := findLocalOpenWrtBackups()
	if len(backups) > 0 {
		printTitle("Найденные backup OpenWrt")
		for i, path := range backups {
			fmt.Printf("%d. %s\n", i+1, path)
		}
		fmt.Println("/. Ввести путь вручную")
		fmt.Println("0. Назад")
		fmt.Print("Выберите backup: ")
		choice, err := readActionChoice(reader)
		if err != nil {
			printError(fmt.Sprintf("Ошибка чтения пункта: %v", err))
			return "", false
		}
		if choice == "0" {
			return "", false
		}
		if choice != "/" {
			number, err := strconv.Atoi(choice)
			if err == nil && number > 0 && number <= len(backups) {
				return backups[number-1], true
			}
			printWarning("Неверный пункт меню")
			return "", false
		}
	}

	fmt.Print("Введите путь к backup .tar.gz или 0 для отмены: ")
	pathText, err := reader.ReadString('\n')
	if err != nil {
		printError(fmt.Sprintf("Ошибка чтения пути: %v", err))
		return "", false
	}
	path := strings.TrimSpace(pathText)
	if path == "" || path == "0" {
		return "", false
	}
	return path, true
}

func showOpenWrtBackupResultMenu(reader *bufio.Reader, createdPath string) {
	for {
		fmt.Println()
		printTitle("Backup OpenWrt")
		backups := findLocalOpenWrtBackups()
		if len(backups) == 0 && createdPath != "" {
			backups = []string{createdPath}
		}
		for i, path := range backups {
			label := path
			if path == createdPath {
				label = colorGreen + path + colorReset
			}
			fmt.Printf("%d. %s\n", i+1, label)
		}
		fmt.Println("/. Ввести путь вручную")
		fmt.Println("0. Назад")
		fmt.Print("Выберите пункт: ")

		choice, err := readActionChoice(reader)
		if err != nil {
			printError(fmt.Sprintf("Ошибка чтения пункта: %v", err))
			return
		}
		switch choice {
		case "0":
			clearTerminal()
			return
		case "/":
			fmt.Print("Введите путь к backup: ")
			pathText, err := reader.ReadString('\n')
			if err != nil {
				printError(fmt.Sprintf("Ошибка чтения пути: %v", err))
				continue
			}
			path := strings.TrimSpace(pathText)
			if path == "" {
				printWarning("Путь не указан")
				continue
			}
			printInfo(path)
		default:
			number, err := strconv.Atoi(choice)
			if err != nil || number < 1 || number > len(backups) {
				printWarning("Неверный пункт меню")
				continue
			}
			printInfo(backups[number-1])
		}
	}
}

func findLocalOpenWrtBackups() []string {
	dirs := make([]string, 0, 2)
	if dir, err := executableDir(); err == nil {
		dirs = append(dirs, dir)
	}
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, cwd)
	}
	seen := make(map[string]bool)
	var backups []string
	for _, dir := range dirs {
		matches, _ := filepath.Glob(filepath.Join(dir, openWrtBackupPrefix+"-*.tar.gz"))
		for _, path := range matches {
			if seen[path] {
				continue
			}
			seen[path] = true
			backups = append(backups, path)
		}
	}
	sort.Slice(backups, func(i, j int) bool {
		left, leftErr := os.Stat(backups[i])
		right, rightErr := os.Stat(backups[j])
		if leftErr != nil || rightErr != nil {
			return backups[i] > backups[j]
		}
		return left.ModTime().After(right.ModTime())
	})
	return backups
}

func openWrtBackupMetadata(router routerClient) (string, error) {
	info, _ := detectOpenWrtRouter(router)
	packages, _ := runRemote(router, "opkg list-installed 2>/dev/null || true")
	info.PackageList = strings.TrimSpace(packages)
	body, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return "", err
	}
	return string(body) + "\n", nil
}

func detectOpenWrtRouter(router routerClient) (openWrtRouterInfo, error) {
	var info openWrtRouterInfo
	boardBody, boardErr := runRemote(router, "ubus call system board 2>/dev/null")
	if boardErr == nil {
		info = parseOpenWrtBoardInfo(boardBody)
		info.Detected = true
	}

	releaseBody, releaseErr := runRemote(router, "cat /etc/openwrt_release 2>/dev/null")
	if releaseErr == nil {
		mergeOpenWrtReleaseVars(&info, releaseBody)
		info.Detected = true
	}

	archBody, _ := runRemote(router, "opkg print-architecture 2>/dev/null || true")
	info.Archs = parseOpenWrtArchitectures(archBody)
	if len(info.Archs) > 0 {
		info.Arch = info.Archs[len(info.Archs)-1]
	}
	if !info.Detected {
		return info, errors.New("ubus и /etc/openwrt_release недоступны")
	}
	return info, nil
}

func parseOpenWrtBoardInfo(body string) openWrtRouterInfo {
	var raw struct {
		Hostname  string `json:"hostname"`
		Model     string `json:"model"`
		BoardName string `json:"board_name"`
		Release   struct {
			Version      string `json:"version"`
			Target       string `json:"target"`
			Distribution string `json:"distribution"`
		} `json:"release"`
	}
	_ = json.Unmarshal([]byte(body), &raw)
	return openWrtRouterInfo{
		Detected:  strings.EqualFold(raw.Release.Distribution, "OpenWrt") || raw.Release.Version != "",
		Hostname:  raw.Hostname,
		Model:     raw.Model,
		BoardName: raw.BoardName,
		Release:   raw.Release.Version,
		Target:    raw.Release.Target,
	}
}

func mergeOpenWrtReleaseVars(info *openWrtRouterInfo, body string) {
	values := parseShellVars(body)
	if info.Release == "" {
		info.Release = values["DISTRIB_RELEASE"]
	}
	if info.Target == "" {
		info.Target = values["DISTRIB_TARGET"]
	}
}

func parseShellVars(body string) map[string]string {
	values := make(map[string]string)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		values[parts[0]] = strings.Trim(strings.TrimSpace(parts[1]), `'"`)
	}
	return values
}

func parseOpenWrtArchitectures(body string) []string {
	type archPriority struct {
		arch     string
		priority int
	}
	var parsed []archPriority
	for _, line := range strings.Split(body, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "arch" {
			continue
		}
		priority, _ := strconv.Atoi(fields[2])
		if fields[1] != "all" && fields[1] != "noarch" {
			parsed = append(parsed, archPriority{arch: fields[1], priority: priority})
		}
	}
	sort.Slice(parsed, func(i, j int) bool { return parsed[i].priority < parsed[j].priority })
	archs := make([]string, 0, len(parsed))
	for _, item := range parsed {
		archs = append(archs, item.arch)
	}
	return archs
}

func readRouterResources(router routerClient) (routerResources, error) {
	dfBody, err := runRemote(router, "df -k /overlay /tmp 2>/dev/null || true")
	if err != nil {
		return routerResources{}, err
	}
	freeBody, _ := runRemote(router, "awk '/MemAvailable/{print $2}' /proc/meminfo 2>/dev/null || true")
	resources := parseRouterDF(dfBody)
	resources.MemAvailableKB = parseFirstInt64(freeBody)
	return resources, nil
}

func parseRouterDF(body string) routerResources {
	var resources routerResources
	for _, line := range strings.Split(body, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[0] == "Filesystem" {
			continue
		}
		available := parseFirstInt64(fields[3])
		mount := fields[len(fields)-1]
		switch mount {
		case "/overlay", "/":
			if resources.OverlayFreeKB == 0 {
				resources.OverlayFreeKB = available
			}
		case "/tmp":
			resources.TmpFreeKB = available
		}
	}
	return resources
}

func parseFirstInt64(value string) int64 {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0
	}
	parsed, _ := strconv.ParseInt(fields[0], 10, 64)
	return parsed
}

func fetchOpenWrtReleases() ([]string, error) {
	body, err := fetch(openWrtReleasesURL, "terminal-openwrt", "text/html")
	if err != nil {
		return nil, err
	}
	return parseOpenWrtReleasesHTML(string(body)), nil
}

func parseOpenWrtReleasesHTML(body string) []string {
	re := regexp.MustCompile(`href="([0-9]+\.[0-9]+(?:\.[0-9]+)?)/"`)
	matches := re.FindAllStringSubmatch(body, -1)
	seen := make(map[string]bool)
	releases := make([]string, 0)
	for _, match := range matches {
		version := match[1]
		if seen[version] || strings.Contains(version, "-rc") {
			continue
		}
		seen[version] = true
		releases = append(releases, version)
	}
	sort.Slice(releases, func(i, j int) bool { return compareVersions(releases[i], releases[j]) > 0 })
	return releases
}

func compareVersions(left string, right string) int {
	leftParts := versionParts(left)
	rightParts := versionParts(right)
	for i := 0; i < len(leftParts) || i < len(rightParts); i++ {
		var l, r int
		if i < len(leftParts) {
			l = leftParts[i]
		}
		if i < len(rightParts) {
			r = rightParts[i]
		}
		if l > r {
			return 1
		}
		if l < r {
			return -1
		}
	}
	return 0
}

func versionParts(version string) []int {
	parts := strings.Split(version, ".")
	result := make([]int, 0, len(parts))
	for _, part := range parts {
		value, _ := strconv.Atoi(part)
		result = append(result, value)
	}
	return result
}

func chooseRelease(reader *bufio.Reader, releases []string, currentVersion string) (string, bool) {
	if len(releases) == 0 {
		printWarning("Список релизов пуст")
		return "", false
	}
	limit := len(releases)
	if limit > 12 {
		limit = 12
	}
	printTitle("Релизы OpenWrt")
	if currentVersion != "" {
		fmt.Println("Текущая версия: " + colorGreen + currentVersion + colorReset)
	}
	for i := 0; i < limit; i++ {
		version := releases[i]
		label := ""
		if i == 0 {
			label += colorYellow + " (рекомендуется)" + colorReset
		}
		if version == currentVersion {
			version = colorGreen + version + colorReset
			label += colorGreen + " (текущая)" + colorReset
		}
		fmt.Printf("%d. %s%s\n", i+1, version, label)
	}
	fmt.Println("0. Назад")
	fmt.Print("Выберите версию: ")
	choice, err := readMenuChoice(reader)
	if err != nil || choice <= 0 || choice > limit {
		if choice != 0 {
			printWarning("Неверный пункт меню")
		}
		return "", false
	}
	return releases[choice-1], true
}

func compatibleOpenWrtReleases(releases []string, info openWrtRouterInfo, imageType string) []string {
	compatible := make([]string, 0, len(releases))
	for _, release := range releases {
		if openWrtReleaseSupportsRouter(release, info, imageType) {
			compatible = append(compatible, release)
		}
	}
	return compatible
}

func openWrtReleaseSupportsRouter(release string, info openWrtRouterInfo, imageType string) bool {
	if info.Target == "" || info.BoardName == "" {
		return false
	}
	profiles, err := fetchOpenWrtProfiles(release, info.Target)
	if err != nil {
		return false
	}
	profile, ok := profiles[info.BoardName]
	if !ok {
		return false
	}
	for _, image := range profile.Images {
		if image.Type == imageType || strings.Contains(image.Name, "-"+imageType+".") {
			return true
		}
	}
	return false
}

func findCompatibleOpenWrtImage(release string, info openWrtRouterInfo, imageType string) (openWrtImage, error) {
	if info.Target == "" || info.BoardName == "" {
		return openWrtImage{}, errors.New("не определены target или board_name роутера")
	}
	profiles, err := fetchOpenWrtProfiles(release, info.Target)
	if err != nil {
		return openWrtImage{}, err
	}
	profile, ok := profiles[info.BoardName]
	if !ok {
		return openWrtImage{}, fmt.Errorf("profile %s не найден", info.BoardName)
	}
	for _, image := range profile.Images {
		if image.Type == imageType || strings.Contains(image.Name, "-"+imageType+".") {
			base := openWrtReleasesURL + release + "/targets/" + info.Target + "/"
			sha, _ := fetchOpenWrtSHA(base, image.Name)
			return openWrtImage{Name: image.Name, Type: image.Type, URL: base + url.PathEscape(image.Name), Size: image.Filesize, SHA: sha}, nil
		}
	}
	return openWrtImage{}, fmt.Errorf("образ %s для %s не найден", imageType, info.BoardName)
}

func fetchOpenWrtProfiles(release string, target string) (map[string]struct {
	Images []struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Filesize int64  `json:"filesize"`
	} `json:"images"`
}, error) {
	body, err := fetch(openWrtReleasesURL+release+"/targets/"+target+"/profiles.json", "terminal-openwrt", "application/json")
	if err != nil {
		return nil, err
	}
	var data struct {
		Profiles map[string]struct {
			Images []struct {
				Name     string `json:"name"`
				Type     string `json:"type"`
				Filesize int64  `json:"filesize"`
			} `json:"images"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return data.Profiles, nil
}

func fetchOpenWrtSHA(baseURL string, filename string) (string, error) {
	body, err := fetch(baseURL+"sha256sums", "terminal-openwrt", "text/plain")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == filename {
			return fields[0], nil
		}
	}
	return "", errors.New("sha256 не найден")
}

func printOpenWrtInstallSummary(info openWrtRouterInfo, resources routerResources, image openWrtImage) {
	printTitle("OpenWrt sysupgrade")
	fmt.Println("Модель: " + valueOrDash(info.Model))
	fmt.Println("Board: " + valueOrDash(info.BoardName))
	fmt.Println("Текущая версия: " + valueOrDash(info.Release))
	fmt.Println("Target: " + valueOrDash(info.Target))
	fmt.Println("Образ: " + image.Name)
	fmt.Println("URL: " + image.URL)
	if image.SHA != "" {
		fmt.Println("SHA256: " + image.SHA)
	}
	fmt.Printf("Свободно /tmp: %d KB\n", resources.TmpFreeKB)
}

func installOpenWrtSysupgrade(router routerClient, image openWrtImage) error {
	remotePath := "/tmp/" + image.Name
	if _, err := runRemote(router, downloadCommand(image.URL, remotePath)); err != nil {
		return err
	}
	if image.SHA != "" {
		command := "cd /tmp && echo " + shellQuote(image.SHA+"  "+image.Name) + " | sha256sum -c -"
		if output, err := runRemote(router, command); err != nil {
			return fmt.Errorf("sha256 check failed: %w: %s", err, strings.TrimSpace(output))
		}
	}
	if output, err := runRemote(router, "sysupgrade -T "+shellQuote(remotePath)); err != nil {
		return fmt.Errorf("sysupgrade test failed: %w: %s", err, strings.TrimSpace(output))
	}
	_, err := runRemote(router, "sysupgrade "+shellQuote(remotePath))
	return err
}

func downloadFactoryImageAction(reader *bufio.Reader, release string) {
	fmt.Print("Введите модель/board роутера для поиска factory image: ")
	queryText, err := reader.ReadString('\n')
	if err != nil {
		printError(fmt.Sprintf("Ошибка чтения модели: %v", err))
		return
	}
	query := strings.TrimSpace(queryText)
	if query == "" {
		printWarning("Модель не указана")
		return
	}
	profiles, err := searchOpenWrtProfiles(release, query)
	if err != nil {
		printError("Поиск образов не выполнен: " + err.Error())
		return
	}
	profile, ok := chooseProfile(reader, profiles)
	if !ok {
		return
	}
	info := openWrtRouterInfo{Target: profile.Target, BoardName: profile.ID}
	image, err := findCompatibleOpenWrtImage(release, info, "factory")
	if err != nil {
		printError("Factory image не найден: " + err.Error())
		return
	}
	printWarning("Для стоковой прошивки автоматическая установка не выполняется. Образ будет только скачан.")
	if !confirmYNDefaultYes(reader, "Скачать factory image рядом с программой? Введите y/n: ") {
		return
	}
	path, err := downloadLocalFile(image.URL, image.Name)
	if err != nil {
		printError("Не удалось скачать образ: " + err.Error())
		return
	}
	printSuccess("Factory image скачан: " + path)
}

func searchOpenWrtProfiles(release string, query string) ([]openWrtReleaseProfile, error) {
	body, err := fetch(openWrtReleasesURL+release+"/.overview.json", "terminal-openwrt", "application/json")
	if err != nil {
		return nil, err
	}
	var overview struct {
		Profiles []struct {
			ID     string   `json:"id"`
			Titles []string `json:"titles"`
			Target string   `json:"target"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(body, &overview); err != nil {
		return nil, err
	}
	query = strings.ToLower(query)
	var result []openWrtReleaseProfile
	for _, profile := range overview.Profiles {
		title := strings.Join(profile.Titles, " ")
		text := strings.ToLower(profile.ID + " " + title)
		if strings.Contains(text, query) {
			result = append(result, openWrtReleaseProfile{ID: profile.ID, Title: title, Target: profile.Target})
		}
	}
	return result, nil
}

func chooseProfile(reader *bufio.Reader, profiles []openWrtReleaseProfile) (openWrtReleaseProfile, bool) {
	if len(profiles) == 0 {
		printWarning("Совместимые профили не найдены")
		return openWrtReleaseProfile{}, false
	}
	limit := len(profiles)
	if limit > 20 {
		limit = 20
	}
	for i := 0; i < limit; i++ {
		fmt.Printf("%d. %s | %s | %s\n", i+1, profiles[i].ID, profiles[i].Target, profiles[i].Title)
	}
	fmt.Println("0. Назад")
	fmt.Print("Выберите профиль: ")
	choice, err := readMenuChoice(reader)
	if err != nil || choice <= 0 || choice > limit {
		return openWrtReleaseProfile{}, false
	}
	return profiles[choice-1], true
}

func downloadLocalFile(remoteURL string, filename string) (string, error) {
	resp, err := http.Get(remoteURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	dir, err := executableDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, filename)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if _, err := io.Copy(file, resp.Body); err != nil {
		return "", err
	}
	return path, nil
}

func printPackageResourceAdvice(resources routerResources, minSpaceKB int64, minMemoryKB int64, description string) {
	fmt.Println(description)
	fmt.Printf("Свободно overlay: %d KB, /tmp: %d KB, RAM: %d KB\n", resources.OverlayFreeKB, resources.TmpFreeKB, resources.MemAvailableKB)
	if resources.OverlayFreeKB > 0 && resources.OverlayFreeKB < minSpaceKB {
		printWarning("Места в overlay может не хватить. Лучше использовать роутер с большим flash или custom image.")
	}
	if resources.MemAvailableKB > 0 && resources.MemAvailableKB < minMemoryKB {
		printWarning("Свободной RAM может не хватить для стабильной работы.")
	}
}

func runPackageInstall(router routerClient, packages []string) {
	command := "opkg update && opkg install " + strings.Join(shellQuoteList(packages), " ")
	if output, err := runRemote(router, command); err != nil {
		printRouterError("Пакет не установлен", fmt.Errorf("%w: %s", err, strings.TrimSpace(output)))
		return
	}
	printSuccess("Пакет установлен")
}

func runPackageUpgrade(router routerClient, packageName string) {
	command := "opkg update && opkg upgrade " + shellQuote(packageName)
	if output, err := runRemote(router, command); err != nil {
		printRouterError("Пакет не обновлен", fmt.Errorf("%w: %s", err, strings.TrimSpace(output)))
		return
	}
	printSuccess("Пакет обновлен")
}

func runPackageRemove(router routerClient, packages []string) {
	command := "opkg remove " + strings.Join(shellQuoteList(packages), " ")
	if output, err := runRemote(router, command); err != nil {
		printRouterError("Пакет не удален", fmt.Errorf("%w: %s", err, strings.TrimSpace(output)))
		return
	}
	printSuccess("Пакет удален")
}

func installDNSPackage(router routerClient, packageName string) {
	if err := installDNSPackageCommand(router, packageName); err != nil {
		printRouterError("DNS пакет не установлен", err)
		return
	}
	printSuccess("DNS пакет установлен")
}

func installDNSPackageCommand(router routerClient, packageName string) error {
	var command string
	switch packageName {
	case "dnsmasq-full":
		command = strings.Join([]string{
			"opkg update",
			"(opkg list-installed dnsmasq-full >/dev/null 2>&1 || (opkg remove dnsmasq && opkg install dnsmasq-full))",
			"mkdir -p /tmp/dnsmasq.d",
			"uci -q delete dhcp.@dnsmasq[0].confdir",
			"uci add_list dhcp.@dnsmasq[0].confdir='/tmp/dnsmasq.d'",
			"uci commit dhcp",
			"service dnsmasq restart",
		}, " && ")
	case "dnscrypt-proxy2":
		command = strings.Join([]string{
			"opkg update",
			"opkg install dnscrypt-proxy2",
			"/etc/init.d/dnscrypt-proxy enable",
			"/etc/init.d/dnscrypt-proxy restart",
			"uci set dhcp.@dnsmasq[0].noresolv='1'",
			"uci -q delete dhcp.@dnsmasq[0].server",
			"uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#5353'",
			"uci commit dhcp",
			"service dnsmasq restart",
		}, " && ")
	case "stubby":
		command = strings.Join([]string{
			"opkg update",
			"opkg install stubby",
			"/etc/init.d/stubby enable",
			"/etc/init.d/stubby restart",
			"uci set dhcp.@dnsmasq[0].noresolv='1'",
			"uci -q delete dhcp.@dnsmasq[0].server",
			"uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#5453'",
			"uci commit dhcp",
			"service dnsmasq restart",
		}, " && ")
	default:
		command = "opkg update && opkg install " + shellQuote(packageName)
	}
	if output, err := runRemote(router, command); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(output))
	}
	return nil
}

func configureDNSPackage(router routerClient, packageName string) {
	if err := configureDNSPackageCommand(router, packageName); err != nil {
		printWarning("DNS пакет установлен, но настройка не применена: " + err.Error())
	}
}

func configureDNSPackageCommand(router routerClient, packageName string) error {
	var command string
	switch packageName {
	case "dnsmasq-full":
		command = "mkdir -p /tmp/dnsmasq.d && uci -q delete dhcp.@dnsmasq[0].confdir && uci add_list dhcp.@dnsmasq[0].confdir='/tmp/dnsmasq.d' && uci commit dhcp && service dnsmasq restart"
	case "dnscrypt-proxy2":
		command = "/etc/init.d/dnscrypt-proxy enable && /etc/init.d/dnscrypt-proxy restart && uci set dhcp.@dnsmasq[0].noresolv='1' && uci -q delete dhcp.@dnsmasq[0].server && uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#5353' && uci commit dhcp && service dnsmasq restart"
	case "stubby":
		command = "/etc/init.d/stubby enable && /etc/init.d/stubby restart && uci set dhcp.@dnsmasq[0].noresolv='1' && uci -q delete dhcp.@dnsmasq[0].server && uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#5453' && uci commit dhcp && service dnsmasq restart"
	default:
		return nil
	}
	if output, err := runRemote(router, command); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(output))
	}
	return nil
}

func removeDNSPackage(router routerClient, packageName string) {
	command := "opkg remove " + shellQuote(packageName)
	switch packageName {
	case "dnscrypt-proxy2":
		command = "/etc/init.d/dnscrypt-proxy stop 2>/dev/null || true; " + command + "; uci -q delete dhcp.@dnsmasq[0].server; uci -q delete dhcp.@dnsmasq[0].noresolv; uci commit dhcp; service dnsmasq restart"
	case "stubby":
		command = "/etc/init.d/stubby stop 2>/dev/null || true; " + command + "; uci -q delete dhcp.@dnsmasq[0].server; uci -q delete dhcp.@dnsmasq[0].noresolv; uci commit dhcp; service dnsmasq restart"
	case "dnsmasq-full":
		command = command + "; opkg install dnsmasq; uci -q delete dhcp.@dnsmasq[0].confdir; uci commit dhcp; service dnsmasq restart"
	}
	if output, err := runRemote(router, command); err != nil {
		printRouterError("DNS пакет не удален", fmt.Errorf("%w: %s", err, strings.TrimSpace(output)))
		return
	}
	printSuccess("DNS пакет удален")
}

func configureSingBoxService(router routerClient) {
	config := openWrtSingBoxBaseConfig()
	_, _ = runRemote(router, "mkdir -p /etc/sing-box")
	if err := writeRemote(router, "/tmp/remnawave-sing-box-base.json", []byte(config)); err == nil {
		_, _ = runRemote(router, "[ -s /etc/sing-box/config.json ] || mv /tmp/remnawave-sing-box-base.json /etc/sing-box/config.json")
	}
	commands := []string{
		"uci set sing-box.main=sing-box",
		"uci set sing-box.main.enabled='1'",
		"uci set sing-box.main.user='root'",
		"uci set sing-box.main.conffile='/etc/sing-box/config.json'",
		"uci commit sing-box",
		"/etc/init.d/sing-box enable",
		configureTunFirewallCommand(),
	}
	for _, command := range commands {
		_, _ = runRemote(router, command)
	}
	printSuccess("sing-box настроен")
}

func openWrtSingBoxBaseConfig() string {
	config := map[string]any{
		"log": map[string]any{"level": "info"},
		"inbounds": []any{map[string]any{
			"type":           "tun",
			"tag":            "tun-in",
			"interface_name": "tun0",
			"address":        []string{"172.16.250.1/30"},
			"auto_route":     false,
			"strict_route":   false,
			"sniff":          true,
		}},
		"outbounds": []any{
			map[string]any{"type": "direct", "tag": "direct"},
			map[string]any{"type": "block", "tag": "block"},
		},
		"route": map[string]any{"auto_detect_interface": true, "final": "direct"},
	}
	body, _ := json.MarshalIndent(config, "", "  ")
	return string(body) + "\n"
}

func configureTunFirewallCommand() string {
	return strings.Join([]string{
		"uci set firewall.tun=zone",
		"uci set firewall.tun.name='tun'",
		"uci set firewall.tun.forward='ACCEPT'",
		"uci set firewall.tun.output='ACCEPT'",
		"uci set firewall.tun.input='ACCEPT'",
		"uci set firewall.tun.masq='1'",
		"uci set firewall.tun.mtu_fix='1'",
		"uci set firewall.tun.device='tun0'",
		"uci set firewall.tun.family='ipv4'",
		"uci set firewall.lan_tun=forwarding",
		"uci set firewall.lan_tun.name='lan-tun'",
		"uci set firewall.lan_tun.src='lan'",
		"uci set firewall.lan_tun.dest='tun'",
		"uci set firewall.lan_tun.family='ipv4'",
		"uci commit firewall",
		"service firewall restart",
	}, " && ")
}

func backupSingBoxBeforePackageChange(router routerClient) (string, error) {
	existsOutput, err := runRemote(router, "if [ -d /etc/sing-box ] || opkg list-installed sing-box >/dev/null 2>&1; then echo yes; fi")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(existsOutput) != "yes" {
		return "", nil
	}

	name := "sing-box-backup-" + time.Now().Format("20060102-150405") + ".tar.gz"
	remotePath := "/tmp/" + name
	command := "tar -czf " + shellQuote(remotePath) + " " +
		"/etc/sing-box /etc/config/sing-box 2>/dev/null || " +
		"tar -czf " + shellQuote(remotePath) + " /etc/sing-box 2>/dev/null || true"
	if output, err := runRemote(router, command); err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(output))
	}
	if output, err := runRemote(router, "test -s "+shellQuote(remotePath)+" && ls -lh "+shellQuote(remotePath)); err != nil {
		return "", fmt.Errorf("backup пустой: %w: %s", err, strings.TrimSpace(output))
	}
	body, err := runRemoteOutput(router, "cat "+shellQuote(remotePath))
	if err != nil {
		return "", err
	}
	localPath, err := saveLocalBackupFile(name, body)
	if err != nil {
		return "", err
	}
	_, _ = runRemote(router, "rm -f "+shellQuote(remotePath))
	return localPath, nil
}

func chooseAndInstallPackageVersion(reader *bufio.Reader, router routerClient, info openWrtRouterInfo, packageName string) {
	_ = chooseAndInstallPackageVersionResult(reader, router, info, packageName, false)
}

func chooseAndInstallSingBoxPackageVersion(reader *bufio.Reader, router routerClient, info openWrtRouterInfo) bool {
	return chooseAndInstallPackageVersionResult(reader, router, info, "sing-box", true)
}

func chooseAndInstallPackageVersionResult(reader *bufio.Reader, router routerClient, info openWrtRouterInfo, packageName string, backupBeforeInstall bool) bool {
	versions, err := fetchCompatiblePackageVersions(info, packageName)
	if err != nil {
		printRouterError("Версии пакета не найдены", err)
		return false
	}
	if len(versions) == 0 {
		printWarning("Совместимые версии не найдены")
		return false
	}
	for i, item := range versions {
		fmt.Printf("%d. %s %s (%d KB)\n", i+1, item.Package, item.Version, item.Size/1024)
	}
	fmt.Println("0. Назад")
	fmt.Print("Выберите версию: ")
	choice, err := readMenuChoice(reader)
	if err != nil || choice <= 0 || choice > len(versions) {
		return false
	}
	item := versions[choice-1]
	if !hasEnoughOverlayForPackage(router, item) {
		waitEnter(reader)
		return false
	}
	if !confirmYNDefaultYes(reader, "Установить выбранный пакет? Введите y/n: ") {
		return false
	}
	remotePackagePath, ok := prepareRemotePackageFile(router, item)
	if !ok {
		return false
	}
	if backupBeforeInstall {
		backupPath, err := backupSingBoxBeforePackageChange(router)
		if err != nil {
			printWarning("Backup sing-box не создан: " + err.Error())
		} else if backupPath != "" {
			printSuccess("Backup sing-box скачан: " + backupPath)
		}
	}
	runPackageInstall(router, []string{remotePackagePath})
	return true
}

func hasEnoughOverlayForPackage(router routerClient, item openWrtPackageVersion) bool {
	resources, err := readRouterResources(router)
	if err != nil {
		printWarning("Не удалось проверить свободное место: " + err.Error())
		return true
	}
	requiredKB := item.Size/1024 + 2048
	if item.Size <= 0 || resources.OverlayFreeKB <= 0 {
		printWarning("Не удалось точно оценить размер пакета или свободное место")
		return true
	}
	if resources.OverlayFreeKB < requiredKB {
		printError(fmt.Sprintf(
			"Недостаточно места в overlay: свободно %d KB, нужно примерно %d KB для %s %s.",
			resources.OverlayFreeKB,
			requiredKB,
			item.Package,
			item.Version,
		))
		printWarning("Установка отменена. Освободите место, используйте extroot или соберите OpenWrt image с нужным пакетом.")
		return false
	}
	return true
}

func prepareRemotePackageFile(router routerClient, item openWrtPackageVersion) (string, bool) {
	remotePath := "/tmp/" + filepath.Base(item.Filename)
	if output, err := runRemote(router, downloadCommand(item.URL, remotePath)); err != nil {
		printRouterError("Пакет не скачан на роутер", fmt.Errorf("%w: %s", err, strings.TrimSpace(output)))
		return "", false
	}
	if output, err := runRemote(router, "test -s "+shellQuote(remotePath)+" && ls -lh "+shellQuote(remotePath)); err != nil {
		printRouterError("Скачанный пакет не найден или пустой", fmt.Errorf("%w: %s", err, strings.TrimSpace(output)))
		return "", false
	}
	return remotePath, true
}

func fetchCompatiblePackageVersions(info openWrtRouterInfo, packageName string) ([]openWrtPackageVersion, error) {
	if info.Release == "" || info.Arch == "" {
		return nil, errors.New("не определены версия OpenWrt или архитектура opkg")
	}
	feeds := []string{"base", "packages", "routing", "telephony"}
	var result []openWrtPackageVersion
	for _, feed := range feeds {
		base := openWrtReleasesURL + info.Release + "/packages/" + info.Arch + "/" + feed + "/"
		versions, err := fetchPackageFeed(base, packageName)
		if err == nil {
			result = append(result, versions...)
		}
	}
	return result, nil
}

func fetchPackageFeed(baseURL string, packageName string) ([]openWrtPackageVersion, error) {
	body, err := fetch(baseURL+"Packages.gz", "terminal-openwrt", "application/octet-stream")
	if err != nil {
		return nil, err
	}
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	plain, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return parsePackageFeed(string(plain), baseURL, packageName), nil
}

func parsePackageFeed(body string, baseURL string, packageName string) []openWrtPackageVersion {
	var result []openWrtPackageVersion
	for _, block := range strings.Split(body, "\n\n") {
		fields := parsePackageBlock(block)
		if fields["Package"] != packageName {
			continue
		}
		size, _ := strconv.ParseInt(fields["Size"], 10, 64)
		filename := fields["Filename"]
		if filename == "" {
			continue
		}
		result = append(result, openWrtPackageVersion{
			Package:  packageName,
			Version:  fields["Version"],
			Filename: filename,
			Size:     size,
			URL:      baseURL + filename,
		})
	}
	return result
}

func parsePackageBlock(block string) map[string]string {
	values := make(map[string]string)
	var current string
	for _, line := range strings.Split(block, "\n") {
		if strings.HasPrefix(line, " ") && current != "" {
			values[current] += "\n" + strings.TrimSpace(line)
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		current = parts[0]
		values[current] = strings.TrimSpace(parts[1])
	}
	return values
}

func chooseDNSOption(reader *bufio.Reader, options []dnsPackageOption, resources routerResources, installed map[string]installedPackage) (dnsPackageOption, bool) {
	for i, option := range options {
		title := option.Title
		if item, ok := installed[option.Name]; ok {
			title = colorGreen + title + " (установлен: " + item.Version + ")" + colorReset
		}
		fmt.Printf("%d. %s\n", i+1, title)
		fmt.Println("   " + option.Description)
		if resources.OverlayFreeKB > 0 && resources.OverlayFreeKB < option.MinSpaceKB {
			fmt.Println("   " + colorYellow + "Места может не хватить" + colorReset)
		}
		if resources.MemAvailableKB > 0 && resources.MemAvailableKB < option.MinMemoryKB {
			fmt.Println("   " + colorYellow + "RAM может не хватить" + colorReset)
		}
	}
	fmt.Println("0. Назад")
	fmt.Print("Выберите вариант: ")
	choice, err := readMenuChoice(reader)
	if err != nil || choice <= 0 || choice > len(options) {
		return dnsPackageOption{}, false
	}
	return options[choice-1], true
}

func chooseInstalledDNSOption(reader *bufio.Reader, router routerClient, options []dnsPackageOption) (dnsPackageOption, bool) {
	installed := installedDNSPackages(router, options)
	if len(installed) == 0 {
		printWarning("DNS пакеты из списка не установлены")
		return dnsPackageOption{}, false
	}

	printTitle("Установленные DNS пакеты")
	for i, option := range options {
		item, ok := installed[option.Name]
		if !ok {
			fmt.Printf("%d. %s%s%s\n", i+1, colorYellow, option.Title+" (не установлен)", colorReset)
			continue
		}
		fmt.Printf("%d. %s%s (установлен: %s)%s\n", i+1, colorGreen, option.Title, item.Version, colorReset)
	}
	fmt.Println("0. Назад")
	fmt.Print("Выберите что удалить: ")
	choice, err := readMenuChoice(reader)
	if err != nil || choice <= 0 || choice > len(options) {
		return dnsPackageOption{}, false
	}
	option := options[choice-1]
	if _, ok := installed[option.Name]; !ok {
		printWarning("Этот пакет не установлен")
		return dnsPackageOption{}, false
	}
	return option, true
}

func installedDNSPackages(router routerClient, options []dnsPackageOption) map[string]installedPackage {
	names := make([]string, 0, len(options))
	for _, option := range options {
		names = append(names, option.Name)
	}
	body, err := runRemote(router, "opkg list-installed "+strings.Join(shellQuoteList(names), " ")+" 2>/dev/null || true")
	if err != nil {
		return nil
	}
	return parseInstalledPackages(body)
}

func primaryInstalledDNSOption(options []dnsPackageOption, installed map[string]installedPackage) (dnsPackageOption, bool) {
	for _, option := range options {
		if _, ok := installed[option.Name]; ok {
			return option, true
		}
	}
	return dnsPackageOption{}, false
}

func parseInstalledPackages(body string) map[string]installedPackage {
	result := make(map[string]installedPackage)
	for _, line := range strings.Split(body, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), " - ", 2)
		if len(parts) != 2 || parts[0] == "" {
			continue
		}
		result[parts[0]] = installedPackage{Name: parts[0], Version: parts[1]}
	}
	return result
}

func installedPackageVersion(router routerClient, packageName string) string {
	body, err := runRemote(router, "opkg list-installed "+shellQuote(packageName)+" 2>/dev/null || true")
	if err != nil {
		return ""
	}
	packages := parseInstalledPackages(body)
	return packages[packageName].Version
}

func readProxyDomains(router routerClient) ([]string, error) {
	body, err := runRemote(router, "cat "+shellQuote(proxyDomainsPath)+" 2>/dev/null || true")
	if err != nil {
		return nil, err
	}
	return parseProxyDomains(body), nil
}

func readProxyDomainsFromFile(router routerClient, file proxyDomainFile) ([]string, error) {
	body, err := readRemoteFile(router, file.Path)
	if err != nil {
		return nil, err
	}
	if file.Path == "/etc/config/dhcp" {
		return parseDHCPVPNDomains(body), nil
	}
	return parseProxyDomainFileDomains(body), nil
}

func writeProxyDomainsToFile(router routerClient, file proxyDomainFile, domains []string) error {
	domains = parseProxyDomains(strings.Join(domains, "\n"))
	var body string
	if file.Path == "/etc/config/dhcp" {
		current, err := readRemoteFile(router, file.Path)
		if err != nil {
			return err
		}
		body = updateDHCPVPNDomains(current, domains)
	} else if file.Path == proxyDomainsPath || filepath.Base(file.Path) == "discord-voice-ip-list.txt" {
		body = strings.Join(domains, "\n")
		if body != "" {
			body += "\n"
		}
	} else {
		body = dnsmasqConfigForDomains(domains)
	}
	return writeRemote(router, file.Path, []byte(body))
}

func findProxyDomainFiles(router routerClient) ([]proxyDomainFile, error) {
	command := "sh -c " + shellQuote("for file in "+proxyDomainsPath+" "+proxyDomainsDnsmasqPath+" /etc/config/dhcp /etc/dnsmasq.d/*.conf /tmp/dnsmasq.d/* /etc/*domain* /etc/*discord* /tmp/*domain* /tmp/*discord*; do [ -f \"$file\" ] || continue; if [ \"$file\" = \""+proxyDomainsPath+"\" ] || [ \"$(basename \"$file\")\" = \"discord-voice-ip-list.txt\" ] || grep -qE 'vpn_domains|nftset=|list[[:space:]]+name[[:space:]]+.*vpn_domains|list[[:space:]]+domain' \"$file\" 2>/dev/null; then echo \"$file\"; fi; done")
	body, err := runRemote(router, command)
	if err != nil {
		return nil, err
	}
	return parseProxyDomainFiles(body), nil
}

func parseProxyDomainFiles(body string) []proxyDomainFile {
	seen := make(map[string]bool)
	var files []proxyDomainFile
	for _, line := range strings.Split(body, "\n") {
		path := strings.TrimSpace(line)
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		file := proxyDomainFile{Path: path, Editable: true, Deletable: true}
		switch path {
		case proxyDomainsPath:
			file.Kind = "список доменов"
		case proxyDomainsDnsmasqPath:
			file.Kind = "dnsmasq nftset"
		case "/etc/config/dhcp":
			file.Kind = "dhcp ipset vpn_domains"
			file.Deletable = false
		default:
			if filepath.Base(path) == "discord-voice-ip-list.txt" {
				file.Kind = "discord voice ip list"
			} else {
				file.Kind = "dnsmasq"
			}
		}
		files = append(files, file)
	}
	return files
}

func proxyDomainFilesText(files []proxyDomainFile) string {
	if len(files) == 0 {
		return colorYellow + "Файлы доменов не найдены" + colorReset
	}
	var builder strings.Builder
	builder.WriteString("Найдены файлы:\n")
	for i, file := range files {
		builder.WriteString(fmt.Sprintf("%d. %s%s%s | %s", i+1, colorGreen, file.Path, colorReset, file.Kind))
		if file.Editable {
			builder.WriteString(" | можно редактировать")
		}
		if file.Deletable {
			builder.WriteString(" | можно удалить")
		}
		builder.WriteString("\n")
	}
	return strings.TrimRight(builder.String(), "\n")
}

func chooseProxyDomainFile(reader *bufio.Reader, files []proxyDomainFile) (proxyDomainFile, bool) {
	if len(files) == 0 {
		printWarning("Файлы доменов не найдены")
		return proxyDomainFile{}, false
	}
	fmt.Println(proxyDomainFilesText(files))
	fmt.Println("0. Назад")
	fmt.Print("Выберите файл: ")
	choice, err := readMenuChoice(reader)
	if err != nil || choice <= 0 || choice > len(files) {
		return proxyDomainFile{}, false
	}
	return files[choice-1], true
}

func readRemoteFile(router routerClient, path string) (string, error) {
	if path == "nft:inet/fw4/vpn_domains" {
		body, err := runRemote(router, "nft list set inet fw4 vpn_domains")
		if err != nil {
			return "", err
		}
		return body, nil
	}
	body, err := runRemote(router, "cat "+shellQuote(path))
	if err != nil {
		return "", err
	}
	return body, nil
}

func parseProxyDomains(body string) []string {
	var domains []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(body, "\n") {
		domain := normalizeDomain(line)
		if domain == "" || seen[domain] {
			continue
		}
		seen[domain] = true
		domains = append(domains, domain)
	}
	return domains
}

func parseProxyDomainFileDomains(body string) []string {
	var domains []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(body, "\n") {
		for _, domain := range domainsFromProxyDomainLine(line) {
			domain = normalizeDomain(domain)
			if domain == "" || seen[domain] {
				continue
			}
			seen[domain] = true
			domains = append(domains, domain)
		}
	}
	return domains
}

func parseDHCPVPNDomains(body string) []string {
	block := dhcpVPNDomainsBlock(body)
	if block == "" {
		return nil
	}
	var domains []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "list domain") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		domain := normalizeDomain(strings.Join(parts[2:], " "))
		if domain == "" || seen[domain] {
			continue
		}
		seen[domain] = true
		domains = append(domains, domain)
	}
	return domains
}

func updateDHCPVPNDomains(body string, domains []string) string {
	block := buildDHCPVPNDomainsBlock(domains)
	lines := strings.Split(body, "\n")
	start, end := dhcpVPNDomainsBlockRange(lines)
	if start >= 0 {
		updated := append([]string{}, lines[:start]...)
		updated = append(updated, strings.Split(strings.TrimRight(block, "\n"), "\n")...)
		updated = append(updated, lines[end:]...)
		return strings.TrimRight(strings.Join(updated, "\n"), "\n") + "\n"
	}
	body = strings.TrimRight(body, "\n")
	if body != "" {
		body += "\n\n"
	}
	return body + block
}

func buildDHCPVPNDomainsBlock(domains []string) string {
	var builder strings.Builder
	builder.WriteString("config ipset\n")
	builder.WriteString("\tlist name 'vpn_domains'\n")
	for _, domain := range parseProxyDomains(strings.Join(domains, "\n")) {
		builder.WriteString("\tlist domain '")
		builder.WriteString(domain)
		builder.WriteString("'\n")
	}
	return builder.String()
}

func dhcpVPNDomainsBlock(body string) string {
	lines := strings.Split(body, "\n")
	start, end := dhcpVPNDomainsBlockRange(lines)
	if start < 0 {
		return ""
	}
	return strings.Join(lines[start:end], "\n")
}

func dhcpVPNDomainsBlockRange(lines []string) (int, int) {
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "config ipset" {
			continue
		}
		end := len(lines)
		for j := i + 1; j < len(lines); j++ {
			if strings.HasPrefix(strings.TrimSpace(lines[j]), "config ") {
				end = j
				break
			}
		}
		block := strings.Join(lines[i:end], "\n")
		if strings.Contains(block, "list name 'vpn_domains'") || strings.Contains(block, `list name "vpn_domains"`) || strings.Contains(block, "list name vpn_domains") {
			return i, end
		}
	}
	return -1, -1
}

func domainsFromProxyDomainLine(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	if strings.Contains(line, "nftset=/") {
		return domainsFromDNSMasqNftsetLine(line)
	}
	return []string{line}
}

func domainsFromDNSMasqNftsetLine(line string) []string {
	var domains []string
	parts := strings.Split(line, "nftset=/")
	for _, part := range parts[1:] {
		end := strings.Index(part, "/4#")
		if end < 0 {
			end = strings.Index(part, "/6#")
		}
		if end < 0 {
			end = strings.LastIndex(part, "/")
		}
		if end <= 0 {
			continue
		}
		for _, domain := range strings.Split(part[:end], "/") {
			domain = strings.TrimSpace(domain)
			if domain != "" {
				domains = append(domains, domain)
			}
		}
	}
	return domains
}

func normalizeDomain(value string) string {
	value = strings.Trim(strings.TrimSpace(strings.ToLower(value)), `'"`)
	if value == "" || strings.HasPrefix(value, "#") {
		return ""
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
		value = parsed.Hostname()
	}
	value = strings.TrimPrefix(value, "*.")
	value = strings.Trim(strings.Trim(value, "."), `'"`)
	if strings.Contains(value, "/") {
		value = strings.SplitN(value, "/", 2)[0]
	}
	if value == "" || strings.ContainsAny(value, " \t") {
		return ""
	}
	return value
}

func addProxyDomain(domains []string, domain string) []string {
	domain = normalizeDomain(domain)
	if domain == "" {
		return domains
	}
	for _, existing := range domains {
		if existing == domain {
			return domains
		}
	}
	return append(domains, domain)
}

func removeProxyDomain(domains []string, domain string) []string {
	domain = normalizeDomain(domain)
	result := make([]string, 0, len(domains))
	for _, existing := range domains {
		if existing != domain {
			result = append(result, existing)
		}
	}
	return result
}

func writeProxyDomains(router routerClient, domains []string) error {
	body := strings.Join(parseProxyDomains(strings.Join(domains, "\n")), "\n")
	if body != "" {
		body += "\n"
	}
	return writeRemote(router, proxyDomainsPath, []byte(body))
}

func proxyDomainsText(domains []string) string {
	if len(domains) == 0 {
		return "Список доменов пуст"
	}
	return strings.Join(domains, "\n")
}

func readDomainInput(reader *bufio.Reader, prompt string) string {
	fmt.Print(prompt)
	text, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	return normalizeDomain(text)
}

func readDomainList(reader *bufio.Reader) []string {
	var domains []string
	for {
		text, err := reader.ReadString('\n')
		if err != nil {
			return domains
		}
		if strings.TrimSpace(text) == "" {
			return domains
		}
		domains = addProxyDomain(domains, text)
	}
}

func dnsmasqConfigForDomains(domains []string) string {
	var builder strings.Builder
	for _, domain := range parseProxyDomains(strings.Join(domains, "\n")) {
		builder.WriteString("nftset=/")
		builder.WriteString(domain)
		builder.WriteString("/4#inet#fw4#vpn_domains\n")
	}
	return builder.String()
}

func applyProxyDomains(router routerClient, domains []string) error {
	config := dnsmasqConfigForDomains(domains)
	_, _ = runRemote(router, "mkdir -p /etc/dnsmasq.d /etc/hotplug.d/iface")
	if err := writeRemote(router, proxyDomainsDnsmasqPath, []byte(config)); err != nil {
		return err
	}
	if err := writeRemote(router, "/etc/hotplug.d/iface/99-remnawave-proxy-domains", []byte(proxyDomainsHotplugScript())); err != nil {
		return err
	}
	commands := []string{
		"chmod +x /etc/hotplug.d/iface/99-remnawave-proxy-domains",
		"uci set firewall.vpn_domains=ipset",
		"uci set firewall.vpn_domains.name='vpn_domains'",
		"uci set firewall.vpn_domains.family='ipv4'",
		"uci set firewall.vpn_domains.match='dest_ip'",
		"uci set firewall.mark_domains=rule",
		"uci set firewall.mark_domains.name='mark_domains'",
		"uci set firewall.mark_domains.src='lan'",
		"uci set firewall.mark_domains.dest='*'",
		"uci set firewall.mark_domains.proto='all'",
		"uci set firewall.mark_domains.ipset='vpn_domains'",
		"uci set firewall.mark_domains.set_mark='0x1'",
		"uci set firewall.mark_domains.target='MARK'",
		"uci set firewall.mark_domains.family='ipv4'",
		"uci commit firewall",
		"dnsmasq --conf-file=" + shellQuote(proxyDomainsDnsmasqPath) + " --test",
		"service firewall restart",
		"service dnsmasq restart",
		"ip route replace default dev tun0 table 100 2>/dev/null || true",
		"ip rule add fwmark 0x1 table 100 2>/dev/null || true",
	}
	for _, command := range commands {
		if output, err := runRemote(router, command); err != nil {
			return fmt.Errorf("%s: %w: %s", command, err, strings.TrimSpace(output))
		}
	}
	return nil
}

func proxyDomainsHotplugScript() string {
	return `#!/bin/sh
[ "$ACTION" = ifup ] || exit 0
ip route replace default dev tun0 table 100 2>/dev/null || true
ip rule add fwmark 0x1 table 100 2>/dev/null || true
`
}

func downloadCommand(remoteURL string, path string) string {
	quotedURL := shellQuote(remoteURL)
	quotedPath := shellQuote(path)
	return "(command -v wget >/dev/null 2>&1 && wget -O " + quotedPath + " " + quotedURL + ") || (command -v curl >/dev/null 2>&1 && curl -L -o " + quotedPath + " " + quotedURL + ")"
}

func shellQuoteList(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, shellQuote(value))
	}
	return result
}
