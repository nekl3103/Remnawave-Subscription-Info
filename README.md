# terminal

Программа для просмотра серверов из ссылки подписки Remnawave и настройки `sing-box` на роутере OpenWrt.

## Что умеет

- Запрашивает ссылку подписки.
- Показывает список серверов.
- Поддерживает VLESS, Shadowsocks и Hysteria2.
- Показывает детальную информацию выбранного сервера.
- Генерирует готовый `outbounds` для `sing-box`.
- Подключается к роутеру по SSH.
- Обновляет `/etc/sing-box/config.json`.
- Перезапускает `sing-box`.
- Показывает логи `sing-box` в реальном времени.

## Скачать

Скачайте файл для своей системы в разделе GitHub Releases:

- macOS Intel: `terminal-macos-amd64.tar.gz`
- macOS Apple Silicon: `terminal-macos-arm64.tar.gz`
- Linux 64-bit: `terminal-linux-amd64.tar.gz`
- Windows 64-bit: `terminal-windows-amd64.exe.zip`

## Запуск

### macOS и Linux

Распакуйте архив, откройте терминал в папке с программой и выполните:

```bash
chmod +x terminal-*
./terminal-linux-amd64
```

На macOS имя файла будет `terminal-macos-amd64` или `terminal-macos-arm64`.

### Windows

Распакуйте `.zip` архив и запустите:

```powershell
.\terminal-windows-amd64.exe
```

## Как пользоваться

1. Запустите программу.
2. Вставьте ссылку подписки, например:

```text
https://example.com/subscription-link
```

3. Выберите сервер из списка.
4. После выбора сервера можно:
   - показать настройки для `sing-box`;
   - записать сервер на роутер;
   - посмотреть логи `sing-box`;
   - сменить сервер;
   - выйти из программы.

## Настройка роутера

При выборе пункта `Заполнить данные сервера на роутер` программа спросит SSH адрес роутера:

```text
Введите SSH адрес роутера или нажмите Enter для root@192.168.1.1:
```

Если адрес стандартный, просто нажмите Enter.

Дальше введите пароль от роутера. Программа подключится по SSH и обновит файл:

```text
/etc/sing-box/config.json
```

Перед изменением создается backup:

```text
/etc/sing-box/config.json.bak
```

После сохранения программа перезапустит `sing-box`.

## Сборка из исходников

Нужен Go.

```bash
go test ./...
go build .
```

## Релизные сборки

Сборки создаются автоматически через GitHub Actions при пуше тега:

```bash
git tag v1.0.0
git push origin v1.0.0
```

После этого в GitHub Releases появятся архивы для macOS, Linux и Windows 64-bit.
