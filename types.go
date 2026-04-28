package main

type Server struct {
	Name     string
	Address  string
	Port     string
	Protocol string
	Details  map[string]string
	Raw      map[string]any
}

type installHistoryEntry struct {
	Time       string `json:"time"`
	ServerName string `json:"server_name"`
	Protocol   string `json:"protocol"`
	Address    string `json:"address"`
	Port       string `json:"port"`
	Router     string `json:"router"`
	BackupPath string `json:"backup_path"`
}

const (
	defaultRouterAddress = "root@192.168.1.1"
	appConfigDirName     = "Remnawave Subscription Info"
	appVersion           = "0.0.3"
	routerConfigPath     = "/etc/sing-box/config.json"
	routerBackupPath     = "/etc/sing-box/config.json.bak"
	colorBlue            = "\033[34m"
	colorGreen           = "\033[32m"
	colorYellow          = "\033[33m"
	colorRed             = "\033[31m"
	colorBold            = "\033[1m"
	colorReset           = "\033[0m"
)
