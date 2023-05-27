package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	url    string
	vulnId string
	proxy  string
)

var rootCmd = &cobra.Command{
	Use:   "TongdaScan_go",
	Short: "TongdaScan_go",
	Long: " _____                     _       ____\n" +
		"|_   _|__  _ __   __ _  __| | __ _/ ___|  ___ __ _ _ __       __ _  ___\n" +
		"  | |/ _ \\| '_ \\ / _` |/ _` |/ _` \\___ \\ / __/ _` | '_ \\     / _` |/ _ \\\n" +
		"  | | (_) | | | | (_| | (_| | (_| |___) | (_| (_| | | | |   | (_| | (_) |\n" +
		"  |_|\\___/|_| |_|\\__, |\\__,_|\\__,_|____/ \\___\\__,_|_| |_|____\\__, |\\___/\n" +
		"                 |___/                                 |_____|___/\n" +
		"                                                       @author: Fu5r0dah\n" +
		"                                                       @version: 1.0",
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.Flags().StringVarP(&url, "targetUrl", "u", "", "targetUrl")
	rootCmd.Flags().StringVarP(&proxy, "proxyUrl", "s", "", "设置HTTP代理 eg: http://127.0.0.1:8080")
	rootCmd.Flags().StringVarP(&vulnId, "vulnId", "i", "", "为空时，默认检测所有漏洞")
}
