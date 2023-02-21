package cmd

import (
	"sort"
	"strings"
	"tongdascan_go/core"
	"tongdascan_go/vulners"

	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use: "scan",
	Short: "漏洞检测 Tongdascan scan [flags] \n\n" +
		"                       eg: TongdaScan_go scan -u http://127.0.0.1 -i Td01\n" +
		"                       eg: TongdaScan_go exp -u http://127.0.0.1 -i Td01",
	Long: `漏洞检测功能
`,
	Run: func(cmd *cobra.Command, args []string) {
		vulners.SetProxyURL(proxy)
		pocs := make(map[string]interface{})
		url = strings.Trim(url, "/")
		sorted_keys := make([]string, 0)
		if vulnId != "" {
			a := core.AddPoc(pocs)
			a[vulnId].(vulners.PocInfo).Scan(url)
		} else {
			a := core.AddPoc(pocs)
			for k, _ := range a {
				sorted_keys = append(sorted_keys, k)
			}
			sort.Strings(sorted_keys)
			for _, k := range sorted_keys {
				a[k].(vulners.PocInfo).Scan(url)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVarP(&url, "targetUrl", "u", "", "targetUrl")
	scanCmd.Flags().StringVarP(&proxy, "proxyUrl", "s", "", "设置HTTP代理 eg: http://127.0.0.1:8080")
	scanCmd.Flags().StringVarP(&vulnId, "vulnId", "i", "", "vulnId默认为空检测全部漏洞")
	scanCmd.MarkFlagRequired("targetUrl")
}
