package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	TongdaVulnNames = []string{
		"通达OA v2014 get_contactlist.php 敏感信息泄漏", //1
		"通达OA v2017 video_file.php 任意文件下载",      //2
		"通达OA v2017 action_upload.php 任意文件上传",   //3
		"通达OA v2017 login_code.php 任意用户登录",      //4
		"通达OA v11 login_code.php 任意用户登录",        //5
		"通达OA v11.5 swfupload_new.php SQL注入",    //6
		"通达OA v11.6 report_bi.func.php SQL注入",   //7
		"通达OA v11.8 api.ali.php 任意文件上传",         //8
		"通达OA v11.8 gateway.php 远程文件包含RCE",      //9
		"通达OA v11.6 print.php前台组合拳RCE",          //10
		"通达OA v11.10 getdata 任意文件上传",            //11
	}
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "列出所有漏洞信息",
	Long:  `完整的漏洞列表及其对应ID.`,
	Run: func(cmd *cobra.Command, args []string) {
		for i, v := range TongdaVulnNames {
			fmt.Printf("【%v】%v\n", i+1, v)
		}
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
