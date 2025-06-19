package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func SingleQuery() {
	//csvFile := "tranco_G69KK.csv"
	//fileName := "SingleQuery.jsonl"
	//domains, err := fetchDomainsFromCSV(csvFile, 20240, 20241)
	usernames := []string{"info", "admin", "test", "user", "contact", "support", "random123", "123", "wehuheufescdnjncdnvjndnvsdnksl"}
	domains := []string{"seznam.cz"}
	// if err != nil {
	// 	fmt.Printf("Failed to fetch domains from CSV: %v\n", err)
	// 	return
	// }
	for _, domain := range domains {
		// // autodiscoverResult := queryAutodiscover(domain)
		// // fmt.Print(autodiscoverResult)
		// _, _, _, _, config, _, _ := getAutodiscoverConfig(domain, fmt.Sprintf("http://autodiscover.%s/autodiscover/autodiscover.xml", domain), fmt.Sprintf("info@%s", domain), "post", 3, 0, 0, 0)
		// // var autodiscoverResp AutodiscoverResponse
		// // err = xml.Unmarshal([]byte(config), &autodiscoverResp)
		// // if err == nil {
		// fmt.Print(config) //如果能打印出完整的config说明还是没有解析出Error
		// // 	if autodiscoverResp.Response.Error != nil {
		// // 		fmt.Print(autodiscoverResp.Response.Error.ErrorCode)
		// // 	}

		// // }
		fmt.Printf("====== 检查域名: %s ======\n", domain)
		for _, name := range usernames {
			email := fmt.Sprintf("%s@%s", name, domain)
			url := fmt.Sprintf("http://%s/autodiscover/autodiscover.xml", domain)
			//https://autodiscover.%s/autodiscover/autodiscover.xml //2
			//"http://autodiscover.%s/autodiscover/autodiscover.xml //3
			//"https://%s/autodiscover/autodiscover.xml"//4
			//url := fmt.Sprintf("http://%s/autodiscover/autodiscover.xml", domain) //1
			_, _, _, _, config, _, _ := getAutodiscoverConfig_try_norecord(domain, url, email, "post", 1, 0, 0, 0)

			fmt.Printf("\n[%s] 返回结果:\n", email)
			fmt.Println(config)

			// 尝试查找是否有 ErrorCode=500 的内容
			if strings.Contains(config, "Errorcode:500") {
				fmt.Println("⚠️ 该地址返回 ErrorCode 500，用户可能不存在。")
			} else if strings.Contains(config, "Errorcode") {
				fmt.Println("⚠️ 返回其他错误码，需进一步分析。")
			} else {
				fmt.Println("✅ 没有错误码，可能是有效的配置！")
			}
		}
	}

}

func getAutodiscoverConfig_try_norecord(origin_domain string, uri string, email_add string, method string, index int, flag1 int, flag2 int, flag3 int) (int, int, int, []map[string]interface{}, string, *CertInfo, error) {
	xmlRequest := fmt.Sprintf(`
		<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
			<Request>
				<EMailAddress>%s</EMailAddress>
				<AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
			</Request>
		</Autodiscover>`, email_add)

	req, err := http.NewRequest("POST", uri, bytes.NewBufferString(xmlRequest))
	if err != nil {
		fmt.Printf("Error creating request for %s: %v\n", uri, err)
		return flag1, flag2, flag3, []map[string]interface{}{}, "", nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "text/xml")
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 禁止重定向
		},
		Timeout: 15 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending request to %s: %v\n", uri, err)
		return flag1, flag2, flag3, []map[string]interface{}{}, "", nil, fmt.Errorf("failed to send request: %v", err)
	}

	redirects := getRedirects(resp) // 获取当前重定向链
	defer resp.Body.Close()         //
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		// 处理重定向
		flag1 = flag1 + 1
		fmt.Printf("flag1now:%d\n", flag1)
		location := resp.Header.Get("Location")
		fmt.Printf("Redirect to: %s\n", location)
		if location == "" {
			return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("missing Location header in redirect")
		} else if flag1 > 10 { //12.27限制重定向次数
			//saveXMLToFile_autodiscover("./location.xml", origin_domain, email_add)
			return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("too many redirect times")
		}

		newURI, err := url.Parse(location)
		if err != nil {
			return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("failed to parse redirect URL: %s", location)
		}

		// 递归调用并合并重定向链
		newflag1, newflag2, newflag3, nextRedirects, result, certinfo, err := getAutodiscoverConfig_try_norecord(origin_domain, newURI.String(), email_add, method, index, flag1, flag2, flag3)
		//return append(redirects, nextRedirects...), result, err //12.27原
		return newflag1, newflag2, newflag3, append(redirects, nextRedirects...), result, certinfo, err
	} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// 处理成功响应
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("failed to read response body: %v", err)
		}

		var autodiscoverResp AutodiscoverResponse
		err = xml.Unmarshal(body, &autodiscoverResp)
		//这里先记录下unmarshal就不成功的xml
		if err != nil {
			// if (strings.HasPrefix(strings.TrimSpace(string(body)), `<?xml version="1.0"`) || strings.HasPrefix(strings.TrimSpace(string(body)), `<Autodiscover`)) && !strings.Contains(strings.TrimSpace(string(body)), `<html`) && !strings.Contains(strings.TrimSpace(string(body)), `<item`) && !strings.Contains(strings.TrimSpace(string(body)), `lastmod`) && !strings.Contains(strings.TrimSpace(string(body)), `lt`) {
			// 	//if !strings.Contains(strings.TrimSpace(string(body)), `<html`) && !strings.Contains(strings.TrimSpace(string(body)), `<item`) && !strings.Contains(strings.TrimSpace(string(body)), `lastmod`) && !strings.Contains(strings.TrimSpace(string(body)), `lt`) {
			// 	//saveno_XMLToFile("no_autodiscover_config.xml", string(body), email_add)
			// } //记录错误格式的xml
			return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("failed to unmarshal XML: %v", err)
		}

		// 处理 redirectAddr 和 redirectUrl
		if autodiscoverResp.Response.Account.Action == "redirectAddr" {
			flag2 = flag2 + 1
			newEmail := autodiscoverResp.Response.Account.RedirectAddr
			//record_filename := filepath.Join("./autodiscover/records", "ReAddr.xml")
			//saveXMLToFile_with_ReAdrr_autodiscover(record_filename, string(body), email_add)
			if newEmail != "" && flag2 <= 10 {
				newflag1, newflag2, newflag3, nextRedirects, result, certinfo, err := getAutodiscoverConfig_try_norecord(origin_domain, uri, newEmail, method, index, flag1, flag2, flag3)
				return newflag1, newflag2, newflag3, append(redirects, nextRedirects...), result, certinfo, err
			} else if newEmail != "" { //12.27
				//saveXMLToFile_autodiscover("./flag2.xml", origin_domain, email_add)
				return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("too many RedirectAddr")
			} else {
				return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("nil ReAddr")
			}
		} else if autodiscoverResp.Response.Account.Action == "redirectUrl" {
			flag3 = flag3 + 1
			newUri := autodiscoverResp.Response.Account.RedirectUrl
			//record_filename := filepath.Join("./autodiscover/records", "Reurl.xml")
			//saveXMLToFile_with_Reuri_autodiscover(record_filename, string(body), email_add)
			if newUri != "" && flag3 <= 10 {
				newflag1, newflag2, newflag3, nextRedirects, result, certinfo, err := getAutodiscoverConfig_try_norecord(origin_domain, newUri, email_add, method, index, flag1, flag2, flag3)
				return newflag1, newflag2, newflag3, append(redirects, nextRedirects...), result, certinfo, err
			} else if newUri != "" {
				//saveXMLToFile_autodiscover("./flag3.xml", origin_domain, email_add)
				return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("too many RedirectUrl")
			} else {
				return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("nil Reuri")
			}
		} else if autodiscoverResp.Response.Account.Action == "settings" { //这才是我们需要的
			// 记录并返回成功配置(3.13修改，因为会将Response命名空间不合规的也解析到这里)
			//outputfile := fmt.Sprintf("./autodiscover/autodiscover_%s_%d_config.xml", method, index)
			//saveXMLToFile_autodiscover(outputfile, string(body), email_add)

			//只在可以直接返回xml配置的时候记录证书信息
			var certInfo CertInfo
			// 提取证书信息
			if resp.TLS != nil {
				var encodedData []byte
				goChain := resp.TLS.PeerCertificates
				endCert := goChain[0]

				// 证书验证
				dnsName := resp.Request.URL.Hostname()
				var VerifyError error
				certInfo.IsTrusted, VerifyError = verifyCertificate(goChain, dnsName)
				if VerifyError != nil {
					certInfo.VerifyError = VerifyError.Error()
				} else {
					certInfo.VerifyError = ""
				}

				certInfo.IsExpired = endCert.NotAfter.Before(time.Now())
				certInfo.IsHostnameMatch = verifyHostname(endCert, dnsName)
				certInfo.IsSelfSigned = IsSelfSigned(endCert)
				certInfo.IsInOrder = isChainInOrder(goChain)
				certInfo.TLSVersion = resp.TLS.Version

				// 提取证书的其他信息
				certInfo.Subject = endCert.Subject.CommonName
				certInfo.Issuer = endCert.Issuer.String()
				certInfo.SignatureAlg = endCert.SignatureAlgorithm.String()
				certInfo.AlgWarning = algWarnings(endCert)

				// 将证书编码为 base64 格式
				for _, cert := range goChain {
					encoded := base64.StdEncoding.EncodeToString(cert.Raw)
					encodedData = append(encodedData, []byte(encoded)...)
				}
				certInfo.RawCert = encodedData
			}
			return flag1, flag2, flag3, redirects, string(body), &certInfo, nil
		} else if autodiscoverResp.Response.Error != nil {
			//fmt.Printf("Error: %s\n", string(body))
			// 处理错误响应
			errorConfig := fmt.Sprintf("Errorcode:%d-%s\n", autodiscoverResp.Response.Error.ErrorCode, autodiscoverResp.Response.Error.Message)
			//outputfile := fmt.Sprintf("./autodiscover/autodiscover_%s_%d_Errorconfig.txt", method, index)
			//saveXMLToFile_autodiscover(outputfile, errorConfig, email_add)
			return flag1, flag2, flag3, redirects, errorConfig, nil, nil
		} else {
			//fmt.Printf("Response element not valid:%s\n", string(body))
			//处理Response可能本身就不正确的响应,同时也会存储不合规的xml(unmarshal的时候合规但Response不合规)
			alsoErrorConfig := fmt.Sprintf("Non-valid Response element for %s\n:", email_add)
			//outputfile := fmt.Sprintf("./autodiscover/autodiscover_%s_%d_AlsoErrorConfig.xml", method, index)
			//saveXMLToFile_autodiscover(outputfile, string(body), email_add)
			return flag1, flag2, flag3, redirects, alsoErrorConfig, nil, nil
		}
	} else {
		// 处理非成功响应
		//outputfile := fmt.Sprintf("./autodiscover/autodiscover_%s_%d_badresponse.txt", method, index)
		badResponse := fmt.Sprintf("Bad response for %s: %d\n", email_add, resp.StatusCode)
		//saveXMLToFile_autodiscover(outputfile, badResponse, email_add)
		return flag1, flag2, flag3, redirects, badResponse, nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
