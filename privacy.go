package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type UsernameStrategy int

const (
	Dict UsernameStrategy = iota
	Random
	Hybrid
)

func testAutodiscoverPOST(domain, email string, index int) AutodiscoverResult {
	// index对应post方法第几条
	var uri string = ""
	switch index {
	case 1:
		uri = fmt.Sprintf("http://%s/autodiscover/autodiscover.xml", domain)
	case 2:
		uri = fmt.Sprintf("https://autodiscover.%s/autodiscover/autodiscover.xml", domain)
	case 3:
		uri = fmt.Sprintf("http://autodiscover.%s/autodiscover/autodiscover.xml", domain)
	case 4:
		uri = fmt.Sprintf("https://%s/autodiscover/autodiscover.xml", domain)
	}
	flag1, flag2, flag3, redirects, config, certinfo, err := getAutodiscoverConfig_try_norecord(domain, uri, email, "post", index, 0, 0, 0)
	fmt.Printf("flag1: %d\n", flag1)
	fmt.Printf("flag2: %d\n", flag2)
	fmt.Printf("flag3: %d\n", flag3)

	result := AutodiscoverResult{
		Domain:    domain,
		Username:  email[:strings.Index(email, "@")], // 提取用户名
		Method:    "POST",
		Index:     index,
		URI:       uri,
		Redirects: redirects,
		Config:    config,
		CertInfo:  certinfo,
		//AutodiscoverCNAME: autodiscover_cnameRecords,
	}
	if err != nil {
		result.Error = err.Error()
	}
	return result

}

// func batchTestUsernames(domain string, numUsers, index int) []AutodiscoverResult {
// 	var allResults []AutodiscoverResult
// 	//usernames := generateRandomUsernames(numUsers)//
// 	usernames := generateUsernamesFromDict("privacy2/username.txt", 100)

// 	for _, username := range usernames {
// 		email := fmt.Sprintf("%s@%s", username, domain)
// 		result := testAutodiscoverPOST(domain, email, index)
// 		result.Username = username // 加入用户名字段，方便后续分析
// 		allResults = append(allResults, result)
// 	}
// 	return allResults
// }

// func check_dif_username() {
// 	// 打开汇总文件
// 	summaryFile, err := os.Create("privacy2/username_config_consistency_summary.txt") //
// 	if err != nil {
// 		fmt.Println("❌ Failed to create summary file:", err)
// 		return
// 	}
// 	defer summaryFile.Close()

// 	// // 从原始 XML 提取成功配置的域名
// 	successfulDomains, err := extractDomainsFromXML("/www/wwwroot/Golang/auto/autodiscover/autodiscover_post_1_config.xml")
// 	if err != nil {
// 		fmt.Println("❌ Error reading XML:", err)
// 		return
// 	}
// 	//successfulDomains := []string{"cock.li", "mailnesia.com", "go5pm.com", "careerride.com"}

// 	index := 1
// 	for _, domain := range successfulDomains {
// 		fmt.Printf("🔍 Testing domain: %s\n", domain)
// 		results := batchTestUsernames(domain, 1000, index)

// 		// 保存每个域名的 JSON 测试结果
// 		filename := fmt.Sprintf("privacy2/%s_post%d_variants.json", domain, index)
// 		saveResultsToJSON(filename, results)

// 		// 判断一致性
// 		var summary string
// 		if isConfigConsistent(results) {
// 			summary = fmt.Sprintf("✅ [%s] All configs are consistent across usernames\n", domain)
// 		} else {
// 			summary = fmt.Sprintf("⚠️ [%s] Inconsistencies found in config across usernames\n", domain)
// 		}

// 		fmt.Print(summary)

// 		// 写入汇总文件
// 		if _, err := summaryFile.WriteString(summary); err != nil {
// 			fmt.Println("❌ Failed to write to summary file:", err)
// 		}
// 	}
// }

// // 随机生成 num 个用户名
// func generateRandomUsernames(num int) []string {
// 	var usernames []string
// 	letters := []rune("abcdefghijklmnopqrstuvwxyz0123456789")
// 	prefixes := []string{"", "user", "test", "admin", "x"}

// 	rand.Seed(time.Now().UnixNano())

// 	for i := 0; i < num; i++ {
// 		// 生成用户名长度（3~12）
// 		length := rand.Intn(10) + 3
// 		var username []rune
// 		for j := 0; j < length; j++ {
// 			username = append(username, letters[rand.Intn(len(letters))])
// 		}

// 		// 随机决定是否添加前缀（50% 概率）
// 		prefix := prefixes[rand.Intn(len(prefixes))]
// 		if prefix != "" && rand.Float64() < 0.5 {
// 			usernames = append(usernames, prefix+string(username))
// 		} else {
// 			usernames = append(usernames, string(username))
// 		}
// 	}
// 	return usernames
// }

// func loadUsernamesFromFile(path string) ([]string, error) {
// 	file, err := os.Open(path)
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer file.Close()

// 	var usernames []string
// 	scanner := bufio.NewScanner(file)
// 	for scanner.Scan() {
// 		line := scanner.Text()
// 		if line != "" {
// 			usernames = append(usernames, line)
// 		}
// 	}

// 	if err := scanner.Err(); err != nil {
// 		return nil, err
// 	}
// 	return usernames, nil
// }
// func generateUsernamesFromDict(dictPath string, num int) []string {
// 	allUsernames, err := loadUsernamesFromFile(dictPath)
// 	if err != nil {
// 		log.Fatalf("Failed to load usernames from file: %v", err)
// 	}

// 	// rand.Seed(time.Now().UnixNano())
// 	// var selected []string
// 	// for i := 0; i < num; i++ {
// 	// 	//selected = append(selected, allUsernames[rand.Intn(len(allUsernames))])

// 	// }
// 	// return selected
// 	return allUsernames
// }

// 支持三种策略的用户名测试入口
func batchTestUsernames(domain string, numUsers, index int, strategy UsernameStrategy) []AutodiscoverResult {
	var allResults []AutodiscoverResult
	var usernames []string

	switch strategy {
	case Dict:
		usernames = generateUsernamesFromDict("privacy2/username.txt", numUsers)
	case Random:
		usernames = generateRandomUsernames(numUsers)
	case Hybrid:
		dict := generateUsernamesFromDict("privacy2/username.txt", numUsers)
		usernames = generateHybridUsernames(dict, numUsers)
	}

	for _, username := range usernames {
		email := fmt.Sprintf("%s@%s", username, domain)
		result := testAutodiscoverPOST(domain, email, index)
		result.Username = username
		allResults = append(allResults, result)
	}
	return allResults
}

// 主控函数
func check_dif_username() {
	summaryFile, err := os.Create("privacypost2/username_config_consistency_summary_post2.txt") //4.27
	if err != nil {
		fmt.Println("❌ Failed to create summary file:", err)
		return
	}
	defer summaryFile.Close()

	successfulDomains, err := extractDomainsFromXML("/www/wwwroot/Golang/auto/autodiscover/autodiscover_post_2_config.xml")
	//successfulDomains := []string{"mailfence.com"}
	if err != nil {
		fmt.Println("❌ Error reading XML:", err)
		return
	}

	index := 2
	for _, domain := range successfulDomains {
		for _, strategy := range []UsernameStrategy{Dict, Random, Hybrid} {
			fmt.Printf("🔍 Testing domain: %s [strategy %d]\n", domain, strategy)
			results := batchTestUsernames(domain, 200, index, strategy)

			strategyName := map[UsernameStrategy]string{
				Dict:   "dict",
				Random: "random",
				Hybrid: "hybrid",
			}[strategy]

			filename := fmt.Sprintf("privacypost2/%s_post%d_variants_%s_sub.json", domain, index, strategyName)
			saveResultsToJSON(filename, results)

			var summary string
			if isConfigConsistent(results) {
				summary = fmt.Sprintf("✅ [%s][%s] All configs are consistent across usernames\n", domain, strategyName)
			} else {
				summary = fmt.Sprintf("⚠️ [%s][%s] Inconsistencies found in config across usernames\n", domain, strategyName)
			}
			fmt.Print(summary)
			summaryFile.WriteString(summary)
		}
	}

	summaryFile, err = os.Create("privacypost3/username_config_consistency_summary_post3.txt") //4.29
	if err != nil {
		fmt.Println("❌ Failed to create summary file:", err)
		return
	}
	defer summaryFile.Close()

	successfulDomains, err = extractDomainsFromXML("/www/wwwroot/Golang/auto/autodiscover/autodiscover_post_3_config.xml")
	if err != nil {
		fmt.Println("❌ Error reading XML:", err)
		return
	}

	index = 3
	for _, domain := range successfulDomains {
		for _, strategy := range []UsernameStrategy{Dict, Random, Hybrid} {
			fmt.Printf("🔍 Testing domain: %s [strategy %d]\n", domain, strategy)
			results := batchTestUsernames(domain, 200, index, strategy)

			strategyName := map[UsernameStrategy]string{
				Dict:   "dict",
				Random: "random",
				Hybrid: "hybrid",
			}[strategy]

			filename := fmt.Sprintf("privacypost3/%s_post%d_variants_%s_sub.json", domain, index, strategyName)
			saveResultsToJSON(filename, results)

			var summary string
			if isConfigConsistent(results) {
				summary = fmt.Sprintf("✅ [%s][%s] All configs are consistent across usernames\n", domain, strategyName)
			} else {
				summary = fmt.Sprintf("⚠️ [%s][%s] Inconsistencies found in config across usernames\n", domain, strategyName)
			}
			fmt.Print(summary)
			summaryFile.WriteString(summary)
		}
	}

	summaryFile, err = os.Create("privacypost4/username_config_consistency_summary_post4.txt") //4.27
	if err != nil {
		fmt.Println("❌ Failed to create summary file:", err)
		return
	}
	defer summaryFile.Close()

	successfulDomains, err = extractDomainsFromXML("/www/wwwroot/Golang/auto/autodiscover/autodiscover_post_4_config.xml")
	if err != nil {
		fmt.Println("❌ Error reading XML:", err)
		return
	}

	index = 4
	for _, domain := range successfulDomains {
		for _, strategy := range []UsernameStrategy{Dict, Random, Hybrid} {
			fmt.Printf("🔍 Testing domain: %s [strategy %d]\n", domain, strategy)
			results := batchTestUsernames(domain, 200, index, strategy)

			strategyName := map[UsernameStrategy]string{
				Dict:   "dict",
				Random: "random",
				Hybrid: "hybrid",
			}[strategy]

			filename := fmt.Sprintf("privacypost4/%s_post%d_variants_%s_sub.json", domain, index, strategyName)
			saveResultsToJSON(filename, results)

			var summary string
			if isConfigConsistent(results) {
				summary = fmt.Sprintf("✅ [%s][%s] All configs are consistent across usernames\n", domain, strategyName)
			} else {
				summary = fmt.Sprintf("⚠️ [%s][%s] Inconsistencies found in config across usernames\n", domain, strategyName)
			}
			fmt.Print(summary)
			summaryFile.WriteString(summary)
		}
	}

}

// 生成随机用户名
func generateRandomUsernames(num int) []string {
	letters := []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	prefixes := []string{"", "user", "test", "admin", "x"}

	rand.Seed(time.Now().UnixNano())
	var usernames []string

	for i := 0; i < num; i++ {
		length := rand.Intn(10) + 3
		var username []rune
		for j := 0; j < length; j++ {
			username = append(username, letters[rand.Intn(len(letters))])
		}
		prefix := prefixes[rand.Intn(len(prefixes))]
		if prefix != "" && rand.Float64() < 0.5 {
			usernames = append(usernames, prefix+string(username))
		} else {
			usernames = append(usernames, string(username))
		}
	}
	return usernames
}

// 从字典中加载用户名
func loadUsernamesFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var usernames []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			usernames = append(usernames, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return usernames, nil
}

// 字典选取
func generateUsernamesFromDict(dictPath string, num int) []string {
	allUsernames, err := loadUsernamesFromFile(dictPath)
	if err != nil {
		log.Fatalf("Failed to load usernames from file: %v", err)
	}
	if len(allUsernames) > num {
		rand.Shuffle(len(allUsernames), func(i, j int) {
			allUsernames[i], allUsernames[j] = allUsernames[j], allUsernames[i]
		})
		return allUsernames[:num]
	}
	return allUsernames
}

// Hybrid 模式：字典+随机后缀
func generateHybridUsernames(dict []string, num int) []string {
	letters := []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	rand.Seed(time.Now().UnixNano())
	var hybrid []string

	for i := 0; i < num; i++ {
		base := dict[rand.Intn(len(dict))]
		suffixLen := rand.Intn(4) + 2
		var suffix []rune
		for j := 0; j < suffixLen; j++ {
			suffix = append(suffix, letters[rand.Intn(len(letters))])
		}
		hybrid = append(hybrid, base+string(suffix))
	}
	return hybrid
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

// 保存结果为 JSON 文件
func saveResultsToJSON(filename string, results []AutodiscoverResult) {
	f, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	err = enc.Encode(results)
	if err != nil {
		fmt.Println("Error encoding JSON:", err)
	}
}

// 比较所有 Config 是否一致
func isConfigConsistent(results []AutodiscoverResult) bool {
	if len(results) == 0 {
		return true
	}

	var configs []*MethodConfig
	for _, r := range results {
		if r.Config == "" {
			continue
		}
		cfg, err := parseXMLConfig_Autodiscover(r.Config)
		if err != nil {
			log.Printf("Failed to parse config for %s: %v", r.Username, err)
			continue
		}
		configs = append(configs, cfg) //这里是整个.json文件的[]config
	}
	// if len(configs) != len(results) && len(configs) != 0 { //说明有的不能解析
	// 	return false
	// } //4.27
	fmt.Printf("Processing domain: %s\n", results[0].Domain) //
	consistent, _ := compareMethodConfigs_autodiscover(configs)
	return consistent
}

func extractDomainsFromXML(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var domains []string
	seen := make(map[string]bool)
	re := regexp.MustCompile(`<!--\s*Config for email address:\s*[^@]+@([^>\s]+)\s*-->`)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		matches := re.FindStringSubmatch(line)
		if len(matches) == 2 {
			domain := strings.ToLower(matches[1])
			if !seen[domain] {
				seen[domain] = true
				domains = append(domains, domain)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return domains, nil
}
