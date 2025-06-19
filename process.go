package main

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/zakjan/cert-chain-resolver/certUtil"
	"golang.org/x/net/publicsuffix"
)

var semaphore = make(chan struct{}, 200)

var (
	//msg       = new(dns.Msg)
	dnsServer = "8.8.8.8:53"
	//client    = new(dns.Client)
)

// var fileMutex sync.Mutex
var fileLocks sync.Map //存储每个文件的锁

type DomainResult struct {
	Domain_id     int                  `json:"id"`
	Domain        string               `json:"domain"`
	CNAME         []string             `json:"cname,omitempty"`
	Autodiscover  []AutodiscoverResult `json:"autodiscover"`
	Autoconfig    []AutoconfigResult   `json:"autoconfig"`
	SRV           SRVResult            `json:"srv"`
	Timestamp     string               `json:"timestamp"`
	ErrorMessages []string             `json:"errors"`
}

type AutoconfigResponse struct {
	XMLName xml.Name `xml:"clientConfig"`
}

type AutodiscoverResponse struct {
	XMLName  xml.Name `xml:"http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006 Autodiscover"`
	Response Response `xml:"http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a Response"`
}

type Response struct {
	XMLName xml.Name `xml:"Response"`
	User    User     `xml:"User"`
	Account Account  `xml:"Account"`
	Error   *Error   `xml:"Error,omitempty"`
}

type User struct {
	AutoDiscoverSMTPAddress string `xml:"AutoDiscoverSMTPAddress"`
	DisplayName             string `xml:"DisplayName"`
	LegacyDN                string `xml:"LegacyDN"`
	DeploymentId            string `xml:"DeploymentId"`
}

type Account struct {
	XMLName         xml.Name `xml:"Account"`
	AccountType     string   `xml:"AccountType"`
	Action          string   `xml:"Action"`
	MicrosoftOnline string   `xml:"MicrosoftOnline"`
	ConsumerMailbox string   `xml:"ConsumerMailbox"`
	Protocol        Protocol `xml:"Protocol"`
	RedirectAddr    string   `xml:"RedirectAddr"`
	RedirectUrl     string   `xml:"RedirectUrl"`
}

type Protocol struct{}

type Error struct {
	XMLName   xml.Name `xml:"Error"`
	Time      string   `xml:"Time,attr"`
	Id        string   `xml:"Id,attr"`
	DebugData string   `xml:"DebugData"`
	ErrorCode int      `xml:"ErrorCode"`
	Message   string   `xml:"Message"`
}

type CertInfo struct {
	IsTrusted       bool
	VerifyError     string
	IsHostnameMatch bool
	IsInOrder       string
	IsExpired       bool
	IsSelfSigned    bool
	SignatureAlg    string
	AlgWarning      string
	TLSVersion      uint16
	Subject         string
	Issuer          string
	RawCert         []byte
}

// AutodiscoverResult 保存每次Autodiscover查询的结果
type AutodiscoverResult struct {
	Domain            string                   `json:"domain"`
	AutodiscoverCNAME []string                 `json:"autodiscovercname,omitempty"`
	Method            string                   `json:"method"` // 查询方法，如 POST, GET, SRV
	Index             int                      `json:"index"`
	URI               string                   `json:"uri"`       // 查询的 URI
	Redirects         []map[string]interface{} `json:"redirects"` // 重定向链
	Config            string                   `json:"config"`    // 配置信息
	CertInfo          *CertInfo                `json:"cert_info"`
	Error             string                   `json:"error"` // 错误信息（如果有）
}

// AutoconfigResult 保存每次Autoconfig查询的结果
type AutoconfigResult struct {
	Domain    string                   `json:"domain"`
	Method    string                   `json:"method"`
	Index     int                      `json:"index"`
	URI       string                   `json:"uri"`
	Redirects []map[string]interface{} `json:"redirects"`
	Config    string                   `json:"config"`
	CertInfo  *CertInfo                `json:"cert_info"`
	Error     string                   `json:"error"`
}

type SRVRecord struct {
	Service  string
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

type DNSRecord struct {
	Domain      string `json:"domain"`
	SOA         string `json:"SOA,omitempty"`
	NS          string `json:"NS,omitempty"`
	ADbit_imap  *bool  `json:"ADbit_imap,omitempty"`
	ADbit_imaps *bool  `json:"ADbit_imaps,omitempty"`
	ADbit_pop3  *bool  `json:"ADbit_pop3,omitempty"`
	ADbit_pop3s *bool  `json:"ADbit_pop3s,omitempty"`
	ADbit_smtp  *bool  `json:"ADbit_smtp,omitempty"`
	ADbit_smtps *bool  `json:"ADbit_smtps,omitempty"`
}

type SRVResult struct {
	Domain      string      `json:"domain"`
	RecvRecords []SRVRecord `json:"recv_records,omitempty"` // 收件服务 (IMAP/POP3)
	SendRecords []SRVRecord `json:"send_records,omitempty"` // 发件服务 (SMTP)
	DNSRecord   *DNSRecord  `json:"dns_record,omitempty"`
}

/*
func main() {
	var wg sync.WaitGroup
	var results []DomainResult
	//domains := []string{"yahoo.com", "yandex.ru", "zohu.com"}
	fileName := "results3.json"
	csvFile := "tranco_V9KQN.csv"
	domains, err := fetchDomainsFromCSV(csvFile, 0, 100) // 设置需要读取的行范围(,]
	if err != nil {
		fmt.Printf("Failed to fetch domains from CSV: %v\n", err)
		return
	}
	var resultsMutex sync.Mutex
	for _, domain := range domains {
		wg.Add(1)
		semaphore <- struct{}{} // 占用一个信号量
		go func(domain string) {
			defer wg.Done()
			defer func() { <-semaphore }() // 释放信号量
			domainResult := processDomain(domain)
			resultsMutex.Lock()
			results = append(results, domainResult)
			resultsMutex.Unlock()
		}(domain)
	}
	wg.Wait()

	// 将结果转换为 JSON
	output, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling results: %v\n", err)
		return
	}

	// 检查文件是否存在
	fileExists := false
	if _, err := os.Stat(fileName); err == nil {
		fileExists = true
	} else if !os.IsNotExist(err) {
		// 如果是其他错误，提示用户并退出
		fmt.Printf("Error checking file: %v\n", err)
		return
	}

	// 获取与文件名对应的锁
	lock := getFileLock(fileName)
	lock.Lock()
	defer lock.Unlock()

	var file *os.File
	if fileExists {
		// 如果文件已存在，追加模式打开
		file, err = os.OpenFile(fileName, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Printf("Error opening file for append: %v\n", err)
			return
		}
		// 去掉 JSON 的开头和结尾方括号
		output = output[1 : len(output)-1]
		_, err = file.WriteString(",\n" + string(output))
	} else {
		// 如果文件不存在，创建新文件
		file, err = os.Create(fileName)
		if err != nil {
			fmt.Printf("Error creating file: %v\n", err)
			return
		}
		_, err = file.WriteString("[\n" + string(output) + "\n]")
	}
	if err != nil {
		fmt.Printf("Error writing to file: %v\n", err)
		return
	}
	file.Close()

	fmt.Printf("Results successfully saved to %s\n", fileName)
}
*/

func process() { //func main()
	var wg sync.WaitGroup
	fileName := "init1.json"
	csvFile := "tranco_V9KQN.csv"
	domains, err := fetchDomainsFromCSV(csvFile, 0, 1000000) // 设置需要读取的行范围
	if err != nil {
		fmt.Printf("Failed to fetch domains from CSV: %v\n", err)
		return
	}

	// 批次大小
	batchSize := 1000
	var currentBatch []DomainResult
	var resultsMutex sync.Mutex

	// 初始化文件，写入开头的 `[`
	err = initializeJSONFile(fileName)
	if err != nil {
		fmt.Printf("Error initializing JSON file: %v\n", err)
		return
	}

	for index, domain := range domains {
		wg.Add(1)
		semaphore <- struct{}{} // 占用一个信号量

		go func(domain string, index int) {
			defer wg.Done()
			defer func() { <-semaphore }() // 释放信号量

			// 处理域名获取结果
			domainResult := processDomain(domain)
			domainResult.Domain_id = index + 1

			// 将结果添加到当前批次
			resultsMutex.Lock()
			currentBatch = append(currentBatch, domainResult)

			// 如果达到批次大小，写入文件并清空当前批次
			if len(currentBatch) >= batchSize {
				if err := appendResultsToFile(fileName, currentBatch); err != nil {
					fmt.Printf("Error writing batch to file: %v\n", err)
				}
				currentBatch = []DomainResult{}
			}
			resultsMutex.Unlock()
		}(domain, index)
	}

	// 等待所有协程完成
	wg.Wait()

	// 写入剩余的结果
	if len(currentBatch) > 0 {
		if err := appendResultsToFile(fileName, currentBatch); err != nil {
			fmt.Printf("Error writing last batch to file: %v\n", err)
		}
	}

	removeTrailingCommaAndAddClosingBracket(fileName)

	fmt.Printf("Results successfully saved to %s\n", fileName)
}
func removeTrailingCommaAndAddClosingBracket(fileName string) error {
	// 执行删除最后一行中的逗号
	cmd1 := exec.Command("sed", "-i", "$s/,$//", fileName)
	err := cmd1.Run()
	if err != nil {
		return fmt.Errorf("error executing sed command 1: %v", err)
	}

	// 执行在文件最后添加 `]`
	cmd2 := exec.Command("sed", "-i", "-e", "$a ]", fileName)
	err = cmd2.Run()
	if err != nil {
		return fmt.Errorf("error executing sed command 2: %v", err)
	}

	return nil
}

func initializeJSONFile(fileName string) error {
	lock := getFileLock(fileName)
	lock.Lock()
	defer lock.Unlock()

	file, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("error creating file: %v", err)
	}
	defer file.Close()

	_, err = file.WriteString("[\n")
	if err != nil {
		return fmt.Errorf("error writing file start: %v", err)
	}
	return nil
}
func appendResultsToFile(fileName string, results []DomainResult) error {
	lock := getFileLock(fileName)
	lock.Lock()
	defer lock.Unlock()

	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("error opening file for append: %v", err)
	}
	defer file.Close()

	output, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling results: %v", err)
	}
	output[len(output)-2] = ','        //
	output = output[1 : len(output)-1] // 移除数组的首尾方括号

	// 写入数据
	_, err = file.WriteString(string(output) + "\n")
	if err != nil {
		return fmt.Errorf("error writing to file: %v", err)
	}
	return nil
}

// 获取文件锁
func getFileLock(filename string) *sync.Mutex {
	lock, _ := fileLocks.LoadOrStore(filename, &sync.Mutex{})
	return lock.(*sync.Mutex)
}

func fetchDomainsFromCSV(filename string, start int, end int) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	var domains []string

	lineIndex := 0
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("failed to read CSV file: %v", err)
		}

		// 判断是否在指定范围内
		if lineIndex >= start && lineIndex < end {
			if len(record) > 1 { // 确保存在第二列
				domain := strings.TrimSpace(record[1])
				if domain != "" {
					domains = append(domains, domain)
				}
			}
		}

		lineIndex++
	}

	return domains, nil
}

// 处理单个域名
func processDomain(domain string) DomainResult {
	domainResult := DomainResult{
		Domain:        domain,
		Timestamp:     time.Now().Format(time.RFC3339),
		ErrorMessages: []string{},
	}
	//处理每个域名的一开始就查询CNAME字段
	cnameRecords, err := lookupCNAME(domain)
	if err != nil {
		domainResult.ErrorMessages = append(domainResult.ErrorMessages, fmt.Sprintf("CNAME lookup error: %v", err))
	}
	domainResult.CNAME = cnameRecords

	// Autodiscover 查询

	autodiscoverResults := queryAutodiscover(domain)
	domainResult.Autodiscover = autodiscoverResults

	// Autoconfig 查询
	autoconfigResults := queryAutoconfig(domain)
	domainResult.Autoconfig = autoconfigResults

	// SRV 查询
	srvconfigResults := querySRV(domain)
	domainResult.SRV = srvconfigResults

	return domainResult
}

// 查询CNAME部分
func lookupCNAME(domain string) ([]string, error) {
	resolverAddr := "8.8.8.8:53" // Google Public DNS
	timeout := 5 * time.Second   // Timeout for DNS query

	client := &dns.Client{
		Net:     "udp",
		Timeout: timeout,
	}

	var lastErr error
	for i := 0; i < 3; i++ {
		m := dns.Msg{}
		m.SetQuestion(dns.Fqdn(domain), dns.TypeA) // 查询 A 记录
		r, _, err := client.Exchange(&m, resolverAddr)
		if err != nil {
			lastErr = err
			time.Sleep(1 * time.Second * time.Duration(i+1))
			continue
		}

		var dst []string
		for _, ans := range r.Answer {
			if record, ok := ans.(*dns.CNAME); ok {
				dst = append(dst, record.Target)
			}
		}

		if len(dst) > 0 {
			return dst, nil // 如果找到结果，立即返回
		}

		lastErr = nil
		break
	}

	return nil, lastErr
}

// 查询Autodiscover部分
func queryAutodiscover(domain string) []AutodiscoverResult {
	var results []AutodiscoverResult
	email := fmt.Sprintf("info@%s", domain)
	//查询autodiscover.example.com的cname记录
	autodiscover_prefixadd := "autodiscover." + domain
	autodiscover_cnameRecords, _ := lookupCNAME(autodiscover_prefixadd)
	// method1:直接通过text manipulation，直接发出post请求
	uris := []string{
		fmt.Sprintf("http://%s/autodiscover/autodiscover.xml", domain),
		fmt.Sprintf("https://autodiscover.%s/autodiscover/autodiscover.xml", domain),
		fmt.Sprintf("http://autodiscover.%s/autodiscover/autodiscover.xml", domain),
		fmt.Sprintf("https://%s/autodiscover/autodiscover.xml", domain),
	}
	for i, uri := range uris {
		index := i + 1
		flag1, flag2, flag3, redirects, config, certinfo, err := getAutodiscoverConfig(domain, uri, email, "post", index, 0, 0, 0) //getAutodiscoverConfig照常
		fmt.Printf("flag1: %d\n", flag1)
		fmt.Printf("flag2: %d\n", flag2)
		fmt.Printf("flag3: %d\n", flag3)

		result := AutodiscoverResult{
			Domain:            domain,
			Method:            "POST",
			Index:             index,
			URI:               uri,
			Redirects:         redirects,
			Config:            config,
			CertInfo:          certinfo,
			AutodiscoverCNAME: autodiscover_cnameRecords,
		}
		if err != nil {
			result.Error = err.Error()
		}
		results = append(results, result)
	}

	//method2:通过dns找到server,再post请求
	service := "_autodiscover._tcp." + domain
	uriDNS, adBit, err := lookupSRVWithAD_autodiscover(domain) //
	if err != nil {
		result_srv := AutodiscoverResult{
			Domain: domain,
			Method: "srv-post",
			Index:  0,
			Error:  fmt.Sprintf("Failed to lookup SRV records for %s: %v", service, err),
		}
		results = append(results, result_srv)
	} else {
		record_ADbit_SRV_autodiscover("autodiscover_record_ad_srv.txt", domain, adBit)
		_, _, _, redirects, config, certinfo, err1 := getAutodiscoverConfig(domain, uriDNS, email, "srv-post", 0, 0, 0, 0)
		result_srv := AutodiscoverResult{
			Domain:            domain,
			Method:            "srv-post",
			Index:             0,
			Redirects:         redirects,
			Config:            config,
			CertInfo:          certinfo,
			AutodiscoverCNAME: autodiscover_cnameRecords,
		}
		if err1 != nil {
			result_srv.Error = err1.Error()
		}
		results = append(results, result_srv)
	}

	//method3：先GET找到server，再post请求
	getURI := fmt.Sprintf("http://autodiscover.%s/autodiscover/autodiscover.xml", domain) //是通过这个getURI得到server的uri，然后再进行post请求10.26
	redirects, config, certinfo, err := GET_AutodiscoverConfig(domain, getURI, email)     //一开始的get请求返回的不是重定向的没有管
	result_GET := AutodiscoverResult{
		Domain:            domain,
		Method:            "get-post",
		Index:             0,
		URI:               getURI,
		Redirects:         redirects,
		Config:            config,
		CertInfo:          certinfo,
		AutodiscoverCNAME: autodiscover_cnameRecords,
	}
	if err != nil {
		result_GET.Error = err.Error()
	} //TODO:len(redirect)>0?
	results = append(results, result_GET)

	//method4:增加几条直接GET请求的路径
	direct_getURIs := []string{
		fmt.Sprintf("http://%s/autodiscover/autodiscover.xml", domain),               //uri1
		fmt.Sprintf("https://autodiscover.%s/autodiscover/autodiscover.xml", domain), //2
		fmt.Sprintf("http://autodiscover.%s/autodiscover/autodiscover.xml", domain),  //3
		fmt.Sprintf("https://%s/autodiscover/autodiscover.xml", domain),              //4
	}
	for i, direct_getURI := range direct_getURIs {
		index := i + 1
		_, _, _, redirects, config, certinfo, err := direct_GET_AutodiscoverConfig(domain, direct_getURI, email, "get", index, 0, 0, 0)
		result := AutodiscoverResult{
			Domain:            domain,
			Method:            "direct_get",
			Index:             index,
			URI:               direct_getURI,
			Redirects:         redirects,
			Config:            config,
			CertInfo:          certinfo,
			AutodiscoverCNAME: autodiscover_cnameRecords,
		}
		if err != nil {
			result.Error = err.Error()
		}
		results = append(results, result)
	}

	return results
}

func getAutodiscoverConfig(origin_domain string, uri string, email_add string, method string, index int, flag1 int, flag2 int, flag3 int) (int, int, int, []map[string]interface{}, string, *CertInfo, error) {
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
			saveXMLToFile_autodiscover("./location.xml", origin_domain, email_add)
			return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("too many redirect times")
		}

		newURI, err := url.Parse(location)
		if err != nil {
			return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("failed to parse redirect URL: %s", location)
		}

		// 递归调用并合并重定向链
		newflag1, newflag2, newflag3, nextRedirects, result, certinfo, err := getAutodiscoverConfig(origin_domain, newURI.String(), email_add, method, index, flag1, flag2, flag3)
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
		if err != nil {
			// if (strings.HasPrefix(strings.TrimSpace(string(body)), `<?xml version="1.0"`) || strings.HasPrefix(strings.TrimSpace(string(body)), `<Autodiscover`)) && !strings.Contains(strings.TrimSpace(string(body)), `<html`) && !strings.Contains(strings.TrimSpace(string(body)), `<item`) && !strings.Contains(strings.TrimSpace(string(body)), `lastmod`) && !strings.Contains(strings.TrimSpace(string(body)), `lt`) {
			if !strings.Contains(strings.TrimSpace(string(body)), `<html`) && !strings.Contains(strings.TrimSpace(string(body)), `<item`) && !strings.Contains(strings.TrimSpace(string(body)), `lastmod`) && !strings.Contains(strings.TrimSpace(string(body)), `lt`) {
				saveno_XMLToFile("no_autodiscover_config.xml", string(body), email_add)
			} //记录错误格式的xml
			return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("failed to unmarshal XML: %v", err)
		}

		// 处理 redirectAddr 和 redirectUrl
		if autodiscoverResp.Response.Account.Action == "redirectAddr" {
			flag2 = flag2 + 1
			newEmail := autodiscoverResp.Response.Account.RedirectAddr
			record_filename := filepath.Join("./autodiscover/records", "ReAddr.xml")
			saveXMLToFile_with_ReAdrr_autodiscover(record_filename, string(body), email_add)
			if newEmail != "" && flag2 <= 10 {
				newflag1, newflag2, newflag3, nextRedirects, result, err, certinfo := getAutodiscoverConfig(origin_domain, uri, newEmail, method, index, flag1, flag2, flag3)
				return newflag1, newflag2, newflag3, append(redirects, nextRedirects...), result, err, certinfo
			} else if newEmail != "" { //12.27
				saveXMLToFile_autodiscover("./flag2.xml", origin_domain, email_add)
				return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("too many RedirectAddr")
			} else {
				return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("nil ReAddr")
			}
		} else if autodiscoverResp.Response.Account.Action == "redirectUrl" {
			flag3 = flag3 + 1
			newUri := autodiscoverResp.Response.Account.RedirectUrl
			record_filename := filepath.Join("./autodiscover/records", "Reurl.xml")
			saveXMLToFile_with_Reuri_autodiscover(record_filename, string(body), email_add)
			if newUri != "" && flag3 <= 10 {
				newflag1, newflag2, newflag3, nextRedirects, result, err, certinfo := getAutodiscoverConfig(origin_domain, newUri, email_add, method, index, flag1, flag2, flag3)
				return newflag1, newflag2, newflag3, append(redirects, nextRedirects...), result, err, certinfo
			} else if newUri != "" {
				saveXMLToFile_autodiscover("./flag3.xml", origin_domain, email_add)
				return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("too many RedirectUrl")
			} else {
				return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("nil Reuri")
			}
		} else if autodiscoverResp.Response.Error != nil {
			// 处理错误响应
			errorConfig := fmt.Sprintf("Errorcode:%d-%s\n", autodiscoverResp.Response.Error.ErrorCode, autodiscoverResp.Response.Error.Message)
			outputfile := fmt.Sprintf("./autodiscover/autodiscover_%s_%d_Errorconfig.txt", method, index)
			saveXMLToFile_autodiscover(outputfile, errorConfig, email_add)
			return flag1, flag2, flag3, redirects, errorConfig, nil, nil
		} else {
			// 记录并返回成功配置
			outputfile := fmt.Sprintf("./autodiscover/autodiscover_%s_%d_config.xml", method, index)
			saveXMLToFile_autodiscover(outputfile, string(body), email_add)

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
		}
	} else {
		// 处理非成功响应
		//outputfile := fmt.Sprintf("./autodiscover/autodiscover_%s_%d_badresponse.txt", method, index)
		badResponse := fmt.Sprintf("Bad response for %s: %d\n", email_add, resp.StatusCode)
		//saveXMLToFile_autodiscover(outputfile, badResponse, email_add)
		return flag1, flag2, flag3, redirects, badResponse, nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

func GET_AutodiscoverConfig(origin_domain string, uri string, email_add string) ([]map[string]interface{}, string, *CertInfo, error) { //使用先get后post方法
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
	resp, err := client.Get(uri)
	if err != nil {
		return []map[string]interface{}{}, "", nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	redirects := getRedirects(resp) // 获取当前重定向链

	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently { //仅通过get请求获取重定向地址
		location := resp.Header.Get("Location")
		fmt.Printf("Redirect to: %s\n", location)
		if location == "" {
			return nil, "", nil, fmt.Errorf("missing Location header in redirect")
		}
		newURI, err := url.Parse(location)
		if err != nil {
			return nil, "", nil, fmt.Errorf("failed to parse redirect URL: %s", location)
		}

		// 递归调用并合并重定向链
		_, _, _, nextRedirects, result, certinfo, err := getAutodiscoverConfig(origin_domain, newURI.String(), email_add, "get_post", 0, 0, 0, 0)
		return append(redirects, nextRedirects...), result, certinfo, err
	} else {
		return nil, "", nil, fmt.Errorf("not find Redirect Statuscode")
	}
}

func direct_GET_AutodiscoverConfig(origin_domain string, uri string, email_add string, method string, index int, flag1 int, flag2 int, flag3 int) (int, int, int, []map[string]interface{}, string, *CertInfo, error) { //一路get请求
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
		Timeout: 15 * time.Second, // 设置请求超时时间
	}
	resp, err := client.Get(uri)
	if err != nil {
		return flag1, flag2, flag3, []map[string]interface{}{}, "", nil, fmt.Errorf("failed to send request: %v", err)
	}

	redirects := getRedirects(resp)
	defer resp.Body.Close() //

	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		flag1 = flag1 + 1
		location := resp.Header.Get("Location")
		fmt.Printf("Redirect to: %s\n", location)
		if location == "" {
			return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("missing Location header in redirect")
		} else if flag1 > 10 {
			saveXMLToFile_autodiscover("./location2.xml", origin_domain, email_add)
			return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("too many redirect times")
		}

		newURI, err := url.Parse(location)
		if err != nil {
			return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("failed to parse redirect URL: %s", location)
		}

		// 递归调用并合并重定向链
		newflag1, newflag2, newflag3, nextRedirects, result, certinfo, err := direct_GET_AutodiscoverConfig(origin_domain, newURI.String(), email_add, method, index, flag1, flag2, flag3)
		return newflag1, newflag2, newflag3, append(redirects, nextRedirects...), result, certinfo, err
	} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("failed to read response body: %v", err)
		}
		var autodiscoverResp AutodiscoverResponse
		err = xml.Unmarshal(body, &autodiscoverResp)
		if err != nil {
			return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("failed to unmarshal XML: %v", err)
		}
		if autodiscoverResp.Response.Account.Action == "redirectAddr" {
			flag2 = flag2 + 1
			newEmail := autodiscoverResp.Response.Account.RedirectAddr
			outputfile := fmt.Sprintf("./autodiscover/autodiscover_%s_%d_redirectAddr_config.xml", method, index)
			saveXMLToFile_autodiscover(outputfile, string(body), email_add)
			if newEmail != "" {
				return flag1, flag2, flag3, redirects, string(body), nil, nil //TODO, 这里直接返回带redirect_email了
			} else {
				return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("nil ReAddr")
			}
		} else if autodiscoverResp.Response.Account.Action == "redirectUrl" {
			flag3 = flag3 + 1
			newUri := autodiscoverResp.Response.Account.RedirectUrl
			record_filename := filepath.Join("./autodiscover/records", "Reurl_dirGET.xml")
			saveXMLToFile_with_Reuri_autodiscover(record_filename, string(body), email_add) //记录redirecturi,是否会出现继续reUri?
			if newUri != "" && flag3 <= 10 {
				newflag1, newflag2, newflag3, nextRedirects, result, certinfo, err := direct_GET_AutodiscoverConfig(origin_domain, newUri, email_add, method, index, flag1, flag2, flag3)
				return newflag1, newflag2, newflag3, append(redirects, nextRedirects...), result, certinfo, err
			} else if newUri != "" {
				saveXMLToFile_autodiscover("./flag32.xml", origin_domain, email_add)
				return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("too many RedirectUrl")
			} else {
				return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("nil Reurl")
			}
		} else if autodiscoverResp.Response.Error != nil {
			Errorconfig := fmt.Sprintf("Errorcode:%d-%s\n", autodiscoverResp.Response.Error.ErrorCode, autodiscoverResp.Response.Error.Message)
			outputfile := fmt.Sprintf("./autodiscover/autodiscover_%s_%d_Errorconfig.txt", method, index)
			saveXMLToFile_autodiscover(outputfile, Errorconfig, email_add) //直接保存了
			return flag1, flag2, flag3, redirects, Errorconfig, nil, nil
		} else {
			outputfile := fmt.Sprintf("./autodiscover/autodiscover_%s_%d_config.xml", method, index)
			saveXMLToFile_autodiscover(outputfile, string(body), email_add)
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
		}
	} else {
		//outputfile := fmt.Sprintf("./autodiscover/autodiscover_%s_%d_badresponse.txt", method, index)
		bad_response := fmt.Sprintf("Bad response for %s:%d\n", email_add, resp.StatusCode)
		//saveXMLToFile_autodiscover(outputfile, bad_response, email_add)
		return flag1, flag2, flag3, redirects, bad_response, nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode) //同时也想记录请求发送失败时的状态码
	}
}

func getRedirects(resp *http.Response) (history []map[string]interface{}) {
	for resp != nil {
		req := resp.Request
		status := resp.StatusCode
		entry := map[string]interface{}{
			"URL":    req.URL.String(),
			"Status": status,
		}
		history = append(history, entry)
		resp = resp.Request.Response
	}
	if len(history) >= 1 {
		for l, r := 0, len(history)-1; l < r; l, r = l+1, r-1 {
			history[l], history[r] = history[r], history[l]
		}
	}
	return history
}

func lookupSRVWithAD_autodiscover(domain string) (string, bool, error) {
	// DNS Resolver configuration
	resolverAddr := "8.8.8.8:53" // Google Public DNS
	timeout := 5 * time.Second   // Timeout for DNS query

	// Create a DNS client
	client := &dns.Client{
		Net:     "udp", //
		Timeout: timeout,
	}

	// Create the SRV query
	service := "_autodiscover._tcp." + domain
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(service), dns.TypeSRV)
	msg.RecursionDesired = true // Enable recursion
	msg.SetEdns0(4096, true)    // true 表示启用 DO 位，支持 DNSSEC

	// Perform the DNS query
	response, _, err := client.Exchange(msg, resolverAddr)
	if err != nil {
		return "", false, fmt.Errorf("DNS query failed: %v", err)
	}

	// Check the AD bit in the DNS response flags
	adBit := response.AuthenticatedData

	var srvRecords []*dns.SRV
	for _, ans := range response.Answer {
		if srv, ok := ans.(*dns.SRV); ok {
			srvRecords = append(srvRecords, srv)
		}
	}
	var uriDNS string
	if len(srvRecords) > 0 {
		sort.Slice(srvRecords, func(i, j int) bool {
			if srvRecords[i].Priority == srvRecords[j].Priority {
				return srvRecords[i].Weight > srvRecords[j].Weight
			}
			return srvRecords[i].Priority < srvRecords[j].Priority
		})

		hostname := srvRecords[0].Target
		port := srvRecords[0].Port
		if hostname != "." {
			if port == 443 {
				uriDNS = fmt.Sprintf("https://%s/autodiscover/autodiscover.xml", hostname)
			} else if port == 80 {
				uriDNS = fmt.Sprintf("http://%s/autodiscover/autodiscover.xml", hostname)
			} else {
				uriDNS = fmt.Sprintf("https://%s:%d/autodiscover/autodiscover.xml", hostname, port)
			}
		} else {
			return "", adBit, fmt.Errorf("hostname == '.'")
		}
	} else {
		return "", adBit, fmt.Errorf("no srvRecord found")
	}

	return uriDNS, adBit, nil
}

func record_ADbit_SRV_autodiscover(filename string, domain string, ADbit bool) error {
	lock := getFileLock(filename) // 获取与文件名对应的锁
	lock.Lock()
	defer lock.Unlock()
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	separator := fmt.Sprintf("\n\n<!-- Adbit of domain when looking up srv: %s -->\n", domain)
	if _, err := file.WriteString(separator); err != nil {
		return err
	}
	file.WriteString(fmt.Sprint(ADbit) + "\n")
	return nil
}

func saveXMLToFile_autodiscover(filename, data string, email_add string) error {
	lock := getFileLock(filename) // 获取与文件名对应的锁
	lock.Lock()
	defer lock.Unlock()

	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	if data != "" { //
		separator := fmt.Sprintf("\n\n<!-- Config for email address: %s -->\n", email_add)
		if _, err := file.WriteString(separator); err != nil {
			return err
		}

		if _, err := file.WriteString(data); err != nil {
			return err
		}
	}

	return nil
}
func saveXMLToFile_with_ReAdrr_autodiscover(filename, data string, email_add string) error {
	lock := getFileLock(filename) // 获取与文件名对应的锁
	lock.Lock()
	defer lock.Unlock()
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	if data != "" { //
		separator := fmt.Sprintf("\n\n<!-- Init Config with redirect email_address for email address: %s -->\n", email_add)
		if _, err := file.WriteString(separator); err != nil {
			return err
		}

		if _, err := file.WriteString(data); err != nil {
			return err
		}
	}

	return nil
}
func saveno_XMLToFile(filename, data string, email_add string) error {
	lock := getFileLock(filename) // 获取与文件名对应的锁
	lock.Lock()
	defer lock.Unlock()
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	if data != "" { //
		separator := fmt.Sprintf("\n\n<!-- Init Config with invalid format for email address: %s -->\n", email_add)
		if _, err := file.WriteString(separator); err != nil {
			return err
		}

		if _, err := file.WriteString(data); err != nil {
			return err
		}
	}

	return nil
}

func saveXMLToFile_with_Reuri_autodiscover(filename, data string, email_add string) error {
	lock := getFileLock(filename) // 获取与文件名对应的锁
	lock.Lock()
	defer lock.Unlock()

	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	if data != "" { //
		separator := fmt.Sprintf("\n\n<!-- Init Config with redirect uri for email address: %s -->\n", email_add)
		if _, err := file.WriteString(separator); err != nil {
			return err
		}

		if _, err := file.WriteString(data); err != nil {
			return err
		}
	}

	return nil
}

func verifyCertificate(chain []*x509.Certificate, domain string) (bool, error) {
	if len(chain) == 1 {
		temp_chain, err := certUtil.FetchCertificateChain(chain[0])
		if err != nil {
			//log.Println("failed to fetch certificate chain")
			return false, fmt.Errorf("failed to fetch certificate chain:%v", err)
		}
		chain = temp_chain
	}

	intermediates := x509.NewCertPool()
	for i := 1; i < len(chain); i++ {
		intermediates.AddCert(chain[i])
	}

	certPool := x509.NewCertPool()
	pemFile := "IncludedRootsPEM_1225.txt" //修改获取roots的途径
	pem, err := os.ReadFile(pemFile)
	if err != nil {
		//log.Println("failed to read root certificate")
		return false, fmt.Errorf("failed to read root certificate:%v", err)
	}
	ok := certPool.AppendCertsFromPEM(pem)
	if !ok {
		//log.Println("failed to import root certificate")
		return false, fmt.Errorf("failed to import root certificate:%v", err)
	}

	opts := x509.VerifyOptions{
		Roots:         certPool,
		Intermediates: intermediates,
		DNSName:       domain,
	}

	if _, err := chain[0].Verify(opts); err != nil {
		//fmt.Println(err)
		return false, fmt.Errorf("certificate verify failed: %v", err)
	}

	return true, nil
}

func verifyHostname(cert *x509.Certificate, domain string) bool {
	return cert.VerifyHostname(domain) == nil
}

// Ref to: https://github.com/izolight/certigo/blob/v1.10.0/lib/encoder.go#L445
func IsSelfSigned(cert *x509.Certificate) bool {
	if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return true
	} //12.25
	return cert.CheckSignatureFrom(cert) == nil
}

// Ref to: https://github.com/google/certificate-transparency-go/blob/master/ctutil/sctcheck/sctcheck.go
func isChainInOrder(chain []*x509.Certificate) string {
	// var issuer *x509.Certificate
	leaf := chain[0]
	for i := 1; i < len(chain); i++ {
		c := chain[i]
		if bytes.Equal(c.RawSubject, leaf.RawIssuer) && c.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil {
			// issuer = c
			if i > 1 {
				return "not"
			}
			break
		}
	}
	if len(chain) < 1 {
		return "single"
	}
	return "yes"
}

var algoName = [...]string{
	x509.MD2WithRSA:      "MD2-RSA",
	x509.MD5WithRSA:      "MD5-RSA",
	x509.SHA1WithRSA:     "SHA1-RSA",
	x509.SHA256WithRSA:   "SHA256-RSA",
	x509.SHA384WithRSA:   "SHA384-RSA",
	x509.SHA512WithRSA:   "SHA512-RSA",
	x509.DSAWithSHA1:     "DSA-SHA1",
	x509.DSAWithSHA256:   "DSA-SHA256",
	x509.ECDSAWithSHA1:   "ECDSA-SHA1",
	x509.ECDSAWithSHA256: "ECDSA-SHA256",
	x509.ECDSAWithSHA384: "ECDSA-SHA384",
	x509.ECDSAWithSHA512: "ECDSA-SHA512",
}

var badSignatureAlgorithms = [...]x509.SignatureAlgorithm{
	x509.MD2WithRSA,
	x509.MD5WithRSA,
	x509.SHA1WithRSA,
	x509.DSAWithSHA1,
	x509.ECDSAWithSHA1,
}

func algWarnings(cert *x509.Certificate) (warning string) {
	alg, size := decodeKey(cert.PublicKey)
	if (alg == "RSA" || alg == "DSA") && size < 2048 {
		// warnings = append(warnings, fmt.Sprintf("Size of %s key should be at least 2048 bits", alg))
		warning = fmt.Sprintf("Size of %s key should be at least 2048 bits", alg)
	}
	if alg == "ECDSA" && size < 224 {
		warning = fmt.Sprintf("Size of %s key should be at least 224 bits", alg)
	}

	for _, alg := range badSignatureAlgorithms {
		if cert.SignatureAlgorithm == alg {
			warning = fmt.Sprintf("Signed with %s, which is an outdated signature algorithm", algString(alg))
		}
	}

	if alg == "RSA" {
		key := cert.PublicKey.(*rsa.PublicKey)
		if key.E < 3 {
			warning = "Public key exponent in RSA key is less than 3"
		}
		if key.N.Sign() != 1 {
			warning = "Public key modulus in RSA key appears to be zero/negative"
		}
	}

	return warning
}

// decodeKey returns the algorithm and key size for a public key.
func decodeKey(publicKey interface{}) (string, int) {
	switch publicKey.(type) {
	case *dsa.PublicKey:
		return "DSA", publicKey.(*dsa.PublicKey).P.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", publicKey.(*ecdsa.PublicKey).Curve.Params().BitSize
	case *rsa.PublicKey:
		return "RSA", publicKey.(*rsa.PublicKey).N.BitLen()
	default:
		return "", 0
	}
}

func algString(algo x509.SignatureAlgorithm) string {
	if 0 < algo && int(algo) < len(algoName) {
		return algoName[algo]
	}
	return strconv.Itoa(int(algo))
}

// 查询Autoconfig部分
func queryAutoconfig(domain string) []AutoconfigResult {
	var results []AutoconfigResult
	email := fmt.Sprintf("info@%s", domain)
	//method1 直接通过url发送get请求得到config
	urls := []string{
		fmt.Sprintf("https://autoconfig.%s/mail/config-v1.1.xml?emailaddress=%s", domain, email),             //uri1
		fmt.Sprintf("https://%s/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress=%s", domain, email), //uri2
		fmt.Sprintf("http://autoconfig.%s/mail/config-v1.1.xml?emailaddress=%s", domain, email),              //uri3
		fmt.Sprintf("http://%s/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress=%s", domain, email),  //uri4
	}
	for i, url := range urls {
		index := i + 1
		config, redirects, certinfo, err := Get_autoconfig_config(domain, url, "directurl", index)

		result := AutoconfigResult{
			Domain:    domain,
			Method:    "directurl",
			Index:     index,
			URI:       url,
			Redirects: redirects,
			Config:    config,
			CertInfo:  certinfo,
		}
		if err != nil {
			result.Error = err.Error()
		}
		results = append(results, result)
	}

	//method2 ISPDB
	ISPurl := fmt.Sprintf("https://autoconfig.thunderbird.net/v1.1/%s", domain)
	config, redirects, certinfo, err := Get_autoconfig_config(domain, ISPurl, "ISPDB", 0)
	result_ISPDB := AutoconfigResult{
		Domain:    domain,
		Method:    "ISPDB",
		Index:     0,
		URI:       ISPurl,
		Redirects: redirects,
		Config:    config,
		CertInfo:  certinfo,
	}
	if err != nil {
		result_ISPDB.Error = err.Error()
	}
	results = append(results, result_ISPDB)

	//method3 MX查询
	mxHost, err := ResolveMXRecord(domain)
	if err != nil {
		result_MX := AutoconfigResult{
			Domain: domain,
			Method: "MX",
			Index:  0,
			Error:  fmt.Sprintf("Resolve MX Record error for %s: %v", domain, err),
		}
		results = append(results, result_MX)
	} else {
		mxFullDomain, mxMainDomain, err := extractDomains(mxHost)
		if err != nil {
			result_MX := AutoconfigResult{
				Domain: domain,
				Method: "MX",
				Index:  0,
				Error:  fmt.Sprintf("extract domain from mxHost error for %s: %v", domain, err),
			}
			results = append(results, result_MX)
		} else {
			if mxFullDomain == mxMainDomain {
				urls := []string{
					fmt.Sprintf("https://autoconfig.%s/mail/config-v1.1.xml?emailaddress=%s", mxFullDomain, email), //1
					fmt.Sprintf("https://autoconfig.thunderbird.net/v1.1/%s", mxFullDomain),                        //3
				}
				for i, url := range urls {
					config, redirects, certinfo, err := Get_autoconfig_config(domain, url, "MX_samedomain", i*2+1)
					result := AutoconfigResult{
						Domain:    domain,
						Method:    "MX_samedomain",
						Index:     i*2 + 1,
						URI:       url,
						Redirects: redirects,
						Config:    config,
						CertInfo:  certinfo,
					}
					if err != nil {
						result.Error = err.Error()
					}
					results = append(results, result)
				}
			} else {
				urls := []string{
					fmt.Sprintf("https://autoconfig.%s/mail/config-v1.1.xml?emailaddress=%s", mxFullDomain, email), //1
					fmt.Sprintf("https://autoconfig.%s/mail/config-v1.1.xml?emailaddress=%s", mxMainDomain, email), //2
					fmt.Sprintf("https://autoconfig.thunderbird.net/v1.1/%s", mxFullDomain),                        //3
					fmt.Sprintf("https://autoconfig.thunderbird.net/v1.1/%s", mxMainDomain),                        //4
				}
				for i, url := range urls {
					config, redirects, certinfo, err := Get_autoconfig_config(domain, url, "MX", i+1)
					result := AutoconfigResult{
						Domain:    domain,
						Method:    "MX",
						Index:     i + 1,
						URI:       url,
						Redirects: redirects,
						Config:    config,
						CertInfo:  certinfo,
					}
					if err != nil {
						result.Error = err.Error()
					}
					results = append(results, result)
				}
			}
		}

	}
	return results

}

func Get_autoconfig_config(domain string, url string, method string, index int) (string, []map[string]interface{}, *CertInfo, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10,
			},
		},
		Timeout: 15 * time.Second,
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", []map[string]interface{}{}, nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", []map[string]interface{}{}, nil, err
	}
	// 获取重定向历史记录
	redirects := getRedirects(resp)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", redirects, nil, fmt.Errorf("failed to read response body: %v", err)
	}
	var autoconfigResp AutoconfigResponse
	err = xml.Unmarshal(body, &autoconfigResp)
	if err != nil {
		return "", redirects, nil, fmt.Errorf("failed to unmarshal XML: %v", err)
	} else {
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

		config := string(body)
		outputfile := fmt.Sprintf("./autoconfig/autoconfig_%s_%d.xml", method, index) //12.18 用Index加以区分
		err = saveXMLToFile_autoconfig(outputfile, config, domain)
		if err != nil {
			return "", redirects, &certInfo, err
		}
		return config, redirects, &certInfo, nil
	}
}

func saveXMLToFile_autoconfig(filename, data string, email_add string) error {
	lock := getFileLock(filename) // 获取与文件名对应的锁
	lock.Lock()
	defer lock.Unlock()

	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	separator := fmt.Sprintf("\n\n<!-- Config for email address: %s -->\n", email_add)
	if _, err := file.WriteString(separator); err != nil {
		return err
	}

	if _, err := file.WriteString(data); err != nil {
		return err
	}

	return nil
}

// 获取MX记录
func ResolveMXRecord(domain string) (string, error) {
	//创建DNS客户端并设置超时时间
	client := &dns.Client{
		Timeout: 15 * time.Second, // 设置超时时间
	}

	// 创建DNS消息
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
	//发送DNS查询
	response, _, err := client.Exchange(msg, dnsServer)
	if err != nil {
		fmt.Printf("Failed to query DNS for %s: %v\n", domain, err)
		return "", err
	}

	//处理响应
	if response.Rcode != dns.RcodeSuccess {
		fmt.Printf("DNS query failed with Rcode %d\n", response.Rcode)
		return "", fmt.Errorf("DNS query failed with Rcode %d", response.Rcode)
	}

	var mxRecords []*dns.MX
	for _, ans := range response.Answer {
		if mxRecord, ok := ans.(*dns.MX); ok {
			fmt.Printf("MX record for %s: %s, the priority is %d\n", domain, mxRecord.Mx, mxRecord.Preference)
			mxRecords = append(mxRecords, mxRecord)
		}
	}
	if len(mxRecords) == 0 {
		return "", fmt.Errorf("no MX Record")
	}

	// 根据Preference字段排序，Preference值越小优先级越高
	sort.Slice(mxRecords, func(i, j int) bool {
		return mxRecords[i].Preference < mxRecords[j].Preference
	})
	highestMX := mxRecords[0]
	return highestMX.Mx, nil

}

// 提取%MXFULLDOMAIN%和%MXMAINDOMAIN%
func extractDomains(mxHost string) (string, string, error) {
	mxHost = strings.TrimSuffix(mxHost, ".")

	// 获取%MXFULLDOMAIN%
	parts := strings.Split(mxHost, ".")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid MX Host name: %s", mxHost)
	}
	mxFullDomain := strings.Join(parts[1:], ".")
	fmt.Println("fulldomain:", mxFullDomain)

	// 获取%MXMAINDOMAIN%（提取第二级域名）
	mxMainDomain, err := publicsuffix.EffectiveTLDPlusOne(mxHost)
	if err != nil {
		return "", "", fmt.Errorf("cannot extract maindomain: %v", err)
	}
	fmt.Println("maindomain:", mxMainDomain)

	return mxFullDomain, mxMainDomain, nil
}

func querySRV(domain string) SRVResult {
	var dnsrecord DNSRecord
	dnsManager, isSOA, err := queryDNSManager(domain)
	if err != nil {
		fmt.Printf("Failed to query DNS manager for %s: %v\n", domain, err)
	} else {
		if isSOA {
			dnsrecord = DNSRecord{
				Domain: domain,
				SOA:    dnsManager,
			}
		} else {
			dnsrecord = DNSRecord{
				Domain: domain,
				NS:     dnsManager,
			}
		}
	}

	// 定义要查询的服务标签
	recvServices := []string{
		"_imap._tcp." + domain,
		"_imaps._tcp." + domain,
		"_pop3._tcp." + domain,
		"_pop3s._tcp." + domain,
	}
	sendServices := []string{
		"_submission._tcp." + domain,
		"_submissions._tcp." + domain,
	}

	var recvRecords, sendRecords []SRVRecord

	// 查询(IMAP/POP3)
	for _, service := range recvServices {
		records, adBit, err := lookupSRVWithAD_srv(service)
		record_ADbit_SRV(service, "SRV_record_ad_srv.txt", domain, adBit)

		if err != nil || len(records) == 0 {
			fmt.Printf("Failed to query SRV for %s or no records found: %v\n", service, err)
			continue
		}

		// 更新 DNSRecord 的 AD 位
		if strings.HasPrefix(service, "_imaps") {
			dnsrecord.ADbit_imaps = &adBit
		} else if strings.HasPrefix(service, "_imap") {
			dnsrecord.ADbit_imap = &adBit
		} else if strings.HasPrefix(service, "_pop3s") {
			dnsrecord.ADbit_pop3s = &adBit
		} else if strings.HasPrefix(service, "_pop3") {
			dnsrecord.ADbit_pop3 = &adBit
		}

		// 添加 SRV 记录
		for _, record := range records {
			if record.Target == "." {
				continue
			}
			recvRecords = append(recvRecords, SRVRecord{
				Service:  service,
				Priority: record.Priority,
				Weight:   record.Weight,
				Port:     record.Port,
				Target:   record.Target,
			})
		}
	}

	// 查询 (SMTP)
	for _, service := range sendServices {
		records, adBit, err := lookupSRVWithAD_srv(service)
		record_ADbit_SRV(service, "SRV_record_ad_srv.txt", domain, adBit)

		if err != nil || len(records) == 0 {
			fmt.Printf("Failed to query SRV for %s or no records found: %v\n", service, err)
			continue
		}

		// 更新 DNSRecord 的 AD 位
		if strings.HasPrefix(service, "_submissions") {
			dnsrecord.ADbit_smtps = &adBit
		} else if strings.HasPrefix(service, "_submission") {
			dnsrecord.ADbit_smtp = &adBit
		}

		// 添加 SRV 记录
		for _, record := range records {
			if record.Target == "." {
				continue
			}
			sendRecords = append(sendRecords, SRVRecord{
				Service:  service,
				Priority: record.Priority,
				Weight:   record.Weight,
				Port:     record.Port,
				Target:   record.Target,
			})
		}
	}

	// 对收件服务和发件服务进行排序
	sort.Slice(recvRecords, func(i, j int) bool {
		if recvRecords[i].Priority == recvRecords[j].Priority {
			return recvRecords[i].Weight > recvRecords[j].Weight
		}
		return recvRecords[i].Priority < recvRecords[j].Priority
	})

	sort.Slice(sendRecords, func(i, j int) bool {
		if sendRecords[i].Priority == sendRecords[j].Priority {
			return sendRecords[i].Weight > sendRecords[j].Weight
		}
		return sendRecords[i].Priority < sendRecords[j].Priority
	})

	// 返回组合后的结果
	return SRVResult{
		Domain:      domain,
		DNSRecord:   &dnsrecord,
		RecvRecords: recvRecords,
		SendRecords: sendRecords,
	}
}

func queryDNSManager(domain string) (string, bool, error) {
	resolverAddr := "8.8.8.8:53" // Google Public DNS
	timeout := 15 * time.Second  // DNS 查询超时时间

	client := &dns.Client{
		Net:     "udp",
		Timeout: timeout,
	}

	// 查询 SOA 记录
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	response, _, err := client.Exchange(msg, resolverAddr)
	if err != nil {
		return "", false, fmt.Errorf("SOA query failed: %v", err)
	}

	// 提取 SOA 记录的管理者信息
	for _, ans := range response.Answer {
		if soa, ok := ans.(*dns.SOA); ok {
			return soa.Ns, true, nil // SOA 记录中的权威 DNS 服务器名称
		}
	}

	// 若 SOA 查询无结果，尝试查询 NS 记录
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	response, _, err = client.Exchange(msg, resolverAddr)
	if err != nil {
		return "", false, fmt.Errorf("NS query failed: %v", err)
	}

	var nsRecords []string
	for _, ans := range response.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			nsRecords = append(nsRecords, ns.Ns)
		}
	}

	if len(nsRecords) > 0 {
		return strings.Join(nsRecords, ", "), false, nil // 返回 NS 记录列表
	}

	return "", false, fmt.Errorf("no SOA or NS records found for domain: %s", domain)
}

func lookupSRVWithAD_srv(service string) ([]*dns.SRV, bool, error) {
	// DNS Resolver configuration
	resolverAddr := "8.8.8.8:53" // Google Public DNS
	timeout := 15 * time.Second  // Timeout for DNS query

	// Create a DNS client
	client := &dns.Client{
		Net:     "udp", //
		Timeout: timeout,
	}
	// Create the SRV query
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(service), dns.TypeSRV)
	msg.RecursionDesired = true // Enable recursion
	msg.SetEdns0(4096, true)    // true 表示启用 DO 位，支持 DNSSEC

	// Perform the DNS query
	response, _, err := client.Exchange(msg, resolverAddr)
	if err != nil {
		return nil, false, fmt.Errorf("DNS query failed: %v", err)
	}

	// Check the AD bit in the DNS response flags
	adBit := response.AuthenticatedData
	// 解析 SRV 记录
	var srvRecords []*dns.SRV
	for _, ans := range response.Answer {
		if srv, ok := ans.(*dns.SRV); ok {
			srvRecords = append(srvRecords, srv)
		}
	}
	fmt.Printf("service:%s, adBit:%v\n", service, adBit)
	return srvRecords, adBit, nil
}

func record_ADbit_SRV(service string, filename string, domain string, ADbit bool) error {
	lock := getFileLock(filename) // 获取与文件名对应的锁
	lock.Lock()
	defer lock.Unlock()
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	separator := fmt.Sprintf("\n\n<!-- Adbit of domain when looking up service %s: %s -->\n", service, domain)
	if _, err := file.WriteString(separator); err != nil {
		return err
	}
	file.WriteString(fmt.Sprint(ADbit) + "\n")
	return nil
}
