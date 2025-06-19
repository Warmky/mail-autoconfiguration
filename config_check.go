package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/beevik/etree"
)

type ProtocolInfo struct {
	Type           string `json:"Type"`
	Server         string `json:"Server"`
	Port           string `json:"Port"`
	DomainRequired string `json:"DomainRequired,omitempty"`
	SPA            string `json:"SPA,omitempty"`
	SSL            string `json:"SSL,omitempty"` //
	AuthRequired   string `json:"AuthRequired,omitempty"`
	Encryption     string `json:"Encryption,omitempty"`
	UsePOPAuth     string `json:"UsePOPAuth,omitempty"`
	SMTPLast       string `json:"SMTPLast,omitempty"`
	TTL            string `json:"TTL,omitempty"`
	SingleCheck    string `json:"SingleCheck"`        //          // Status 用于标记某个Method(Autodiscover/Autoconfig/SRV)的单个Protocol检查结果
	Priority       string `json:"Priority,omitempty"` //SRV
	Weight         string `json:"Weight,omitempty"`
}

type MethodConfig struct {
	Method       string         `json:"Method"`
	Protocols    []ProtocolInfo `json:"Protocols"`
	OverallCheck string         `json:"OverallCheck"`
}
type DomainCheckResult struct {
	Domain                  string        `json:"Domain"`
	AutodiscoverCheckResult *MethodConfig `json:"AutodiscoverCheckResult,omitempty"`
	AutoconfigCheckResult   *MethodConfig `json:"AutoconfigCheckResult,omitempty"`
	SRVCheckResult          *MethodConfig `json:"SRVCheckResult,omitempty"`
}

// 解析每个对象中的Autodiscover的config
func parseXMLConfig_Autodiscover(config string) (*MethodConfig, error) {
	// 创建一个新的 etree 文档
	doc := etree.NewDocument()

	// 解析 config 中的 XML 字符串
	err := doc.ReadFromString(config)
	if err != nil {
		log.Printf("Error parsing XML: %v", err)
		return nil, err
	}

	// 查找根元素
	root := doc.SelectElement("Autodiscover")
	if root == nil {
		log.Println("No root element <Autodiscover> found.")
		result1 := &MethodConfig{
			Method:       "Autodiscover",
			Protocols:    nil,
			OverallCheck: "Invalid, root element <Autodiscover> lost",
		}
		return result1, fmt.Errorf("missing root element <Autodiscover>")
	}

	// 查找 Response 元素
	responseElem := root.SelectElement("Response")
	if responseElem == nil {
		log.Println("No <Response> element found.")
		result2 := &MethodConfig{
			Method:       "Autodiscover",
			Protocols:    nil,
			OverallCheck: "Invalid, <Response> element lost",
		}
		return result2, fmt.Errorf("missing <Response> element")
	}

	// // 打印 User 和 Account 信息
	// userElem := responseElem.SelectElement("User")
	// if userElem == nil {
	// 	result3 := &MethodConfig{
	// 		Method:       "Autodiscover",
	// 		Protocols:    nil,
	// 		OverallCheck: "Invalid, <User> element lost",
	// 	}
	// 	return result3, fmt.Errorf("missing <User> element")
	// } else if userElem.SelectElement("DisplayName") == nil {
	// 	result3 := &MethodConfig{
	// 		Method:       "Autodiscover",
	// 		Protocols:    nil,
	// 		OverallCheck: "Invalid,missing <DisplayName> in <User>",
	// 	}
	// 	return result3, fmt.Errorf("missing <DisplayName> in <User>")
	// } //需要考虑将diaplayName输出到结构体中吗？TODO  3.8因为没有User的过多，先不算作错误10105 ，9

	accountElem := responseElem.SelectElement("Account")
	if accountElem == nil {
		result4 := &MethodConfig{
			Method:       "Autodiscover",
			Protocols:    nil,
			OverallCheck: "Invalid, missing <Account> element",
		}
		return result4, fmt.Errorf("missing <Account> element")
	}
	//4.1检查<AccountType>和<Action>
	accountTypeElem := accountElem.SelectElement("AccountType")
	if accountTypeElem == nil || accountTypeElem.Text() != "email" {
		return &MethodConfig{
			Method:       "Autodiscover",
			Protocols:    nil,
			OverallCheck: "Invalid, <AccountType> must be 'email'",
		}, fmt.Errorf("<AccountType> must be 'email'")
	}
	actionElem := accountElem.SelectElement("Action")
	if actionElem == nil || actionElem.Text() != "settings" {
		return &MethodConfig{
			Method:       "Autodiscover",
			Protocols:    nil,
			OverallCheck: "Invalid, <Action> must be 'settings'",
		}, fmt.Errorf("<Action> must be 'settings'")
	}
	//4.2查找<Protocol>元素
	var protocols []ProtocolInfo
	for _, protocolElem := range accountElem.SelectElements("Protocol") {
		protocol := ProtocolInfo{}
		protocol.SingleCheck = "Valid" //首先设置为Valid //
		// 检查每个子元素是否存在再获取其内容
		if typeElem := protocolElem.SelectElement("Type"); typeElem != nil {
			protocol.Type = typeElem.Text()
		}
		if serverElem := protocolElem.SelectElement("Server"); serverElem != nil {
			protocol.Server = serverElem.Text()
		}
		if portElem := protocolElem.SelectElement("Port"); portElem != nil {
			protocol.Port = portElem.Text()
		}
		if domainRequiredElem := protocolElem.SelectElement("DomainRequired"); domainRequiredElem != nil {
			protocol.DomainRequired = domainRequiredElem.Text()
		}
		if spaElem := protocolElem.SelectElement("SPA"); spaElem != nil {
			protocol.SPA = spaElem.Text()
		}
		if sslElem := protocolElem.SelectElement("SSL"); sslElem != nil {
			protocol.SSL = sslElem.Text()
		}
		if authRequiredElem := protocolElem.SelectElement("AuthRequired"); authRequiredElem != nil {
			protocol.AuthRequired = authRequiredElem.Text()
		}
		if encryptionElem := protocolElem.SelectElement("Encryption"); encryptionElem != nil {
			protocol.Encryption = encryptionElem.Text()
		}
		if usePOPAuthElem := protocolElem.SelectElement("UsePOPAuth"); usePOPAuthElem != nil {
			protocol.UsePOPAuth = usePOPAuthElem.Text()
		}
		if smtpLastElem := protocolElem.SelectElement("SMTPLast"); smtpLastElem != nil {
			protocol.SMTPLast = smtpLastElem.Text()
		}
		if ttlElem := protocolElem.SelectElement("TTL"); ttlElem != nil {
			protocol.TTL = ttlElem.Text()
		}

		// 检查
		if protocolElem.SelectAttr("Type") != nil && protocol.Type != "" {
			protocol.SingleCheck = fmt.Sprintf("Invalid, <Type> element mustn't show, Type attribute of <Protocol> is %s", protocolElem.SelectAttr("Type").Value)
		} else {
			if protocol.Type == "" && protocolElem.SelectAttr("Type") == nil {
				protocol.SingleCheck = "Invalid, no Type attribute in <Protocol> element nor <Type> element"
			}
		}
		if protocol.SSL == "" {
			protocol.SSL = "default(on)" //补充了SSL的缺省值
		} //SSL检查应该在Encryption之前
		if protocol.Encryption != "" {
			if !(protocol.Type == "IMAP" || protocol.Type == "SMTP" || protocol.Type == "POP3") {
				protocol.SingleCheck = "Invalid, supposed no <Encryption>"
			}
			if !(protocol.Encryption == "None" || protocol.Encryption == "SSL" || protocol.Encryption == "TLS" || protocol.Encryption == "Auto") { //按照协议规范是只有这4个值，实际上不止，还有如STARTTLS
				protocol.SingleCheck = fmt.Sprintf("Invalid, Encryption method %s, not supposed to appear", protocol.Encryption)
			}
			if protocol.SSL != "" {
				protocol.SSL = ""
			}
		}
		if protocol.Type == "EXCH" || protocol.Type == "EXPR" || protocol.Type == "EXHTTP" || protocol.Type == "POP3" || protocol.Type == "SMTP" || protocol.Type == "IMAP" {
			if protocol.Server == "" {
				protocol.SingleCheck = "Invalid, no valid Server"
			}
		}
		if protocol.SMTPLast != "" && protocol.Type != "SMTP" {
			protocol.SMTPLast = ""
			protocol.SingleCheck = "Invalid, SMTPLast not supposed"
		}
		if protocol.SPA == "" && (protocol.Type == "IMAP" || protocol.Type == "SMTP" || protocol.Type == "POP3") {
			protocol.SPA = "default(on)" //补充SPA缺省值
		}
		if protocol.SPA != "" && !(protocol.Type == "IMAP" || protocol.Type == "SMTP" || protocol.Type == "POP3") {
			protocol.SPA = ""
			protocol.SingleCheck = "Invalid, SPA not supposed"
		}
		if protocol.UsePOPAuth != "" && protocol.Type != "SMTP" {
			protocol.UsePOPAuth = ""
			protocol.SingleCheck = "Invalid, UsePOPAuth not supposed"
		}

		protocols = append(protocols, protocol)
	}
	finalStatus := "Valid"
	for _, protocol := range protocols {
		if protocol.SingleCheck != "Valid" {
			finalStatus = "Invalid"
			break
		}
	} //Autodiscover采取的是有一个协议不对就都不对（因为没有找到优先使用规则）
	result := &MethodConfig{
		Method:       "Autodiscover",
		Protocols:    protocols,
		OverallCheck: finalStatus,
	}
	return result, nil

}

// 解析每个对象中的Autoconfig的config
func parseXMLConfig_Autoconfig(config string) (*MethodConfig, error) {
	doc := etree.NewDocument()
	err := doc.ReadFromString(config)
	if err != nil {
		log.Printf("Error parsing XML: %v", err)
		return nil, err
	}
	//1.确保根元素是<ClientConfig>
	root := doc.SelectElement("clientConfig")
	if root == nil {
		result1 := &MethodConfig{
			Method:       "Autoconfig",
			Protocols:    nil,
			OverallCheck: "Invalid, root element <clientConfig> lost",
		}
		return result1, fmt.Errorf("missing root element <clientConfig>")
	}
	//2.查找<emailProvider>元素
	emailProviderElem := root.SelectElement("emailProvider")
	if emailProviderElem == nil {
		result2 := &MethodConfig{
			Method:       "Autoconfig",
			Protocols:    nil,
			OverallCheck: "Invalid, <emailProvider> element lost",
		}
		return result2, fmt.Errorf("missing <emailProvider> element")
	}
	//先查找incomingServer,再OutgoingServer
	var protocols []ProtocolInfo
	for _, protocolElem := range emailProviderElem.SelectElements("incomingServer") {
		protocol := ProtocolInfo{}
		protocol.SingleCheck = "Valid"
		if typeELem := protocolElem.SelectAttr("type"); typeELem != nil {
			protocol.Type = typeELem.Value //? type属性 -> <Type>
		}
		if serverElem := protocolElem.SelectElement("hostname"); serverElem != nil {
			protocol.Server = serverElem.Text() //<hostname> -> <Server>
		}
		if portElem := protocolElem.SelectElement("port"); portElem != nil {
			protocol.Port = portElem.Text()
		}
		if sslElem := protocolElem.SelectElement("socketType"); sslElem != nil {
			protocol.SSL = sslElem.Text() //<socketType> -> <SSL>
		}

		//检查

		var authentications []string
		//对authentication
		hasOAuth2 := false
		haspassword_cleartext := false
		for _, authElem := range protocolElem.SelectElements("authentication") {
			authText := authElem.Text()
			authentications = append(authentications, authText)
			if authText == "OAuth2" {
				hasOAuth2 = true
			} else if authText == "password-cleartext" {
				haspassword_cleartext = true
			}
		}
		if hasOAuth2 && len(authentications) == 1 {
			protocol.SingleCheck = "Invalid, OAuth2 must have fallback authmethod" //

		}

		if len(authentications) != 0 {
			protocol.Encryption = strings.Join(authentications, ", ")
		}

		if protocol.Type == "imap" {
			//关于端口和socketType的检查
			if protocol.SSL == "SSL" || protocol.SSL == "TLS" {
				if protocol.Port != "993" {
					protocol.SingleCheck = "Invalid, supposed IMAP-SSL-993"
				}
			} else if protocol.SSL == "STARTTLS" {
				if protocol.Port != "143" {
					protocol.SingleCheck = "Invalid, supposed IMAP-STARTTLS-143"
				}
			} else if protocol.SSL == "plain" { //plain
				if haspassword_cleartext && len(authentications) == 1 {
					protocol.SingleCheck = "Invalid, only plain method is not supposed"
				} //如果只有plain认证算Invalid
			} else { //出现了除以上三者之外别的socketType
				protocol.SingleCheck = fmt.Sprintf("Invalid, socketType %s not supposed", protocol.SSL)
			}

		} else if protocol.Type == "pop3" {
			if protocol.SSL == "SSL" || protocol.SSL == "TLS" {
				if protocol.Port != "995" {
					protocol.SingleCheck = "Invalid, supposed POP3-SSL-995"
				}
			} else if protocol.SSL == "STARTTLS" {
				if protocol.Port != "110" {
					protocol.SingleCheck = "Invalid, supposed POP3-STARTTLS-110"
				}
			} else if protocol.SSL == "plain" { //plain
				if haspassword_cleartext && len(authentications) == 1 {
					protocol.SingleCheck = "Invalid, only plain method is not supposed"
				}
			} else {
				protocol.SingleCheck = fmt.Sprintf("Invalid, socketType %s not supposed", protocol.SSL)
			}

		} else {
			protocol.SingleCheck = "Invalid, Type supposed to be imap or pop3"
		}
		protocols = append(protocols, protocol)
	}
	finalStatus1 := "Invalid"
	for _, protocol := range protocols {
		if protocol.SingleCheck == "Valid" {
			finalStatus1 = "Valid"
			break
		}
	} //设定的是incoming中有一个Valid即可,是按照priority先后顺序得到的

	var protocols2 []ProtocolInfo
	for _, protocolElem := range emailProviderElem.SelectElements("outgoingServer") {
		protocol := ProtocolInfo{}
		protocol.SingleCheck = "Valid"
		if typeELem := protocolElem.SelectAttr("type"); typeELem != nil {
			protocol.Type = typeELem.Value //? type属性 -> <Type>
		}
		if serverElem := protocolElem.SelectElement("hostname"); serverElem != nil {
			protocol.Server = serverElem.Text() //<hostname> -> <Server>
		}
		if portElem := protocolElem.SelectElement("port"); portElem != nil {
			protocol.Port = portElem.Text()
		}
		if sslElem := protocolElem.SelectElement("socketType"); sslElem != nil {
			protocol.SSL = sslElem.Text() //<socketType> -> <SSL>
		}
		// if encryptionElem := protocolElem.SelectElement("authentication"); encryptionElem != nil {
		// 	protocol.Encryption = encryptionElem.Text() //<authentication> -> <Encryption>
		// } //<username>没写

		//检查
		var authentications []string
		//对authentication
		hasOAuth2 := false
		haspassword_cleartext := false
		for _, authElem := range protocolElem.SelectElements("authentication") {
			authText := authElem.Text()
			authentications = append(authentications, authText)
			if authText == "OAuth2" {
				hasOAuth2 = true
			} else if authText == "password-cleartext" {
				haspassword_cleartext = true
			}
		}
		if hasOAuth2 && len(authentications) == 1 {
			protocol.SingleCheck = "Invalid, OAuth2 must have fallback authmethod"

		}

		if len(authentications) != 0 {
			protocol.Encryption = strings.Join(authentications, ", ")
		}

		if protocol.Type == "smtp" {
			if protocol.SSL == "SSL" || protocol.SSL == "TLS" {
				if protocol.Port != "465" { //?不确定
					protocol.SingleCheck = "Invalid, supposed SMTP-SSL-465"
				}
			} else if protocol.SSL == "STARTTLS" {
				if !(protocol.Port == "25" || protocol.Port == "2525" || protocol.Port == "587") { //?协议中没写2525
					protocol.SingleCheck = "Invalid, supposed SMTP-STARTTLS-587" //
				}
			} else if protocol.SSL == "plain" { //plain
				if haspassword_cleartext && len(authentications) == 1 {
					protocol.SingleCheck = "Invalid, only plain method is not supposed"
				}
			} else {
				protocol.SingleCheck = fmt.Sprintf("Invalid, socketType %s not supposed", protocol.SSL)
			}

		} else {
			protocol.SingleCheck = "Invalid, Type supposed to be smtp"
		}
		protocols2 = append(protocols2, protocol)
		protocols = append(protocols, protocol)
	}
	finalStatus2 := "Invalid"
	for _, protocol := range protocols2 {
		if protocol.SingleCheck == "Valid" {
			finalStatus2 = "Valid"
			break
		}
	} //设定的是outcoming中有一个Valid即可
	var finalStatus string
	if finalStatus1 == "Valid" && finalStatus2 == "Valid" {
		finalStatus = "Valid"
	} else {
		finalStatus = "Invalid"
	}
	result := &MethodConfig{
		Method:       "Autoconfig",
		Protocols:    protocols,
		OverallCheck: finalStatus,
	}
	return result, nil

}

// 根据 SRV 服务名称获取协议类型
func getServiceType(service string) string {
	switch {
	case strings.HasPrefix(service, "_imaps"):
		return "IMAPS"
	case strings.HasPrefix(service, "_imap"):
		return "IMAP"
	case strings.HasPrefix(service, "_pop3s"):
		return "POP3S"
	case strings.HasPrefix(service, "_pop3"):
		return "POP3"
	case strings.HasPrefix(service, "_submissions"):
		return "SMTPS"
	case strings.HasPrefix(service, "_submission"):
		return "SMTP"
	default:
		return "Unknown"
	}
}

// 解析每个对象中的Autodiscover的config
func parseConfig_SRV(SRVResult *SRVResult) (*MethodConfig, error) {
	var protocols []ProtocolInfo
	finalStatus := "Invalid"
	if SRVResult.RecvRecords != nil {
		for _, RecvRecord := range SRVResult.RecvRecords {
			var protocol ProtocolInfo
			protocol.Type = getServiceType(RecvRecord.Service)
			protocol.Server = RecvRecord.Target
			// if protocol.Server == "." {
			// 	continue //表示该服务不可使用，直接跳过 //应该在跑配置的时候已经过滤掉了
			// }
			protocol.Port = fmt.Sprintf("%d", RecvRecord.Port)
			protocol.SingleCheck = "Valid"
			if protocol.Type == "IMAPS" && protocol.Port != "993" {
				protocol.SingleCheck = "Invalid, supposed imaps-993"
			} else if protocol.Type == "IMAP" && protocol.Port != "143" { //也有用993的？
				protocol.SingleCheck = "Invalid, supposed imap-143"
			} else if protocol.Type == "POP3S" && protocol.Port != "995" {
				protocol.SingleCheck = "Invalid, supposed pop3s-995"
			} else if protocol.Type == "POP3" && protocol.Port != "110" {
				protocol.SingleCheck = "Invalid, supposed pop3-110"
			} else {
				if protocol.Type == "Unknown" {
					protocol.SingleCheck = "Invalid, unknown protocol type"
				}
			}
			if protocol.SingleCheck == "Valid" {
				finalStatus = "Valid"
			}
			protocols = append(protocols, protocol) //SRV是只要三者中有一个valid即为valid
		}
	}
	if SRVResult.SendRecords != nil {
		for _, SendRecord := range SRVResult.SendRecords {
			var protocol ProtocolInfo
			protocol.Type = getServiceType(SendRecord.Service)
			protocol.Server = SendRecord.Target
			protocol.Port = fmt.Sprintf("%d", SendRecord.Port)
			protocol.SingleCheck = "Valid"
			if protocol.Type == "SMTPS" && protocol.Port != "465" {
				protocol.SingleCheck = "Invalid, supposed smtps-465"
			} else if protocol.Type == "SMTP" {
				if protocol.Port == "25" { //没有考虑其他端口
					protocol.SingleCheck = "Invalid, cleartext SMTP not supposed"
				} else {
					if protocol.Port != "587" {
						protocol.SingleCheck = "Invalid, supposed smtp-587"
					}
				}
			} else {
				if protocol.Type == "Unknown" {
					protocol.SingleCheck = "Invalid, unknown protocol type"
				}
			}
			if protocol.SingleCheck == "Valid" {
				finalStatus = "Valid"
			}
			protocols = append(protocols, protocol)
		}
	}
	result := &MethodConfig{
		Method:       "SRV",
		Protocols:    protocols,
		OverallCheck: finalStatus,
	}
	return result, nil
}

// 处理每个 DomainResult 对象
func processDomainResult(obj DomainResult) *DomainCheckResult {
	domain := obj.Domain
	var result1, result2, result3 *MethodConfig
	// 遍历 Autodiscover 配置并解析 XML
	for _, entry := range obj.Autodiscover {
		if entry.Config != "" && !strings.HasPrefix(entry.Config, "Bad") && !strings.HasPrefix(entry.Config, "Errorcode") {
			// fmt.Print(obj.Domain_id)
			// fmt.Print("\n")
			// 解析并处理 XML 配置
			//result1, _ = parseXMLConfig_Autodiscover(entry.Config)//3.3原
			r, _ := parseXMLConfig_Autodiscover(entry.Config)
			// if err == nil && r != nil {
			// 	result1 = r
			// 	break // 找到第一个成功解析的就退出
			// }
			// s1, _ := encoding.ToIndentJSON(result1)
			// fmt.Printf("content1=%v\n", s1)
			if r != nil {
				result1 = r
				break
			}

		}
	}
	for _, entry := range obj.Autoconfig {
		if entry.Config != "" {
			fmt.Print(entry.Domain + "\n")
			// 解析并处理 XML 配置
			//result2, _ = parseXMLConfig_Autoconfig(entry.Config) //3.3原
			s, _ := parseXMLConfig_Autoconfig(entry.Config)
			if s != nil {
				result2 = s
				break
			}
			// s2, _ := encoding.ToIndentJSON(result2)
			// fmt.Printf("content2=%v\n", s2)

		}
	}

	if obj.SRV.RecvRecords != nil || obj.SRV.SendRecords != nil {
		result3, _ = parseConfig_SRV(&obj.SRV)
		// s3, _ := encoding.ToIndentJSON(result3)
		// fmt.Printf("content3=%v\n", s3)
	}

	// 判断是否所有结果都为空
	if result1 == nil && result2 == nil && result3 == nil {
		return nil // 如果都为空，则返回 nil
	}
	data := &DomainCheckResult{
		Domain:                  domain,
		AutodiscoverCheckResult: result1,
		AutoconfigCheckResult:   result2,
		SRVCheckResult:          result3,
	}
	//s, _ := encoding.ToIndentJSON(data)
	//fmt.Printf("content=%v\n", s)
	return data
}

func saveCheckResultAsJSONL(result *DomainCheckResult, outputFile string) error {
	// 如果 result 为空，返回错误，避免崩溃
	if result == nil {
		return fmt.Errorf("received nil result")
	}

	// 将结果转换为 JSON 字符串
	jsonData, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal check result to JSON: %v", err)
	}

	// 打开文件，如果文件不存在则创建
	file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file for appending: %v", err)
	}
	defer file.Close()

	// 写入 JSON 数据
	writer := bufio.NewWriter(file)
	_, err = writer.Write(jsonData)
	if err != nil {
		return fmt.Errorf("failed to write to file: %v", err)
	}

	// 换行
	_, err = writer.Write([]byte("\n"))
	if err != nil {
		return fmt.Errorf("failed to write newline to file: %v", err)
	}

	// 刷新缓冲区确保写入
	writer.Flush()

	return nil
}

/*
func onlycount() {
	file, err := os.Open("init1.json")
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()
	autodiscover_count := 0
	decoder := json.NewDecoder(file)
	sem := make(chan struct{}, 10)
	var id int64 = 0
	var wg sync.WaitGroup
	if _, err := decoder.Token(); err != nil {
		log.Fatalf("Error reading JSON array: %v", err)
	}
	for decoder.More() {
		var obj DomainResult
		if err := decoder.Decode(&obj); err != nil {
			log.Fatalf("Error decoding JSON object: %v", err)
		}

		sem <- struct{}{} // 先占位
		wg.Add(1)
		go func(obj DomainResult) {
			defer wg.Done()
			defer func() { <-sem }()

			err := processDomainResult_onlycount(obj)
			if err == nil {
				autodiscover_count += 1
			}
			curID := atomic.AddInt64(&id, 1)
			fmt.Printf("%d\n", curID)

		}(obj)
	}

	wg.Wait()
	fmt.Printf("Only count Autodiscover: %d\n", autodiscover_count)
}
*/
// func processDomainResult_onlycount(obj DomainResult) error {
// 	// 打开或创建文件
// 	file, err := os.OpenFile("outputonlytry.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
// 	if err != nil {
// 		return fmt.Errorf("failed to open file: %v", err)
// 	}
// 	defer file.Close()

//		// domain := obj.Domain
//		for _, entry := range obj.Autodiscover {
//			if entry.Config != "" && !strings.HasPrefix(entry.Config, "Bad") && !strings.HasPrefix(entry.Config, "Errorcode") {
//				//if entry.Config != "" && !strings.HasPrefix(entry.Config, "Bad") {
//				doc := etree.NewDocument()
//				err := doc.ReadFromString(entry.Config)
//				if err == nil {
//					// 将entry.Config写入文件
//					_, err := file.WriteString(entry.Config + "\n")
//					if err != nil {
//						return fmt.Errorf("failed to write to file: %v", err)
//					}
//					return nil
//				}
//			}
//		}
//		return fmt.Errorf("not any xml format config")
//	}
func processtocount(obj DomainResult) bool {
	domain := obj.Domain
	for _, entry := range obj.Autoconfig {
		if entry.Config != "" && entry.Method == "ISPDB" {
			doc := etree.NewDocument()
			err := doc.ReadFromString(entry.Config)
			if err == nil && doc.SelectElement("clientConfig") != nil {
				fmt.Print(domain)
				return true
			}
		}
	}
	return false
}
func processcount() {
	file, err := os.Open("init1.json")
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	sem := make(chan struct{}, 50)
	var id int64 = 0
	var wg sync.WaitGroup
	var total_ISPDB int64 // 使用 int64 以便使用 atomic
	//var mu sync.Mutex
	if _, err := decoder.Token(); err != nil {
		log.Fatalf("Error reading JSON array: %v", err)
	}

	for decoder.More() {
		var obj DomainResult
		if err := decoder.Decode(&obj); err != nil {
			log.Fatalf("Error decoding JSON object: %v", err)
		}

		sem <- struct{}{} // 先占位
		wg.Add(1)
		go func(obj DomainResult) {
			defer wg.Done()
			defer func() { <-sem }()

			data := processtocount(obj)
			curID := atomic.AddInt64(&id, 1)
			fmt.Printf("%d\n", curID)

			if data {
				atomic.AddInt64(&total_ISPDB, 1)
			}
		}(obj)
	}
	// fmt.Print(total_ISPDB)
	wg.Wait()
	fmt.Print(atomic.LoadInt64(&total_ISPDB))
}

func check() {
	file, err := os.Open("init1.json")
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	outputFile := "check_results3.jsonl"
	sem := make(chan struct{}, 10)
	var id int64 = 0
	var wg sync.WaitGroup

	if _, err := decoder.Token(); err != nil {
		log.Fatalf("Error reading JSON array: %v", err)
	}

	for decoder.More() {
		var obj DomainResult
		if err := decoder.Decode(&obj); err != nil {
			log.Fatalf("Error decoding JSON object: %v", err)
		}

		sem <- struct{}{} // 先占位
		wg.Add(1)
		go func(obj DomainResult) {
			defer wg.Done()
			defer func() { <-sem }()

			data := processDomainResult(obj)
			curID := atomic.AddInt64(&id, 1)
			fmt.Printf("%d\n", curID)

			if data != nil {
				if err := saveCheckResultAsJSONL(data, outputFile); err != nil {
					log.Printf("Error saving check result for %v: %v", obj.Domain, err)
				}
			}
		}(obj)
	}

	wg.Wait()
}

func check2() {
	file, err := os.Open("init1.json")
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)

	// 打开一个新的文件以保存结果
	outputFile := "check_result22.jsonl" // 注意这里是 .jsonl 格式
	// 用来控制并发数量的信号量
	sem := make(chan struct{}, 50) // 控制并发数为 10

	var wg sync.WaitGroup
	// 跳过文件开头的数组符号
	if _, err := decoder.Token(); err != nil {
		log.Fatalf("Error reading JSON array: %v", err)
	}

	for {
		var obj DomainResult
		if err := decoder.Decode(&obj); err != nil {
			if err.Error() != "EOF" {
				log.Fatalf("Error decoding JSON object: %v", err)
			}
			break
		}
		// 每个域名的处理都交给一个 goroutine
		wg.Add(1)
		// 并发处理每个对象
		go func(obj DomainResult) {
			// 处理并获得 DomainCheckResult
			data := processDomainResult(obj)
			if data != nil {
				err = saveCheckResultAsJSONL(data, outputFile)
				if err != nil {
					log.Printf("Error saving check result for %v: %v", obj.Domain, err)
				}
			}
			// 释放信号量
			<-sem
		}(obj)
	}
	// 等待所有的 goroutine 完成
	wg.Wait()
}

// func count() {
// 	// 打开 .jsonl 文件
// 	file, err := os.Open("check_results2.jsonl")
// 	if err != nil {
// 		log.Fatalf("Failed to open file: %v", err)
// 	}
// 	defer file.Close()

// 	// 创建一个扫描器逐行读取文件
// 	scanner := bufio.NewScanner(file)

// 	// 用来统计符合条件的域名数量
// 	count := 0

// 	// 逐行解析 JSONL 文件
// 	for scanner.Scan() {
// 		line := scanner.Text()

// 		var domainCheckResult DomainCheckResult
// 		// 解析每一行的 JSON
// 		err := json.Unmarshal([]byte(line), &domainCheckResult)
// 		if err != nil {
// 			log.Printf("Error unmarshalling line: %v", err)
// 			continue
// 		}

// 		// 检查 AutodiscoverCheckResult 中的 Protocols
// 		if domainCheckResult.AutodiscoverCheckResult != nil && domainCheckResult.AutodiscoverCheckResult.Protocols != nil {
// 			for _, protocol := range domainCheckResult.AutodiscoverCheckResult.Protocols {
// 				// 检查 Type 是否为 imap，且 Port 是否为 993
// 				if protocol.Type == "IMAP" && protocol.Port == "993" {
// 					count++
// 					// 打印符合条件的域名
// 					fmt.Println("Matching domain:", domainCheckResult.Domain)
// 					break
// 				}
// 			}
// 		}
// 	}

// 	// 输出符合条件的域名数量
// 	fmt.Printf("Found %d domains with imap protocol and port 993 in AutodiscoverCheckResult\n", count)

//		// 处理文件读取错误
//		if err := scanner.Err(); err != nil {
//			log.Fatalf("Error reading file: %v", err)
//		}
//	}
func Countsettings_Autodiscover() (map[string]int, int) {
	// 打开 .jsonl 文件
	file, err := os.Open("check_results2.jsonl")
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()
	//用来统计符合条件的域名数量
	//count := 0
	reader := bufio.NewReader(file)
	protocolCount := map[string]int{
		"IMAP_143": 0,
		"IMAP_993": 0,
		//"IMAP_both":                              0,
		"IMAP_unexp": 0,
		"POP3_110":   0,
		"POP3_995":   0,
		//"POP3_both":                              0,
		"POP3_unexp": 0,
		"SMTP_465":   0,
		"SMTP_587":   0,
		"SMTP_25":    0,
		"SMTP_2525":  0,
		//"SMTP_both":                              0,
		"SMTP_unexp":  0,
		"not_any_enc": 0,
		"enc_ssl":     0,
		"enc_tls":     0,
		"enc_auto":    0,
		//"enc_starttls": 0,
		//"enc_defaultssl":                         0,
		"enc_not_valid":                          0,
		"ssl_not_valid":                          0,
		"ssl_on":                                 0,
		"ssl_off":                                0,
		"ssl_default_on":                         0,
		"protocol_count":                         0,
		"Error_root element <Autodiscover> lost": 0,
		"Error_missing <Response> element":       0,
		"Error_missing <User> element":           0,
		"Error_missing <DisplayName> in <User>":  0,
		"Error_missing <Account> element":        0,
		"Error_<AccountType> must be 'email'":    0,
		"Error_<Action> must be 'settings'":      0,
		"OverallCheck_not_valid":                 0,
	}
	Autodiscover_total := 0

	// // 创建一个扫描器逐行读取文件
	// scanner := bufio.NewScanner(file)
	// for scanner.Scan() {
	// 	line := scanner.Text()
	for {
		line, err := reader.ReadString('\n') // ✅ 按行读取
		if err != nil {
			break // 读完所有数据后退出
		}
		var domainCheckResult DomainCheckResult
		// 解析每一行的 JSON
		err = json.Unmarshal([]byte(line), &domainCheckResult)
		if err != nil {
			log.Printf("Error unmarshalling line: %v", err)
			continue
		}
		domain := domainCheckResult.Domain
		if domainCheckResult.AutodiscoverCheckResult != nil {
			Autodiscover_total += 1
		}
		//fmt.Print(domain + "\n")
		if domainCheckResult.AutodiscoverCheckResult != nil && domainCheckResult.AutodiscoverCheckResult.OverallCheck != "Valid" {
			//fmt.Print(domain)
			//Autodiscover_total += 1
			protocolCount["OverallCheck_not_valid"]++
			if domainCheckResult.AutodiscoverCheckResult.OverallCheck == "Invalid, root element <Autodiscover> lost" {
				protocolCount["Error_root element <Autodiscover> lost"]++
				save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_root element <Autodiscover> lost: ")
			} else if domainCheckResult.AutodiscoverCheckResult.OverallCheck == "Invalid, <Response> element lost" {
				protocolCount["Error_missing <Response> element"]++
				save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_missing <Response> element: ")
				// } else if domainCheckResult.AutodiscoverCheckResult.OverallCheck == "Invalid, <User> element lost" {
				// 	protocolCount["Error_missing <User> element"]++
				// 	save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_missing <User> element: ")
				// } else if domainCheckResult.AutodiscoverCheckResult.OverallCheck == "Invalid,missing <DisplayName> in <User>" {
				// 	protocolCount["Error_missing <DisplayName> in <User>"]++
				// 	save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_missing <DisplayName> in <User>: ")//3.8
			} else if domainCheckResult.AutodiscoverCheckResult.OverallCheck == "Invalid, missing <Account> element" {
				protocolCount["Error_missing <Account> element"]++
				// fmt.Print(domain)
				// fmt.Print("\n")
				save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_missing <Account> element: ")
			} else if domainCheckResult.AutodiscoverCheckResult.OverallCheck == "Invalid, <AccountType> must be 'email'" {
				protocolCount["Error_<AccountType> must be 'email'"]++
				save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_<AccountType> must be 'email': ")
			} else if domainCheckResult.AutodiscoverCheckResult.OverallCheck == "Invalid, <Action> must be 'settings'" {
				protocolCount["Error_<Action> must be 'settings'"]++
				save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_<Action> must be 'settings': ")
			}
			continue
		}
		if domainCheckResult.AutodiscoverCheckResult != nil && domainCheckResult.AutodiscoverCheckResult.OverallCheck == "Invalid, <User> element lost" {
			protocolCount["Error_missing <User> element"]++
			save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_missing <User> element: ")
		}
		if domainCheckResult.AutodiscoverCheckResult != nil && domainCheckResult.AutodiscoverCheckResult.OverallCheck == "Invalid,missing <DisplayName> in <User>" {
			protocolCount["Error_missing <DisplayName> in <User>"]++
			save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_missing <DisplayName> in <User>: ") //3.8
		}
		// 检查 AutodiscoverCheckResult 中的 Protocols
		if domainCheckResult.AutodiscoverCheckResult != nil && domainCheckResult.AutodiscoverCheckResult.Protocols != nil {
			// Autodiscover_total += 1
			//fmt.Print(domain)
			flag_imap_143 := false
			flag_imap_993 := false
			flag_imap_unexp := false
			flag_pop3_110 := false
			flag_pop3_995 := false
			flag_pop3_unexp := false
			flag_smtp_587 := false
			flag_smtp_465 := false
			flag_smtp_25 := false
			flag_smtp_2525 := false
			flag_smtp_unexp := false
			flag_enc_ssl := false
			flag_enc_tls := false
			flag_enc_auto := false
			flag_enc_none := false
			flag_ssl_on := false
			flag_ssl_off := false
			flag_ssl_default_on := false
			flag_enc_not_valid := false
			flag_ssl_not_valid := false
			for _, protocol := range domainCheckResult.AutodiscoverCheckResult.Protocols {
				if protocol.SingleCheck != "Valid" {
					save_content_tofile("./Autodiscover_Count_results.txt", domain, "protocol among Protocols is invalid': ")
				}
				// if protocol.SSL == "off" && (protocol.Encryption == "None" || protocol.Encryption == "none") {
				// 	protocolCount["not_any_enc"]++
				// } else if protocol.Encryption == "SSL" || protocol.Encryption == "ssl" || protocol.SSL == "on" {
				// 	protocolCount["enc_ssl"]++
				// } else if protocol.Encryption == "TLS" || protocol.Encryption == "tls" {
				// 	protocolCount["enc_tls"]++
				// } else if protocol.Encryption == "auto" || protocol.Encryption == "Auto" {
				// 	protocolCount["enc_auto"]++
				// } else if protocol.SSL == "starttls" || protocol.Encryption == "STARTTLS" { //这里没有考虑元素为<STARTTLS>的？
				// 	protocolCount["enc_starttls"]++
				// } else if protocol.SSL == "default(on)" {
				// 	protocolCount["enc_defaultssl"]++
				// }//3.8考虑Encryption会覆盖SSL元素
				if protocol.Encryption != "" {
					if protocol.Encryption == "SSL" {
						//protocolCount["enc_ssl"]++
						flag_enc_ssl = true
					} else if protocol.Encryption == "TLS" {
						//protocolCount["enc_tls"]++
						flag_enc_tls = true
					} else if protocol.Encryption == "Auto" {
						//protocolCount["enc_auto"]++
						flag_enc_auto = true
					} else if protocol.Encryption == "None" {
						//protocolCount["not_any_enc"]++
						flag_enc_none = true
					} else {
						flag_enc_not_valid = true
						protocolCount["enc_not_valid"]++ //不在这四个值之内的都不符合规范，需要记录
						save_content_tofile("./Autodiscover_Count_results.txt", protocol.Encryption, "Not valid <Encryption> value in domain "+domain+":")
					}
				} else {
					if protocol.SSL == "off" {
						//protocolCount["not_any_enc"]++
						flag_ssl_off = true
					} else if protocol.SSL == "on" {
						//protocolCount["enc_ssl"]++
						flag_ssl_on = true
					} else if protocol.SSL == "default(on)" {
						//protocolCount["enc_defaultssl"]++
						flag_ssl_default_on = true
					} else {
						flag_ssl_not_valid = true
						save_content_tofile("./Autodiscover_Count_results.txt", protocol.SSL, "Not valid <SSL> value in domain "+domain+":")
					}
				}

				switch protocol.Type {
				case "IMAP":
					protocolCount["protocol_count"]++
					if protocol.Port == "143" {
						flag_imap_143 = true
					} else if protocol.Port == "993" {
						flag_imap_993 = true
					} else {
						//fmt.Printf("%s,IMAP_unexp,%s\n", protocol.Server, protocol.Port)
						save_content_tofile("./Autodiscover_unexp_port_results.txt", protocol.Port, "unexp imap port in domain "+domain+","+protocol.Server+",")
						flag_imap_unexp = true
					}
				case "POP3":
					protocolCount["protocol_count"]++
					if protocol.Port == "110" {
						flag_pop3_110 = true
					} else if protocol.Port == "995" {
						flag_pop3_995 = true
					} else {
						save_content_tofile("./Autodiscover_unexp_port_results.txt", protocol.Port, "unexp pop3 port in domain "+domain+","+protocol.Server+",")
						//fmt.Printf("%s,POP3_unexp,%s\n", protocol.Server, protocol.Port)
						flag_pop3_unexp = true
					}
				case "SMTP":
					protocolCount["protocol_count"]++
					if protocol.Port == "465" {
						flag_smtp_465 = true
					} else if protocol.Port == "587" {
						flag_smtp_587 = true
					} else if protocol.Port == "25" {
						flag_smtp_25 = true
					} else if protocol.Port == "2525" {
						flag_smtp_2525 = true
					} else {
						save_content_tofile("./Autodiscover_unexp_port_results.txt", protocol.Port, "unexp smtp port in domain "+domain+","+protocol.Server+",")
						//fmt.Printf("%s, SMTP_unexp,%s\n", protocol.Server, protocol.Port)
						flag_smtp_unexp = true
					}
				}

			}
			if flag_imap_unexp {
				protocolCount["IMAP_unexp"]++
			}
			// if flag_imap_143 && flag_imap_993 {
			// 	protocolCount["IMAP_both"]++
			// } else if flag_imap_143 {
			// 	protocolCount["IMAP_only143"]++
			// } else if flag_imap_993 {
			// 	protocolCount["IMAP_only993"]++
			// }
			if flag_imap_143 {
				protocolCount["IMAP_143"]++
			}
			if flag_imap_993 {
				protocolCount["IMAP_993"]++
			}

			if flag_pop3_unexp {
				protocolCount["POP3_unexp"]++
			}
			// if flag_pop3_110 && flag_pop3_995 {
			// 	protocolCount["POP3_both"]++
			// } else if flag_pop3_110 {
			// 	protocolCount["POP3_only110"]++
			// } else if flag_pop3_995 {
			// 	protocolCount["POP3_only995"]++
			// }
			if flag_pop3_110 {
				protocolCount["POP3_110"]++
			}
			if flag_pop3_995 {
				protocolCount["POP3_995"]++
			}

			if flag_smtp_unexp {
				protocolCount["SMTP_unexp"]++
			}
			// if flag_smtp_465 && flag_smtp_587 {
			// 	protocolCount["SMTP_both"]++
			// } else if flag_smtp_465 {
			// 	protocolCount["SMTP_only465"]++
			// } else if flag_smtp_587 {
			// 	protocolCount["SMTP_only587"]++

			// }
			if flag_smtp_465 {
				protocolCount["SMTP_465"]++
			}
			if flag_smtp_587 {
				protocolCount["SMTP_587"]++
			}
			if flag_smtp_25 {
				protocolCount["SMTP_25"]++
			}
			if flag_smtp_2525 {
				protocolCount["SMTP_2525"]++
			}

			if flag_enc_auto {
				protocolCount["enc_auto"]++
			}
			if flag_enc_none {
				protocolCount["not_any_enc"]++
			}
			if flag_enc_not_valid {
				protocolCount["enc_not_valid"]++
			}
			if flag_enc_ssl {
				protocolCount["enc_ssl"]++
			}
			if flag_enc_tls {
				protocolCount["enc_tls"]++
			}

			if flag_ssl_default_on {
				protocolCount["ssl_default_on"]++
			}
			if flag_ssl_on {
				protocolCount["ssl_on"]++
			}
			if flag_ssl_off {
				protocolCount["ssl_off"]++
			}
			if flag_ssl_not_valid {
				protocolCount["ssl_not_valid"]++
			}
		}
	}

	// // // 输出符合条件的域名数量
	// // fmt.Printf("Found %d domains with imap protocol and port 993 in AutodiscoverCheckResult\n", count)

	// // 处理文件读取错误
	// if err := scanner.Err(); err != nil {
	// 	log.Fatalf("Error reading file: %v", err)
	// }
	return protocolCount, Autodiscover_total
}

func Countsettings_Autoconfig() (map[string]int, int) {
	file, err := os.Open("check_results2.jsonl")
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	protocolCount := map[string]int{
		"IMAP_143": 0,
		"IMAP_993": 0,
		//"IMAP_both":      0,
		"IMAP_unexp": 0,
		"POP3_110":   0,
		"POP3_995":   0,
		//"POP3_both":      0,
		"POP3_unexp": 0,
		// "SMTP_only465":   0,
		// "SMTP_only587":   0,
		"SMTP_465": 0,
		"SMTP_587": 0,
		//"SMTP_both":      0,
		"SMTP_25":        0,
		"SMTP_2525":      0,
		"SMTP_unexp":     0,
		"SSL":            0,
		"TLS":            0,
		"STARTTLS":       0,
		"plain":          0,
		"ssl_not_valid":  0,
		"protocol_count": 0,
		"Error_missing root element <clientConfig>": 0,
		"Error_missing <emailProvider> element":     0,
		"finalStatus_not_valid":                     0,
	}
	Autoconfig_total := 0

	//scanner := bufio.NewScanner(file)
	//for scanner.Scan() {
	for {
		line, err := reader.ReadString('\n') // ✅ 按行读取
		if err != nil {
			break // 读完所有数据后退出
		}

		//line := scanner.Text()
		var domainCheckResult DomainCheckResult
		// 解析每一行的 JSON
		err = json.Unmarshal([]byte(line), &domainCheckResult)
		if err != nil {
			log.Printf("Error unmarshalling line: %v", err)
			continue
		}
		domain := domainCheckResult.Domain
		if domainCheckResult.AutoconfigCheckResult != nil {
			Autoconfig_total += 1
		}
		if domainCheckResult.AutoconfigCheckResult != nil && domainCheckResult.AutoconfigCheckResult.OverallCheck != "Valid" {
			if domainCheckResult.AutoconfigCheckResult.OverallCheck == "Invalid, root element <clientConfig> lost" {
				protocolCount["Error_missing root element <clientConfig>"]++
			} else if domainCheckResult.AutoconfigCheckResult.OverallCheck == "Invalid, <emailProvider> element lost" {
				protocolCount["Error_missing <emailProvider> element"]++
			}
			continue
		}
		if domainCheckResult.AutoconfigCheckResult != nil && domainCheckResult.AutoconfigCheckResult.Protocols != nil {
			flag_imap_143 := false
			flag_imap_993 := false
			flag_imap_unexp := false
			flag_pop3_110 := false
			flag_pop3_995 := false
			flag_pop3_unexp := false
			flag_smtp_587 := false
			flag_smtp_465 := false
			flag_smtp_unexp := false
			flag_smtp_25 := false
			flag_smtp_2525 := false
			flag_ssl_plain := false
			flag_ssl_SSL := false
			flag_ssl_TLS := false
			flag_ssl_STARTTLS := false
			flag_ssl_not_valid := false
			for _, protocol := range domainCheckResult.AutoconfigCheckResult.Protocols {
				if protocol.SingleCheck != "Valid" {
					save_content_tofile("./Autoconfig_Count_results.txt", domain, "protocol among Protocols is invalid': ")
				}
				if protocol.SSL == "SSL" {
					//protocolCount["SSL"]++
					flag_ssl_SSL = true
				} else if protocol.SSL == "TLS" {
					//protocolCount["TLS"]++
					flag_ssl_TLS = true
				} else if protocol.SSL == "STARTTLS" {
					//protocolCount["STARTTLS"]++
					flag_ssl_STARTTLS = true
				} else if protocol.SSL == "plain" || protocol.SSL == "PLAIN" {
					//protocolCount["plain"]++
					flag_ssl_plain = true
				} else {
					flag_ssl_not_valid = true
					save_content_tofile("./Autoconfig_Count_results.txt", protocol.SSL, "Not valid <SSL> value in domain "+domain+":")
				}
				switch protocol.Type {
				case "imap":
					protocolCount["protocol_count"]++
					if protocol.Port == "143" {
						flag_imap_143 = true
					} else if protocol.Port == "993" {
						flag_imap_993 = true
					} else {
						//fmt.Printf("%s,imap_unexp,%s\n", protocol.Server, protocol.Port)
						save_content_tofile("./Autoconfig_unexp_port_results.txt", protocol.Port, "unexp imap port in domain "+domain+","+protocol.Server+",")
						flag_imap_unexp = true
					}
				case "pop3":
					protocolCount["protocol_count"]++
					if protocol.Port == "110" {
						flag_pop3_110 = true
					} else if protocol.Port == "995" {
						flag_pop3_995 = true
					} else {
						//fmt.Printf("%s,pop3_unexp,%s\n", protocol.Server, protocol.Port)
						save_content_tofile("./Autoconfig_unexp_port_results.txt", protocol.Port, "unexp pop3 port in domain "+domain+","+protocol.Server+",")
						flag_pop3_unexp = true
					}
				case "smtp":
					protocolCount["protocol_count"]++
					if protocol.Port == "465" {
						flag_smtp_465 = true
					} else if protocol.Port == "587" {
						flag_smtp_587 = true
					} else if protocol.Port == "25" {
						flag_smtp_25 = true
					} else if protocol.Port == "2525" {
						flag_smtp_2525 = true
					} else {
						save_content_tofile("./Autoconfig_unexp_port_results.txt", protocol.Port, "unexp smtp port in domain "+domain+","+protocol.Server+",")
						//fmt.Printf("%s,smtp_unexp,%s\n", protocol.Server, protocol.Port)
						flag_smtp_unexp = true
					}
				}
			}

			if flag_imap_unexp {
				protocolCount["IMAP_unexp"]++
			}
			// if flag_imap_143 && flag_imap_993 {
			// 	protocolCount["IMAP_both"]++
			// } else
			if flag_imap_143 {
				protocolCount["IMAP_143"]++
			}
			if flag_imap_993 {
				protocolCount["IMAP_993"]++
			}

			if flag_pop3_unexp {
				protocolCount["POP3_unexp"]++
			}
			// if flag_pop3_110 && flag_pop3_995 {
			// 	protocolCount["POP3_both"]++
			// } else
			if flag_pop3_110 {
				protocolCount["POP3_110"]++
			}
			if flag_pop3_995 {
				protocolCount["POP3_995"]++
			}

			if flag_smtp_unexp {
				protocolCount["SMTP_unexp"]++
			}
			// if flag_smtp_465 && flag_smtp_587 {
			// 	protocolCount["SMTP_both"]++
			// } else
			if flag_smtp_465 {
				protocolCount["SMTP_465"]++
			}
			if flag_smtp_587 {
				protocolCount["SMTP_587"]++
			}
			if flag_smtp_25 {
				protocolCount["SMTP_25"]++
			}
			if flag_smtp_2525 {
				protocolCount["SMTP_2525"]++
			}

			if flag_ssl_SSL {
				protocolCount["SSL"]++
			}
			if flag_ssl_TLS {
				protocolCount["TLS"]++
			}
			if flag_ssl_STARTTLS {
				protocolCount["STARTTLS"]++
			}
			if flag_ssl_plain {
				protocolCount["plain"]++
			}
			if flag_ssl_not_valid {
				protocolCount["ssl_not_valid"]++
			}

		}

	}

	return protocolCount, Autoconfig_total

	// if err != nil {
	// 	return nil, 0, fmt.Errorf("failed to process config folder:%v", err)
	// }

	//return protocolCount, Autoconfig_total, nil

}

func Countsettings_SRV() (map[string]int, int) {
	file, err := os.Open("check_results2.jsonl")
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	protocolCount := map[string]int{
		"IMAP_143":    0,
		"IMAP_993":    0,
		"IMAP_unexp":  0,
		"IMAPS_143":   0,
		"IMAPS_993":   0,
		"IMAPS_unexp": 0,
		"POP3_110":    0,
		"POP3_995":    0,
		"POP3_unexp":  0,
		"POP3S_110":   0,
		"POP3S_995":   0,
		"POP3S_unexp": 0,
		"SMTP_465":    0,
		"SMTP_587":    0,
		"SMTP_25":     0,
		"SMTP_2525":   0,
		"SMTP_unexp":  0,
		"SMTPS_465":   0,
		"SMTPS_587":   0,
		"SMTPS_25":    0,
		"SMTPS_2525":  0,
		"SMTPS_unexp": 0,
		// "SSL":            0,
		// "TLS":            0,
		// "STARTTLS":       0,
		// "plain":          0,
		// "ssl_not_valid":  0,
		"protocol_count": 0,
		// "Error_missing root element <clientConfig>": 0,
		// "Error_missing <emailProvider> element":     0,
		"OverallCheck_not_valid": 0,
	}
	SRV_total := 0

	for {
		line, err := reader.ReadString('\n') // ✅ 按行读取
		if err != nil {
			break // 读完所有数据后退出
		}
		var domainCheckResult DomainCheckResult
		// 解析每一行的 JSON
		err = json.Unmarshal([]byte(line), &domainCheckResult)
		if err != nil {
			log.Printf("Error unmarshalling line: %v", err)
			continue
		}
		domain := domainCheckResult.Domain
		if domainCheckResult.SRVCheckResult != nil {
			SRV_total += 1
		}
		if domainCheckResult.SRVCheckResult != nil && domainCheckResult.SRVCheckResult.OverallCheck != "Valid" {
			protocolCount["OverallCheck_not_valid"]++
			//continue
		}
		if domainCheckResult.SRVCheckResult != nil && domainCheckResult.SRVCheckResult.Protocols != nil {
			flag_imap_143 := false
			flag_imap_993 := false
			flag_imap_unexp := false
			flag_imaps_143 := false
			flag_imaps_993 := false
			flag_imaps_unexp := false
			flag_pop3_110 := false
			flag_pop3_995 := false
			flag_pop3_unexp := false
			flag_pop3s_110 := false
			flag_pop3s_995 := false
			flag_pop3s_unexp := false
			flag_smtp_587 := false
			flag_smtp_465 := false
			flag_smtp_unexp := false
			flag_smtp_25 := false
			flag_smtp_2525 := false
			flag_smtps_587 := false
			flag_smtps_465 := false
			flag_smtps_unexp := false
			flag_smtps_25 := false
			flag_smtps_2525 := false
			for _, protocol := range domainCheckResult.SRVCheckResult.Protocols {
				if protocol.SingleCheck != "Valid" {
					save_content_tofile("./SRV_Count_results.txt", domain, "protocol among Protocols is invalid': ")
				}
				switch protocol.Type {
				case "IMAP":
					protocolCount["protocol_count"]++
					if protocol.Port == "143" {
						flag_imap_143 = true
					} else if protocol.Port == "993" {
						flag_imap_993 = true
					} else {
						save_content_tofile("./SRV_unexp_port_results.txt", protocol.Port, "unexp imap port in domain "+domain+","+protocol.Server+",")
						flag_imap_unexp = true
					}
				case "IMAPS":
					protocolCount["protocol_count"]++
					if protocol.Port == "143" {
						flag_imaps_143 = true
					} else if protocol.Port == "993" {
						flag_imaps_993 = true
					} else {
						save_content_tofile("./SRV_unexp_port_results.txt", protocol.Port, "unexp imaps port in domain "+domain+","+protocol.Server+",")
						flag_imaps_unexp = true
					}
				case "POP3":
					protocolCount["protocol_count"]++
					if protocol.Port == "110" {
						flag_pop3_110 = true
					} else if protocol.Port == "995" {
						flag_pop3_995 = true
					} else {
						save_content_tofile("./SRV_unexp_port_results.txt", protocol.Port, "unexp pop3 port in domain "+domain+","+protocol.Server+",")
						flag_pop3_unexp = true
					}
				case "POP3S":
					protocolCount["protocol_count"]++
					if protocol.Port == "110" {
						flag_pop3s_110 = true
					} else if protocol.Port == "995" {
						flag_pop3s_995 = true
					} else {
						save_content_tofile("./SRV_unexp_port_results.txt", protocol.Port, "unexp pop3s port in domain "+domain+","+protocol.Server+",")
						flag_pop3s_unexp = true
					}
				case "SMTP":
					protocolCount["protocol_count"]++
					if protocol.Port == "465" {
						flag_smtp_465 = true
					} else if protocol.Port == "587" {
						flag_smtp_587 = true
					} else if protocol.Port == "25" {
						flag_smtp_25 = true
					} else if protocol.Port == "2525" {
						flag_smtp_2525 = true
					} else {
						save_content_tofile("./SRV_unexp_port_results.txt", protocol.Port, "unexp smtp port in domain "+domain+","+protocol.Server+",")
						flag_smtp_unexp = true
					}
				case "SMTPS":
					protocolCount["protocol_count"]++
					if protocol.Port == "465" {
						flag_smtps_465 = true
					} else if protocol.Port == "587" {
						flag_smtps_587 = true
					} else if protocol.Port == "25" {
						flag_smtps_25 = true
					} else if protocol.Port == "2525" {
						flag_smtps_2525 = true
					} else {
						save_content_tofile("./SRV_unexp_port_results.txt", protocol.Port, "unexp smtps port in domain "+domain+","+protocol.Server+",")
						flag_smtps_unexp = true
					}
				}
			}

			if flag_imap_unexp {
				protocolCount["IMAP_unexp"]++
			}
			if flag_imap_143 {
				protocolCount["IMAP_143"]++
			}
			if flag_imap_993 {
				protocolCount["IMAP_993"]++
			}
			if flag_imaps_unexp {
				protocolCount["IMAPS_unexp"]++
			}
			if flag_imaps_143 {
				protocolCount["IMAPS_143"]++
			}
			if flag_imaps_993 {
				protocolCount["IMAPS_993"]++
			}

			if flag_pop3_unexp {
				protocolCount["POP3_unexp"]++
			}
			if flag_pop3_110 {
				protocolCount["POP3_110"]++
			}
			if flag_pop3_995 {
				protocolCount["POP3_995"]++
			}
			if flag_pop3s_unexp {
				protocolCount["POP3S_unexp"]++
			}
			if flag_pop3s_110 {
				protocolCount["POP3S_110"]++
			}
			if flag_pop3s_995 {
				protocolCount["POP3S_995"]++
			}

			if flag_smtp_unexp {
				protocolCount["SMTP_unexp"]++
			}
			if flag_smtp_465 {
				protocolCount["SMTP_465"]++
			}
			if flag_smtp_587 {
				protocolCount["SMTP_587"]++
			}
			if flag_smtp_25 {
				protocolCount["SMTP_25"]++
			}
			if flag_smtp_2525 {
				protocolCount["SMTP_2525"]++
			}
			if flag_smtps_unexp {
				protocolCount["SMTPS_unexp"]++
			}
			if flag_smtps_465 {
				protocolCount["SMTPS_465"]++
			}
			if flag_smtps_587 {
				protocolCount["SMTPS_587"]++
			}
			if flag_smtps_25 {
				protocolCount["SMTPS_25"]++
			}
			if flag_smtps_2525 {
				protocolCount["SMTPS_2525"]++
			}

		}

	}

	return protocolCount, SRV_total

}

func save_content_tofile(fileName string, content string, inputFile string) { //记录数据统计结果到文件的函数
	// 打开文件，使用追加模式，如果不存在则创建
	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	inputfile_Name := filepath.Base(inputFile)
	// 写入内容
	content1 := inputfile_Name + content
	_, err = file.WriteString(content1 + "\n") // 每次追加一行内容
	if err != nil {
		fmt.Printf("Error writing to file: %v\n", err)
		return
	}
	//fmt.Printf("Successfully wrote to file: %s\n", fileName)
}

func Count() {
	protocolCount1, Autodiscover_total := Countsettings_Autodiscover()
	// fmt.Println(protocolCount1)
	write_map_ToFile("./Count_results.txt", protocolCount1, "Autodiscover")
	fmt.Printf("Usage of Autodiscover:%d\n", Autodiscover_total)
	save_number_tofile("./Count_results.txt", Autodiscover_total, "Usage of Autodiscover")

	protocolCount2, Autoconfig_total := Countsettings_Autoconfig()
	write_map_ToFile("./Count_results.txt", protocolCount2, "Autoconfig")
	fmt.Printf("Usage of Autoconfig:%d\n", Autoconfig_total)
	save_number_tofile("./Count_results.txt", Autoconfig_total, "Usage of Autoconfig")

	protocolCount3, SRV_total := Countsettings_SRV()
	write_map_ToFile("./Count_results.txt", protocolCount3, "SRV")
	fmt.Printf("Usage of SRV:%d\n", SRV_total)
	save_number_tofile("./Count_results.txt", SRV_total, "Usage of SRV")

}

func write_map_ToFile(fileName string, data map[string]int, method string) error {
	// 检查文件是否存在，若不存在则创建
	_, err := os.Stat(fileName)
	if os.IsNotExist(err) {
		// 文件不存在，创建文件
		_, err := os.Create(fileName)
		if err != nil {
			return fmt.Errorf("fail to create file: %v", err)
		}
	}

	// 以追加模式打开文件
	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("fail to open file: %v", err)
	}
	defer file.Close()

	file.WriteString("\n" + "Count result for Method: " + method + "\n")
	// 遍历 map 并写入文件
	for key, value := range data {
		line := fmt.Sprintf("%s:%d\n", key, value)
		_, err := file.WriteString(line)
		if err != nil {
			return fmt.Errorf("fail to write to file: %v", err)
		}
	}

	return nil
}
func save_number_tofile(fileName string, number int, inputFile string) { //记录数据统计结果到文件的函数
	// 打开文件，使用追加模式，如果不存在则创建
	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	inputfile_Name := filepath.Base(inputFile)
	// 写入内容
	content := fmt.Sprintf(inputfile_Name+": "+"%d", number)
	_, err = file.WriteString(content + "\n") // 每次追加一行内容
	if err != nil {
		fmt.Printf("Error writing to file: %v\n", err)
		return
	}
	fmt.Printf("Successfully wrote to file: %s\n", fileName)
}
