package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/beevik/etree"
)

func check_config_if_same(inputFile string) {
	file, err := os.Open(inputFile)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	sem := make(chan struct{}, 50) // 控制并发数
	var wg sync.WaitGroup

	domainConfigs := make(map[string]map[string]struct{})

	// 互斥锁保护共享变量
	var mu sync.Mutex

	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("Error reading line: %v", err)
		}

		var obj DomainResult
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			log.Printf("❌ JSON 解析失败，跳过此行: %v", err)
			continue
		}

		sem <- struct{}{} // 占位
		wg.Add(1)
		go func(obj DomainResult) {
			defer wg.Done()
			defer func() { <-sem }()

			domain := obj.Domain

			// // Autoconfig 统计
			// for _, entry := range obj.Autoconfig {
			// 	if entry.Config != "" {
			// 		doc := etree.NewDocument()
			// 		if err := doc.ReadFromString(entry.Config); err == nil {
			// 			if doc.SelectElement("clientConfig") != nil {
			// 				mu.Lock()
			// 				if _, exists := domainConfigs[domain]; !exists {
			// 					domainConfigs[domain] = make(map[string]struct{})
			// 				}
			// 				domainConfigs[domain][entry.Config] = struct{}{}
			// 				mu.Unlock()
			// 			}
			// 		}
			// 	}
			// }

			// Autodiscover 统计
			for _, entry := range obj.Autodiscover {
				if entry.Config != "" && !strings.HasPrefix(entry.Config, "Bad") && !strings.HasPrefix(entry.Config, "Errorcode") {
					doc := etree.NewDocument()
					if err := doc.ReadFromString(entry.Config); err == nil && doc.SelectElement("Autodiscover") != nil {
						mu.Lock()
						if _, exists := domainConfigs[domain]; !exists {
							domainConfigs[domain] = make(map[string]struct{})
						}
						domainConfigs[domain][entry.Config] = struct{}{}
						mu.Unlock()
					}
				}
			}

			// // SRV 统计
			// if len(obj.SRV.RecvRecords) > 0 || len(obj.SRV.SendRecords) > 0 {
			// 	mu.Lock()
			// 	validSRVDomains[domain] = struct{}{}
			// 	mu.Unlock()

			// 	// 检查 DNSSEC
			// 	if obj.SRV.DNSRecord != nil {
			// 		dnssecPassed := true
			// 		dnsRecord := obj.SRV.DNSRecord

			// 		// 只检查存在的 ADbit_ 字段是否全部为 true
			// 		existingFields := []*bool{
			// 			dnsRecord.ADbit_imap, dnsRecord.ADbit_imaps,
			// 			dnsRecord.ADbit_pop3, dnsRecord.ADbit_pop3s,
			// 			dnsRecord.ADbit_smtp, dnsRecord.ADbit_smtps,
			// 		}

			// 		hasCheckedFields := false
			// 		for _, field := range existingFields {
			// 			if field != nil { // 只检查存在的字段
			// 				hasCheckedFields = true
			// 				if !*field { // 只要有一个 false，就不通过
			// 					dnssecPassed = false
			// 					break
			// 				}
			// 			}
			// 		}
			// 		// 如果 DNSSEC 检查通过，添加到 srvDNSSECPassed
			// 		if dnssecPassed && hasCheckedFields {
			// 			mu.Lock()
			// 			srvDNSSECPassed[domain] = struct{}{}
			// 			mu.Unlock()
			// 		}
			// 	}
			// }

			// // 分类统计
			// mu.Lock()
			// _, hasAutoconfig := validAutoconfigDomains[domain]
			// _, hasAutodiscover := validAutodiscoverDomains[domain]
			// _, hasSRV := validSRVDomains[domain]

			// switch {
			// case hasAutoconfig && hasAutodiscover && hasSRV:
			// 	validThreeAll[domain] = struct{}{}
			// case hasAutoconfig && hasAutodiscover:
			// 	validAutodiscoverAndAutoconfig[domain] = struct{}{}
			// case hasAutoconfig && hasSRV:
			// 	validAutoconfigAndSRV[domain] = struct{}{}
			// case hasAutodiscover && hasSRV:
			// 	validAutodiscoverAndSRV[domain] = struct{}{}
			// case hasAutoconfig:
			// 	validOnlyAutoconfig[domain] = struct{}{}
			// case hasAutodiscover:
			// 	validOnlyAutodiscover[domain] = struct{}{}
			// case hasSRV:
			// 	validOnlySRV[domain] = struct{}{}
			// default:
			// 	validNone[domain] = struct{}{}
			// }
			// mu.Unlock()
		}(obj)
	}

	wg.Wait()

	inconsistentConfigs := make(map[string]struct{}) // 记录有多个不同配置的域名

	for domain, configs := range domainConfigs {
		if len(configs) > 1 { // 发现不同的 Config
			inconsistentConfigs[domain] = struct{}{}
			fmt.Printf("⚠️  域名 %s 存在多个不同的配置\n", domain)
		}
	}
	fmt.Printf("共有域名不同配置：%d", len(inconsistentConfigs))

}
