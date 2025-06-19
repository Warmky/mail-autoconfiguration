package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/beevik/etree"
)

func countDomainsWithValidConfig(inputFile string) {
	file, err := os.Open(inputFile)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	sem := make(chan struct{}, 50) // 控制并发数
	var wg sync.WaitGroup

	// 统计变量
	var (
		domainProcessed                int64
		validAutodiscoverDomains       = make(map[string]struct{})
		autodiscoverFromPost           = make(map[string]struct{})
		autodiscoverFromSrvpost        = make(map[string]struct{})
		autodiscoverFromGetpost        = make(map[string]struct{})
		autodiscoverFromDirectGet      = make(map[string]struct{})
		validAutoconfigDomains         = make(map[string]struct{})
		autoconfigFromDirecturl        = make(map[string]struct{})
		autoconfigFromISPDB            = make(map[string]struct{})
		autoconfigFromMXSameDomain     = make(map[string]struct{})
		autoconfigFromMX               = make(map[string]struct{})
		validSRVDomains                = make(map[string]struct{})
		srvDNSSECPassed                = make(map[string]struct{})
		validOnlyAutodiscover          = make(map[string]struct{})
		validOnlyAutoconfig            = make(map[string]struct{})
		validOnlySRV                   = make(map[string]struct{})
		validAutodiscoverAndAutoconfig = make(map[string]struct{})
		validAutodiscoverAndSRV        = make(map[string]struct{})
		validAutoconfigAndSRV          = make(map[string]struct{})
		validThreeAll                  = make(map[string]struct{})
		validNone                      = make(map[string]struct{})
	)

	// 互斥锁保护共享变量
	var mu sync.Mutex

	if _, err := decoder.Token(); err != nil {
		log.Fatalf("Error reading JSON array: %v", err)
	}

	for decoder.More() {
		var obj DomainResult
		if err := decoder.Decode(&obj); err != nil {
			log.Fatalf("Error decoding JSON object: %v", err)
		}

		sem <- struct{}{} // 占位
		wg.Add(1)
		go func(obj DomainResult) {
			defer wg.Done()
			defer func() { <-sem }()

			domain := obj.Domain
			atomic.AddInt64(&domainProcessed, 1)

			// Autoconfig 统计
			for _, entry := range obj.Autoconfig {
				if entry.Config != "" {
					doc := etree.NewDocument()
					if err := doc.ReadFromString(entry.Config); err == nil {
						if doc.SelectElement("clientConfig") != nil {
							mu.Lock()
							validAutoconfigDomains[domain] = struct{}{}
							switch entry.Method {
							case "directurl":
								autoconfigFromDirecturl[domain] = struct{}{}
							case "ISPDB":
								autoconfigFromISPDB[domain] = struct{}{}
							case "MX_samedomain":
								autoconfigFromMXSameDomain[domain] = struct{}{}
							case "MX":
								autoconfigFromMX[domain] = struct{}{}
							}
							mu.Unlock()
						}
					}
				}
			}

			// Autodiscover 统计
			for _, entry := range obj.Autodiscover {
				if entry.Config != "" && !strings.HasPrefix(entry.Config, "Bad") && !strings.HasPrefix(entry.Config, "Errorcode") {
					doc := etree.NewDocument()
					if err := doc.ReadFromString(entry.Config); err == nil && doc.SelectElement("Autodiscover") != nil {
						mu.Lock()
						validAutodiscoverDomains[domain] = struct{}{}
						switch entry.Method {
						case "POST":
							autodiscoverFromPost[domain] = struct{}{}
						case "srv-post":
							autodiscoverFromSrvpost[domain] = struct{}{}
						case "get-post":
							autodiscoverFromGetpost[domain] = struct{}{}
						case "direct_get":
							autodiscoverFromDirectGet[domain] = struct{}{}
						}
						mu.Unlock()
					}
				}
			}

			// SRV 统计
			// SRV 统计
			if len(obj.SRV.RecvRecords) > 0 || len(obj.SRV.SendRecords) > 0 {
				mu.Lock()
				validSRVDomains[domain] = struct{}{}

				// 检查 DNSSEC
				if obj.SRV.DNSRecord != nil {
					dnssecPassed := true
					v := reflect.ValueOf(*obj.SRV.DNSRecord)
					for i := 0; i < v.NumField(); i++ {
						field := v.Field(i)
						fieldName := v.Type().Field(i).Name

						// 只检查以 "ADbit_" 开头的字段
						if strings.HasPrefix(fieldName, "ADbit_") {
							if field.Kind() == reflect.Ptr && !field.IsNil() {
								if !field.Elem().Bool() {
									dnssecPassed = false
									break
								}
							} else {
								dnssecPassed = false
								break
							}
						}
					}

					// 如果 DNSSEC 检查通过，添加到 srvDNSSECPassed
					if dnssecPassed {
						srvDNSSECPassed[domain] = struct{}{}
					}
				}
				mu.Unlock()
			}

			// 分类统计
			mu.Lock()
			_, hasAutoconfig := validAutoconfigDomains[domain]
			_, hasAutodiscover := validAutodiscoverDomains[domain]
			_, hasSRV := validSRVDomains[domain]

			switch {
			case hasAutoconfig && hasAutodiscover && hasSRV:
				validThreeAll[domain] = struct{}{}
			case hasAutoconfig && hasAutodiscover:
				validAutodiscoverAndAutoconfig[domain] = struct{}{}
			case hasAutoconfig && hasSRV:
				validAutoconfigAndSRV[domain] = struct{}{}
			case hasAutodiscover && hasSRV:
				validAutodiscoverAndSRV[domain] = struct{}{}
			case hasAutoconfig:
				validOnlyAutoconfig[domain] = struct{}{}
			case hasAutodiscover:
				validOnlyAutodiscover[domain] = struct{}{}
			case hasSRV:
				validOnlySRV[domain] = struct{}{}
			default:
				validNone[domain] = struct{}{}
			}
			mu.Unlock()
		}(obj)
	}

	wg.Wait()

	// 输出统计结果
	fmt.Printf("✅ 通过 Autodiscover 可以获取配置信息的域名数量: %d\n", len(validAutodiscoverDomains))
	fmt.Printf("✅ 通过 Autodiscover_post 可以获取配置信息的域名数量: %d\n", len(autodiscoverFromPost))
	fmt.Printf("✅ 通过 Autodiscover_srvpost 可以获取配置信息的域名数量: %d\n", len(autodiscoverFromSrvpost))
	fmt.Printf("✅ 通过 Autodiscover_getpost 可以获取配置信息的域名数量: %d\n", len(autodiscoverFromGetpost))
	fmt.Printf("✅ 通过 Autodiscover_direct_get 可以获取配置信息的域名数量: %d\n", len(autodiscoverFromDirectGet))

	fmt.Printf("✅ 通过 Autoconfig 可以获取配置信息的域名数量: %d\n", len(validAutoconfigDomains))
	fmt.Printf("✅ 通过 Autoconfig_directurl 可以获取配置信息的域名数量: %d\n", len(autoconfigFromDirecturl))
	fmt.Printf("✅ 通过 Autoconfig_ISPDB 可以获取配置信息的域名数量: %d\n", len(autoconfigFromISPDB))
	fmt.Printf("✅ 通过 Autoconfig_MX_samedomain 可以获取配置信息的域名数量: %d\n", len(autoconfigFromMXSameDomain))
	fmt.Printf("✅ 通过 Autoconfig_MX 可以获取配置信息的域名数量: %d\n", len(autoconfigFromMX))

	fmt.Printf("✅ 通过 SRV 可以获取配置信息的域名数量: %d\n", len(validSRVDomains))
	fmt.Printf("✅ 通过 SRV 可以获取配置信息且 DNSSEC 检查通过的域名数量: %d\n", len(srvDNSSECPassed))

	fmt.Printf("✅ 可以通过 Autodiscover、Autoconfig、SRV 获取配置信息的域名数量: %d\n", len(validThreeAll))
	fmt.Printf("✅ 可以通过 Autodiscover、Autoconfig 获取配置信息的域名数量: %d\n", len(validAutodiscoverAndAutoconfig))
	fmt.Printf("✅ 可以通过 Autodiscover、SRV 获取配置信息的域名数量: %d\n", len(validAutodiscoverAndSRV))
	fmt.Printf("✅ 可以通过 Autoconfig、SRV 获取配置信息的域名数量: %d\n", len(validAutoconfigAndSRV))
	fmt.Printf("✅ 仅可以通过 Autodiscover 获取配置信息的域名数量: %d\n", len(validOnlyAutodiscover))
	fmt.Printf("✅ 仅可以通过 Autoconfig 获取配置信息的域名数量: %d\n", len(validOnlyAutoconfig))
	fmt.Printf("✅ 仅可以通过 SRV 获取配置信息的域名数量: %d\n", len(validOnlySRV))
	fmt.Printf("✅ 无法通过任意方法获取配置信息的域名数量: %d\n", len(validNone))

	fmt.Printf("✅ 一共处理了域名数量: %d\n", domainProcessed)

	// // 将 autoconfig_from_ISPDB 写入文件
	// autoconfigFromISPDBList := mapToSlice(autoconfigFromISPDB)
	// if err := saveToJSON("autoconfig_from_ISPDB.json", autoconfigFromISPDBList); err != nil {
	// 	log.Fatalf("Error saving autoconfig_from_ISPDB: %v", err)
	// }

	// // 将 domain_stats 写入文件
	// dataToSave := map[string]interface{}{
	// 	"valid_autodiscover_domains":        mapToSlice(validAutodiscoverDomains),
	// 	"autodiscover_from_post":            mapToSlice(autodiscoverFromPost),
	// 	"autodiscover_from_srvpost":         mapToSlice(autodiscoverFromSrvpost),
	// 	"autodiscover_from_getpost":         mapToSlice(autodiscoverFromGetpost),
	// 	"autodiscover_from_direct_get":      mapToSlice(autodiscoverFromDirectGet),
	// 	"valid_autoconfig_domains":          mapToSlice(validAutoconfigDomains),
	// 	"autoconfig_from_directurl":         mapToSlice(autoconfigFromDirecturl),
	// 	"autoconfig_from_ISPDB":             mapToSlice(autoconfigFromISPDB),
	// 	"autoconfig_from_MX_samedomain":     mapToSlice(autoconfigFromMXSameDomain),
	// 	"autoconfig_from_MX":                mapToSlice(autoconfigFromMX),
	// 	"valid_srv_domains":                 mapToSlice(validSRVDomains),
	// 	"srv_dnssec_passed":                 mapToSlice(srvDNSSECPassed),
	// 	"valid_three_all":                   mapToSlice(validThreeAll),
	// 	"valid_autodiscover_and_autoconfig": mapToSlice(validAutodiscoverAndAutoconfig),
	// 	"valid_autodiscover_and_srv":        mapToSlice(validAutodiscoverAndSRV),
	// 	"valid_autoconfig_and_srv":          mapToSlice(validAutoconfigAndSRV),
	// 	"valid_only_autodiscover":           mapToSlice(validOnlyAutodiscover),
	// 	"valid_only_autoconfig":             mapToSlice(validOnlyAutoconfig),
	// 	"valid_only_srv":                    mapToSlice(validOnlySRV),
	// 	"valid_none":                        mapToSlice(validNone),
	// }

	// if err := saveToJSON("domain_stats.json", dataToSave); err != nil {
	// 	log.Fatalf("Error saving domain_stats: %v", err)
	// }
}

func mapToSlice(m map[string]struct{}) []string {
	slice := make([]string, 0, len(m))
	for key := range m {
		slice = append(slice, key)
	}
	return slice
}

func saveToJSON(filename string, data interface{}) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ") // 设置缩进为 4 个空格
	encoder.SetEscapeHTML(false)  // 不转义 HTML 字符

	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode data to JSON: %v", err)
	}

	fmt.Printf("✅ %s saved to '%s'.\n", filename, filename)
	return nil
}

func countDomainsWithSRV_prefix(inputFile string) {
	file, err := os.Open(inputFile)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	sem := make(chan struct{}, 50) // 控制并发数
	var wg sync.WaitGroup

	prefixCounter := make(map[string]int)
	var mu sync.Mutex // 添加互斥锁

	var pop3sDomains []string // 用于收集 pop3s 域名
	var popMu sync.Mutex      // 控制 pop3s 域名并发写入

	if _, err := decoder.Token(); err != nil {
		log.Fatalf("Error reading JSON array: %v", err)
	}

	for decoder.More() {
		var obj DomainResult
		if err := decoder.Decode(&obj); err != nil {
			log.Fatalf("Error decoding JSON object: %v", err)
		}

		sem <- struct{}{}
		wg.Add(1)
		go func(obj DomainResult) {
			defer wg.Done()
			defer func() { <-sem }()

			if len(obj.SRV.RecvRecords) > 0 || len(obj.SRV.SendRecords) > 0 {
				allRecords := append(obj.SRV.RecvRecords, obj.SRV.SendRecords...)
				localCounter := make(map[string]int) // 每个 goroutine 自己统计
				pop3sFound := false
				for _, record := range allRecords {
					parts := strings.Split(record.Service, ".")
					if len(parts) > 0 {
						prefix := parts[0]
						localCounter[prefix]++

						if prefix == "_pop3s" {
							pop3sFound = true
						}
					}
				}

				mu.Lock()
				for prefix, count := range localCounter {
					prefixCounter[prefix] += count
				}
				mu.Unlock()

				if pop3sFound {
					popMu.Lock()
					pop3sDomains = append(pop3sDomains, obj.Domain)
					popMu.Unlock()
				}
			}
		}(obj)
	}

	wg.Wait()

	// ✅ 最后统一打印统计结果
	fmt.Println("📊 SRV 服务前缀统计：")
	for prefix, count := range prefixCounter {
		fmt.Printf("- %s: %d\n", prefix, count)
	}

	// 写入 pop3s 域名到文件
	if len(pop3sDomains) > 0 {
		outputFile := "pop3s_domains.txt"
		if err := os.WriteFile(outputFile, []byte(strings.Join(pop3sDomains, "\n")), 0644); err != nil {
			log.Fatalf("Failed to write pop3s domains file: %v", err)
		}
		fmt.Printf("✅ 写入 pop3s 域名到 %s（共 %d 个域名）\n", outputFile, len(pop3sDomains))
	} else {
		fmt.Println("⚠️ 没有发现包含 pop3s 前缀的域名。")
	}
}
