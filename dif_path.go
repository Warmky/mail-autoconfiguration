package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
)

// 提取关键字段 (Type 除外)
func extractKey(p ProtocolInfo) string {
	return fmt.Sprintf("%s|%s|%s", p.Server, p.Port, p.SSL)
}

// 检查两个 Autoconfig 结果是否符合要求
func isMatchingAutoconfig(ac1, ac2 []ProtocolInfo) bool {
	// 统计两者的协议信息
	set1 := make(map[string]string) // 不包含 Type 的键
	set2 := make(map[string]string)
	countExchange1 := 0
	countExchange2 := 0

	for _, p := range ac1 {
		key := extractKey(p)
		set1[key] = p.Type
		if p.Type == "exchange" {
			countExchange1++
		}
	}
	for _, p := range ac2 {
		key := extractKey(p)
		set2[key] = p.Type
		if p.Type == "exchange" {
			countExchange2++
		}
	}

	// 确保只有一个包含 "exchange" 类型
	if (countExchange1 == 1 && countExchange2 == 0) || (countExchange1 == 0 && countExchange2 == 1) {
		// 移除 exchange 类型，比较其他协议是否完全一致
		for key, t1 := range set1 {
			if t1 == "exchange" {
				delete(set1, key)
			}
		}
		for key, t2 := range set2 {
			if t2 == "exchange" {
				delete(set2, key)
			}
		}
		return reflect.DeepEqual(set1, set2)
	}
	return false
}

func dif_autoconfig() {
	file, err := os.Open("check_results320_onlysome.jsonl")
	if err != nil {
		fmt.Println("无法打开文件:", err)
		return
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	count := 0

	for {
		// 读取一整行
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		// 去掉前后空白字符
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var result DomainCheckResult
		err = json.Unmarshal([]byte(line), &result)
		if err != nil {
			fmt.Println("解析 JSON 失败:", err)
			continue
		}

		// 需要 AutoconfigInconsistent: true
		if !result.AutoconfigInconsistent {
			continue
		}

		// 需要有两个 Autoconfig 结果
		if len(result.AutoconfigCheckResult) != 2 {
			continue
		}

		ac1 := result.AutoconfigCheckResult[0].Protocols
		ac2 := result.AutoconfigCheckResult[1].Protocols

		if isMatchingAutoconfig(ac1, ac2) {
			count++
			fmt.Print(result.Domain + " ")
		}
	}

	fmt.Println("符合条件的域名数量:", count)
}
