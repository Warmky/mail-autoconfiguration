package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

func check_dif_fromjson() {
	summaryFile, err := os.Create("privacy3/username_config_consistency_summary.txt") //4.27
	if err != nil {
		fmt.Println("❌ Failed to create summary file:", err)
		return
	}
	defer summaryFile.Close()

	//inputjsonFile := "/www/wwwroot/Golang/auto/privacy2/mailfence.com_post1_variants_dict.json" //从这里读取

	//inputjsonFile := "/www/wwwroot/Golang/auto/privacy2/okhatrimaza.com.so_post1_variants_dict.json"
	inputjsonFile := "privacypost2/ticketsales.com_post2_variants_random_sub.json"
	//从json文件里读取results数组，
	jsonFile, err := os.Open(inputjsonFile)
	if err != nil {
		fmt.Println("❌ Failed to open JSON file:", err)
		return
	}
	defer jsonFile.Close()

	// 读取整个文件内容
	jsonData, err := io.ReadAll(jsonFile)
	if err != nil {
		fmt.Println("❌ Failed to read JSON file:", err)
		return
	}

	// 定义 results 数组
	var results []AutodiscoverResult

	// 解析到 results 里
	err = json.Unmarshal(jsonData, &results)
	if err != nil {
		fmt.Println("❌ Failed to parse JSON:", err)
		return
	}

	var summary string

	if isConfigConsistent(results) {
		summary = "✅ All configs are consistent across usernames\n"
	} else {
		summary = "⚠️ Inconsistencies found in config across usernames\n"
	}
	summaryFile.WriteString(summary)
}
