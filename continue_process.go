package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// DomainEntry 结构体匹配 JSONL 中的格式
type DomainEntry struct {
	Domain string `json:"domain"`
}

func extractProcessedDomains(jsonlFile, outputTxt string) error {
	processedDomains := make(map[string]struct{}) // 记录已经查询的域名

	file, err := os.Open(jsonlFile)
	if err != nil {
		return fmt.Errorf("failed to open JSONL file: %v", err)
	}
	defer file.Close()

	output, err := os.Create(outputTxt)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer output.Close()

	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n') // 逐行读取 JSONL
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading JSONL: %v", err)
		}

		// 解析 JSON
		var entry DomainEntry
		err = json.Unmarshal([]byte(line), &entry)
		if err == nil {
			// 避免重复存储
			if _, exists := processedDomains[entry.Domain]; !exists {
				processedDomains[entry.Domain] = struct{}{}
				_, writeErr := output.WriteString(entry.Domain + "\n")
				if writeErr != nil {
					return fmt.Errorf("error writing to output file: %v", writeErr)
				}
			}
		}
	}

	fmt.Println("Processed domains saved to:", outputTxt)
	return nil
}

func filterRemainingDomains(csvFile, processedFile, outputCSV string) error {
	// 读取 processed_domains.txt，存入 map
	processedDomains := make(map[string]struct{})
	file, err := os.Open(processedFile)
	if err != nil {
		return fmt.Errorf("failed to open processed domains file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		processedDomains[scanner.Text()] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading processed domains file: %v", err)
	}

	// 处理 tranco.csv
	input, err := os.Open(csvFile)
	if err != nil {
		return fmt.Errorf("failed to open CSV file: %v", err)
	}
	defer input.Close()

	reader := csv.NewReader(input)
	output, err := os.Create(outputCSV)
	if err != nil {
		return fmt.Errorf("failed to create output CSV: %v", err)
	}
	defer output.Close()

	writer := csv.NewWriter(output)
	defer writer.Flush()

	lineIndex := 0
	for {
		record, err := reader.Read()
		if err != nil {
			break
		}

		if len(record) > 1 {
			domain := strings.TrimSpace(record[1])
			if domain != "" {
				// 仅保留未查询的域名
				if _, exists := processedDomains[domain]; !exists {
					writer.Write(record)
				}
			}
		}
		lineIndex++
	}

	fmt.Println("Remaining domains saved to:", outputCSV)
	return nil
}
func dcontinue() {
	jsonlFile := "init.jsonl"
	processedTxt := "processed_domains.txt"
	csvFile := "tranco_KJ7VW.csv"
	remainingCSV := "remaining_domains.csv"

	// 1. 提取已经查询的域名
	err := extractProcessedDomains(jsonlFile, processedTxt)
	if err != nil {
		fmt.Println("Error extracting processed domains:", err)
		return
	}

	// 2. 过滤出未查询的域名
	err = filterRemainingDomains(csvFile, processedTxt, remainingCSV)
	if err != nil {
		fmt.Println("Error filtering remaining domains:", err)
		return
	}

	fmt.Println("Now you can run process() on", remainingCSV)
}
