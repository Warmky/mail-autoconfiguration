package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/tidwall/gjson"
)

// 从zgrab2/real文件夹下的各个.jsonl中提取出error==no such host的domain
func extract_no_such_host() {
	rootDir := "/www/wwwroot/Golang/pkg/mod/github.com/zmap/zgrab2@v0.1.8/cmd/zgrab2/real" // 父级目录
	files, err := filepath.Glob(filepath.Join(rootDir, "*.jsonl"))
	if err != nil {
		fmt.Println("读取文件失败:", err)
		return
	}

	numWorkers := runtime.NumCPU()
	fileChan := make(chan string, numWorkers)
	resultChan := make(chan string, numWorkers)
	var wg sync.WaitGroup

	// 启动并发 worker
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range fileChan {
				processFile(file, resultChan)
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 分发文件给 worker
	go func() {
		for _, file := range files {
			fileChan <- file
		}
		close(fileChan)
	}()

	outputFile, err := os.Create("no_such_host_domains.txt")
	if err != nil {
		fmt.Println("无法创建输出文件:", err)
		return
	}
	defer outputFile.Close()

	writer := bufio.NewWriter(outputFile)
	defer writer.Flush()

	for result := range resultChan {
		writer.WriteString(result + "\n")
	}

	fmt.Println("处理完成！")
}

func processFile(filePath string, resultChan chan<- string) {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("无法打开文件:", filePath, err)
		return
	}
	defer file.Close()
	fmt.Printf("Processing file: %s", filePath)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		domain := gjson.Get(line, "domain").String()
		data := gjson.Get(line, "data")

		protocol := ""
		data.ForEach(func(key, _ gjson.Result) bool {
			protocol = key.String()
			return false // 只取第一个协议
		})

		if protocol != "" {
			errPath := fmt.Sprintf("data.%s.error", protocol)
			errMsg := gjson.Get(line, errPath).String()
			if strings.HasSuffix(errMsg, "no such host") && domain != "name" {
				// resultChan <- fmt.Sprintf("%s %s", domain, errMsg)
				resultChan <- domain
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("读取文件出错:", filePath, err)
	}
}
