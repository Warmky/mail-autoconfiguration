import json
from urllib.parse import urlparse
import csv

input_file = "filtered_redirects.jsonl"  # 输入文件

# 将图直接保存为 CSV 文件，包含 source, target 和 weight 列
def save_graph_to_csv(input_file):
    with open("graph.csv", mode="w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["source", "target", "weight"])  # 写入表头
        
        # 流式解析并分析重定向
        with open(input_file, "r", encoding="utf-8") as f_jsonl:
            for line in f_jsonl:
                # 使用 json.loads 解析每一行
                obj = json.loads(line.strip())  # 使用 strip 去掉可能的空白字符
                domain = obj.get("domain")
                redirects = obj.get("redirects", [])

                if redirects:  # 如果 redirects 列表不为空
                    current_domain = redirects[0]  # 初始化当前域名为第一个域名

                    # 遍历所有的重定向
                    for i, redirect in enumerate(redirects):
                        # 如果当前域名和下一个域名不同，则认为是向外的箭头
                        if redirect != current_domain:
                            writer.writerow([current_domain, redirect, 1])  # 直接写入 source, target 和 weight
                        # 如果是自环，即当前域名和下一个域名相同，则跳过
                        elif redirect == current_domain:
                            continue
                        
                        current_domain = redirect  # 更新当前域名为下一个域名

    print("Graph saved to graph.csv")

# 执行分析并保存图
save_graph_to_csv(input_file)
# Invalid