import ijson
import json
from urllib.parse import urlparse
import tldextract
'''
用来从原始的配置记录文件init1.json中提取出重定向有关的信息，生成.jsonl文件 01
'''
input_file = "init1.json"
output_file = "filtered_redirects_autoconfig_310.jsonl"  # 存储符合条件的重定向链信息

# 函数：标准化为注册域名
def normalize_domain(domain):
    # 提取注册域名
    return tldextract.extract(domain).registered_domain

def extract_redirect_info(input_file):
    with open(input_file, "r", encoding="utf-8") as f:
        objects = ijson.items(f, "item")  # 流式解析 JSON 数组中的对象
        for obj in objects:
            domain = obj.get("domain")
            for entry in obj.get("autoconfig", []):
                redirects = entry.get("redirects", [])
                if redirects:
                    # 获取重定向链中的状态码
                    chainlast_autodiscover_code = redirects[-1].get("Status")
                    # 筛选状态码在 200 到 299 之间的且没有解析错误的重定向链
                    if (200 <= chainlast_autodiscover_code < 300 and entry.get("error", "")==""):
                        
                        
                        # 标准化域名
                        normalized_redirects = [normalize_domain(redirect["URL"]) for redirect in redirects]
                        
                        # 如果重定向链中第一个和最后一个标准化域名相同，则去除环
                        if normalized_redirects[0] == normalized_redirects[-1]:
                            continue #3.10
                            #break #3.10 
                        
                        # 提取符合条件的信息
                        redirect_info = {
                            "domain": domain,
                            "redirects": normalized_redirects,
                        }
                        
                        # 保存提取的符合条件的信息到文件
                        with open(output_file, "a", encoding="utf-8") as out_f:
                            out_f.write(json.dumps(redirect_info) + "\n")
                            #break# 同一个域名提取一个就好 #3.10

extract_redirect_info(input_file)

