'''
分析服务不可用的原因01
'''
import ijson
import json
from urllib.parse import urlparse
import tldextract

input_file = "init1.json"
output_file = "service_error_500.jsonl"
output_file_501 = "service_error_501.jsonl"
output_file_502 = "service_error_502.jsonl"
output_file_503 = "service_error_503.jsonl"
output_file_504 = "service_error_504.jsonl"
output_file_505 = "service_error_505.jsonl"


def normalize_domain(domain):
    # 提取注册域名
    return tldextract.extract(domain).registered_domain

def extract_service_error_500_info(input_file):
    with open(input_file, "r", encoding="utf-8") as f:
        objects = ijson.items(f, "item")  # 流式解析 JSON 数组中的对象
        for obj in objects:
            domain = obj.get("domain")
            for entry in obj.get("autodiscover", []):
                if entry.get("error", "").startswith("unexpected status code: 500"):
                    redirects = entry.get("redirects", [])
                    if redirects:
                        simplified_redirects = [normalize_domain(redirects[0]["URL"])]
                        for index, redirect in enumerate(redirects[1:], start=1):
                            if normalize_domain(redirect["URL"]) != normalize_domain(redirects[index-1]["URL"]): #如果标准化域名后不等于前一个就添加
                                simplified_redirects.append(normalize_domain(redirect["URL"]))
                        redirect_info = {
                            "domain":domain,
                            "redirects":simplified_redirects,
                        }
                        with open(output_file, "a", encoding="utf-8") as out_f:
                            out_f.write(json.dumps(redirect_info) + "\n")
                        break# 同一个域名提取一个就好

# extract_service_error_500_info(input_file)


def extract_service_error_info(input_file):
    with open(input_file, "r", encoding="utf-8") as f:
        objects = ijson.items(f, "item")  # 流式解析 JSON 数组中的对象
        for obj in objects:
            domain = obj.get("domain")
            for entry in obj.get("autodiscover", []):
                if entry.get("error", "").startswith("unexpected status code: 5"):
                    redirects = entry.get("redirects", [])
                    if redirects:
                        simplified_redirects = [normalize_domain(redirects[0]["URL"])]
                        for index, redirect in enumerate(redirects[1:], start=1):
                            if normalize_domain(redirect["URL"]) != normalize_domain(redirects[index-1]["URL"]): #如果标准化域名后不等于前一个就添加
                                simplified_redirects.append(normalize_domain(redirect["URL"]))
                        redirect_info = {
                            "domain":domain,
                            "redirects":simplified_redirects,
                        }
                        if entry.get("error", "").endswith("501"):
                            with open(output_file_501, "a", encoding="utf-8") as out_f:
                                out_f.write(json.dumps(redirect_info) + "\n")
                        elif entry.get("error", "").endswith("502"):
                            with open(output_file_502, "a", encoding="utf-8") as out_f:
                                out_f.write(json.dumps(redirect_info) + "\n")
                        elif entry.get("error", "").endswith("503"):
                            with open(output_file_503, "a", encoding="utf-8") as out_f:
                                out_f.write(json.dumps(redirect_info) + "\n")
                        elif entry.get("error", "").endswith("504"):
                            with open(output_file_504, "a", encoding="utf-8") as out_f:
                                out_f.write(json.dumps(redirect_info) + "\n")
                        elif entry.get("error", "").endswith("505"):
                            with open(output_file_505, "a", encoding="utf-8") as out_f:
                                out_f.write(json.dumps(redirect_info) + "\n")
                        
                        break# 同一个域名提取一个就好

extract_service_error_info(input_file)               