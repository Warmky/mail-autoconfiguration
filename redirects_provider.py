import ijson
import xml.etree.ElementTree as ET
import json
from urllib.parse import urlparse 

input_file = "init1.json"

# 重定向分析服务商准备
def redirect(input_file):
    with open(input_file, "r", encoding="utf-8") as f:
        objects = ijson.items(f, "item")  # 流式解析 JSON 数组中的对象
        for obj in objects:
            domain = obj.get("domain")
            for entry in obj.get("autodiscover", []):
                redirects = entry.get("redirects", [])
                if redirects:  # 确保 redirects 不为空
                    chainlast_autodiscover_code = redirects[-1].get("Status")
                    if (chainlast_autodiscover_code<300 and chainlast_autodiscover_code>=200 and not entry.get("error", "").startswith("failed to unmarshal") and not entry.get("error", "").startswith("failed to read response body")):
                        print(domain + " good")
                        # 打印重定向路径
                        redirect_paths = []
                        for redirect in entry["redirects"]:
                            loc = urlparse(redirect["URL"]).netloc
                            redirect_paths.append(loc)
                            
                        # 使用 join 去除最后一个箭头
                        print(" -> ".join(redirect_paths))
                        print("\n")
                        # print(urlparse((entry.get("redirects", [])[-1]).get("URL")).netloc)
                        # for redirect in entry["redirects"]:
                        #         loc = urlparse(redirect["URL"]).netloc
                        #         print(loc,end='->')
                        # print("\n") 

redirect(input_file)
#Invalid