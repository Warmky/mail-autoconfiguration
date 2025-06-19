# import ijson
# import xml.etree.ElementTree as ET
# import json

# input_file = "fixed_init1.json"
# #input_file = "try.json"

# def count_domains_processed(input_file):
#     domain_processed = 0


#     with open(input_file, "r", encoding="utf-8") as f:
#         objects = ijson.items(f, "item")  # 流式解析 JSON 数组中的对象
#         for obj in objects:
#             domain = obj.get("domain")
#             domain_processed = domain_processed +1 

#     print(f"已经处理的域名数量为：{domain_processed}")





# count_domains_processed(input_file)
import json

# 读取 JSON 文件
with open('domain_stats.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# 遍历字典并打印键和列表长度
for key, value in data.items():
    if isinstance(value, list):
        print(f"{key}: {len(value)}")
    else:
        print(f"{key}: 不是列表")

