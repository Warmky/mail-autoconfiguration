import re
# 统计Reurl的
# 正则表达式来提取邮箱中的域名
email_pattern = r'email address:\s*([^@]+@([^>\s]+))'

# 用来保存提取的域名
domains = set()

# 假设 xml_file 是你的 XML 文件路径
xml_file1 = './autodiscover/records/Reurl_dirGET.xml'
xml_file2 = './autodiscover/records/Reurl.xml'

def Reurl_count(xml_file):
    with open(xml_file, 'r', encoding='utf-8') as file:
        for line in file:
            # 通过正则匹配邮箱地址并提取域名部分
            matches = re.findall(email_pattern, line)
            for match in matches:
                # 提取域名并添加到集合中
                domain = match[1]  # 提取域名部分
                domains.add(domain)

Reurl_count(xml_file1)
Reurl_count(xml_file2)

# 输出统计的域名集合
#print(domains)
print(len(domains))
