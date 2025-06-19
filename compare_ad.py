import ijson
import json
from urllib.parse import urlparse
import tldextract

'''
遍历init1.json,比较web server和dns server是否相同
'''
input_file = "init1.json"
output_file = "compare_server_sub.jsonl"  

def normalize_domain(domain):
    # 提取注册域名
    return tldextract.extract(domain).registered_domain

def extract_server_info(input_file):
    with open(input_file, "r", encoding="utf-8") as f:
        objects = ijson.items(f, "item")
        for obj in objects:
            domain = obj.get("domain")
            ad_autodiscover_exist = False
            ad_autoconfig_exist = False
            ad_srv_exist = False
            ad_autodiscover = ""
            ad_autoconfig = ""
            ad_srv = ""
            for entry in obj.get("autodiscover", []):
                redirects = entry.get("redirects", [])
                if redirects:
                    chainlast_autodiscover_code = redirects[-1].get("Status")
                    if (200 <= chainlast_autodiscover_code < 300 and 
                        not entry.get("error", "").startswith("failed to unmarshal") and 
                        not entry.get("error", "").startswith("failed to read response body")):
                        ad_autodiscover = normalize_domain(redirects[-1]["URL"])
                        ad_autodiscover_exist = True
                        break
            for entry in obj.get("autoconfig", []):
                redirects = entry.get("redirects", [])
                if redirects:
                    chainlast_autoconfig_code = redirects[-1].get("Status")
                    if (200 <= chainlast_autoconfig_code < 300 and entry.get("error", "")==""):
                        ad_autoconfig = normalize_domain(redirects[-1]["URL"])
                        ad_autoconfig_exist = True
                        break
            if obj["srv"]["dns_record"].get("SOA")!=None:
                ad_srv = normalize_domain(obj["srv"]["dns_record"]["SOA"].rstrip("."))
                ad_srv_exist = True
            elif obj["srv"]["dns_record"].get("NS")!=None:
                ad_srv = normalize_domain(obj["srv"]["dns_record"]["NS"].split(",", 1)[0].rstrip("."))
                ad_srv_exist = True

            if (ad_autodiscover_exist or ad_autoconfig_exist) and ad_srv_exist:
                if ad_autodiscover_exist :
                    compare_ad_info = {
                        "domain": domain,
                        "ifsame":ad_autodiscover==ad_srv,
                        "ad_autodiscover":ad_autodiscover,
                        "ad_srv":ad_srv,
                    }   
                else:
                    compare_ad_info = {
                        "domain": domain,
                        "ifsame":ad_autoconfig==ad_srv,
                        "ad_autoconfig":ad_autoconfig,
                        "ad_srv":ad_srv,
                    }
                # 保存提取的符合条件的信息到文件
                with open(output_file, "a", encoding="utf-8") as out_f:
                        out_f.write(json.dumps(compare_ad_info) + "\n")
                        

extract_server_info(input_file)          

            