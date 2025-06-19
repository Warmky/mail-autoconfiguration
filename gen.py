import ijson
import xml.etree.ElementTree as ET
import json

input_file = "init1.json"
#input_file = "try.json"

def count_domains_with_valid_config(input_file):
    domain_processed = 0
    valid_autodiscover_domains = set()
    autodiscover_from_post = set()
    autodiscover_from_srvpost = set()
    autodiscover_from_getpost = set()
    autodiscover_from_direct_get = set()

    valid_autoconfig_domains = set() # 所有可以通过autoconfig得到的domain
    autoconfig_from_directurl = set()
    autoconfig_from_ISPDB = set()
    autoconfig_from_MX_samedomain = set()
    autoconfig_from_MX = set()

    valid_srv_domains = set() 
    srv_dnssec_passed = set()

    valid_only_autodiscover = set()
    valid_only_autoconfig = set()
    valid_only_srv = set()
    valid_autodiscover_and_autoconfig = set()
    valid_autodiscover_and_srv = set()
    valid_autoconfig_and_srv = set()
    valid_three_all = set()
    valid_none = set()


    with open(input_file, "r", encoding="utf-8") as f:
        objects = ijson.items(f, "item")  # 流式解析 JSON 数组中的对象
        for obj in objects:
            domain = obj.get("domain")
            domain_processed = domain_processed +1 
            # autoconfig部署统计部分
            for entry in obj.get("autoconfig", []):
                if entry["config"]!="":
                    try:
                        root = ET.fromstring(entry["config"])
                        if root.tag == "clientConfig":  # **XML 解析成功???**
                            valid_autoconfig_domains.add(domain)
                            if entry["method"] == "directurl":
                                autoconfig_from_directurl.add(domain)
                            if entry["method"] == "ISPDB":
                                autoconfig_from_ISPDB.add(domain)
                            if entry["method"] == "MX_samedomain":
                                autoconfig_from_MX_samedomain.add(domain)
                            if entry["method"] == "MX":
                                autoconfig_from_MX.add(domain)
                            # break  # 找到一个成功的就够了
                    except ET.ParseError:
                        pass  # XML 解析失败，继续检查下一个

            # autodiscover部署统计部分
            for entry in obj.get("autodiscover", []):
                if entry["config"]!= "" and not entry["config"].startswith("Bad") and not entry["config"].startswith("Errorcode"):
                    try:
                        root = ET.fromstring(entry["config"]) # 这一步可以直接规避以Bad response或Errorcode开头的config
                        # if root.tag == "Autodiscover":  # **XML 解析成功** 不能直接这样解析，因为有命名空间xmls
                        valid_autodiscover_domains.add(domain)
                        #print(domain+"")
                        if entry["method"] == "POST":
                            autodiscover_from_post.add(domain)
                        if entry["method"] == "srv-post":
                            autodiscover_from_srvpost.add(domain)
                        if entry["method"] == "get-post":
                            autodiscover_from_getpost.add(domain)
                        if entry["method"] == "direct_get":
                            autodiscover_from_direct_get.add(domain) 
                        #break  # 找到一个成功的就够了
                    except ET.ParseError:
                        pass  # XML 解析失败，继续检查下一个
            
            
            # srv部署统计部分
            srv_data = obj.get("srv", {})
            recv_records = srv_data.get("recv_records", [])
            send_records = srv_data.get("send_records", [])

            if recv_records or send_records:
                valid_srv_domains.add(domain)
                dns_record = obj["srv"]["dns_record"]
                adbits = [value for key, value in dns_record.items() if key.startswith("ADbit_")]
                dnssec_passed = all(adbits) if adbits else False
                if dnssec_passed:
                    srv_dnssec_passed.add(domain)

            if domain in valid_autoconfig_domains :
                if domain in valid_autodiscover_domains:
                    if domain in valid_srv_domains:
                        valid_three_all.add(domain)
                    else:
                        valid_autodiscover_and_autoconfig.add(domain)
                else:
                    if domain in valid_srv_domains:
                        valid_autoconfig_and_srv.add(domain)
                    else:
                        valid_only_autoconfig.add(domain)
            else:
                if domain in valid_autodiscover_domains:
                    if domain in valid_srv_domains:
                        valid_autodiscover_and_srv.add(domain)
                    else:
                        valid_only_autodiscover.add(domain)
                else:
                    if domain in valid_srv_domains:
                        valid_only_srv.add(domain)
                    else:
                        valid_none.add(domain)

    print(f"✅ 通过 Autodiscover可以获取配置信息的域名数量: {len(valid_autodiscover_domains)}")
    print(f"✅ 通过 Autodiscover_post可以获取配置信息的域名数量: {len(autodiscover_from_post)}")
    print(f"✅ 通过 Autodiscover_srvpost可以获取配置信息的域名数量: {len(autodiscover_from_srvpost)}")
    print(f"✅ 通过 Autodiscover_getpost可以获取配置信息的域名数量: {len(autodiscover_from_getpost)}")
    print(f"✅ 通过 Autodiscover_direct_get可以获取配置信息的域名数量: {len(autodiscover_from_direct_get)}")

    print(f"✅ 通过 Autoconfig可以获取配置信息的域名数量: {len(valid_autoconfig_domains)}")
    print(f"✅ 通过 Autoconfig_directurl可以获取配置信息的域名数量: {len(autoconfig_from_directurl)}")
    print(f"✅ 通过 Autoconfig_ISPDB可以获取配置信息的域名数量: {len(autoconfig_from_ISPDB)}")
    print(f"✅ 通过 Autoconfig_MX_samedomain可以获取配置信息的域名数量: {len(autoconfig_from_MX_samedomain)}")
    print(f"✅ 通过 Autoconfig_MX可以获取配置信息的域名数量: {len(autoconfig_from_MX)}")
    print(f"✅ 仅可以通过ISPDB获取配置信息的域名数量: {len((valid_autoconfig_domains) - ((autoconfig_from_directurl)|(autoconfig_from_MX)|(autoconfig_from_MX_samedomain)))}")

    print(f"✅ 通过 srv可以获取配置信息的域名数量: {len(valid_srv_domains)}")
    print(f"✅ 通过 srv可以获取配置信息且ADbit都通过DNSSEC检查的的域名数量: {len(srv_dnssec_passed)}")

    print(f"✅ 可以通过Autodiscover、Autoconfig、 srv获取配置信息的域名数量: {len(valid_three_all)}")
    print(f"✅ 可以通过Autodiscover、Autoconfig获取配置信息的域名数量: {len(valid_autodiscover_and_autoconfig)}")
    print(f"✅ 可以通过Autodiscover、srv获取配置信息的域名数量: {len(valid_autodiscover_and_srv)}")
    print(f"✅ 可以通过Autoconfig、srv获取配置信息的域名数量: {len(valid_autoconfig_and_srv)}")
    print(f"✅ 仅可以通过Autodiscover获取配置信息的域名数量: {len(valid_only_autodiscover)}")
    print(f"✅ 仅可以通过Autoconfig获取配置信息的域名数量: {len(valid_only_autoconfig)}")
    print(f"✅ 仅可以通过srv获取配置信息的域名数量: {len(valid_only_srv)}")
    print(f"✅ 无法通过任意方法获取配置信息的域名数量: {len(valid_none)}")

    print(f"✅ 一共处理了域名数量: {domain_processed}")

    with open("autoconfig_from_ISPDB.json", "w", encoding="utf-8") as f:
        json.dump(list(autoconfig_from_ISPDB), f, indent=4, ensure_ascii=False)
    print(f"✅ autoconfig_from_ISPDB saved to 'autoconfig_from_ISPDB.json'.")

    # print(autoconfig_from_directurl)
    # print(valid_autoconfig_domains)
    # print(valid_autodiscover_domains)
    data_to_save = {
    "valid_autodiscover_domains": list(valid_autodiscover_domains),
    "autodiscover_from_post": list(autodiscover_from_post),
    "autodiscover_from_srvpost": list(autodiscover_from_srvpost),
    "autodiscover_from_getpost": list(autodiscover_from_getpost),
    "autodiscover_from_direct_get": list(autodiscover_from_direct_get),

    "valid_autoconfig_domains": list(valid_autoconfig_domains),
    "autoconfig_from_directurl": list(autoconfig_from_directurl),
    "autoconfig_from_ISPDB": list(autoconfig_from_ISPDB),
    "autoconfig_from_MX_samedomain": list(autoconfig_from_MX_samedomain),
    "autoconfig_from_MX": list(autoconfig_from_MX),

    "only_ISPDB_domains": list(valid_autoconfig_domains - (autoconfig_from_directurl | autoconfig_from_MX | autoconfig_from_MX_samedomain)),

    "valid_srv_domains": list(valid_srv_domains),
    "srv_dnssec_passed": list(srv_dnssec_passed),

    "valid_three_all": list(valid_three_all),
    "valid_autodiscover_and_autoconfig": list(valid_autodiscover_and_autoconfig),
    "valid_autodiscover_and_srv": list(valid_autodiscover_and_srv),
    "valid_autoconfig_and_srv": list(valid_autoconfig_and_srv),
    "valid_only_autodiscover": list(valid_only_autodiscover),
    "valid_only_autoconfig": list(valid_only_autoconfig),
    "valid_only_srv": list(valid_only_srv),
    "valid_none": list(valid_none)
}


    with open("domain_stats.json", "w", encoding="utf-8") as f:
        json.dump(data_to_save, f, indent=4, ensure_ascii=False, sort_keys=True)



count_domains_with_valid_config(input_file)
