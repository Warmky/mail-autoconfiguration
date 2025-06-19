import json
import matplotlib.pyplot as plt
'''
3.10 试图实现基于主机名聚类域名，就是从已有的clusters.json中统计不同的主机名分别对应了多少的域名（不重复统计域名，如果统一主机在不同的配置如pop3-995、pop3-110中均对应到了同一个使用的domain,只计数一次）
'''
# 读取 clusters.json
with open("clusters.json", "r", encoding="utf-8") as f:
    cluster_data = json.load(f)

# 统计主机名对应的唯一域名集合
host_domain_map = {}

for config in cluster_data.values():  # 遍历每种配置类型
    for host, domains in config.items():
        if host not in host_domain_map:
            host_domain_map[host] = set()  # 使用 set 记录唯一域名
        host_domain_map[host].update(domains)  # 添加到集合，避免重复

# 计算每个主机名的唯一域名数量
host_domain_count = {host: len(domains) for host, domains in host_domain_map.items()}

# 按域名数量降序排序
sorted_hosts = sorted(host_domain_count.items(), key=lambda x: x[1], reverse=True)

# 取前 20 个主机名（可调整）
top_n = 50
top_hosts = sorted_hosts[:top_n]

# 提取主机名和对应的域名数
hosts, domain_counts = zip(*top_hosts)

# 绘制柱状图
plt.figure(figsize=(30, 15))
plt.barh(hosts, domain_counts, color="skyblue")
plt.xlabel("Number of Unique Connected Domains")
plt.ylabel("Hostnames")
plt.title(f"Top {top_n} Hostnames by Number of Unique Connected Domains")
plt.gca().invert_yaxis()  # 让排名靠前的主机名在上面
plt.show()
