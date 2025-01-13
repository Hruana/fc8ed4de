import tldextract

# 读取链接的文件
input_file = 'input.txt'  # 输入文件名
output_file = 'output.txt'  # 输出文件名

with open(input_file, 'r') as infile:
    links = infile.readlines()

# 提取主域名
domains = []
for link in links:
    link = link.strip()  # 去掉多余的空白字符
    extracted = tldextract.extract(link)
    # 提取主域名
    domain = f"{extracted.domain}.{extracted.suffix}"
    domains.append(domain)

# 写入新文件
domains = list(set(domains))
with open(output_file, 'w') as outfile:
    for domain in domains:
        outfile.write(domain + '\n')

print(f"主域名已写入 {output_file}")
