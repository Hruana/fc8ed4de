import os
import requests
from netaddr import IPSet
from loguru import logger

GLOBAL_MIRROR = 'https://ghfast.top/https://raw.githubusercontent.com'


# 优化 IP-CIDR 规则
def optimize_ip_cidr(ip_cidr_rules):
    ip_set = IPSet(ip_cidr_rules)
    optimized_cidrs = list(ip_set.iter_cidrs())
    return optimized_cidrs


# 下载规则文件
def download_rules(rule_urls: list):
    rules = []
    for url in rule_urls:
        response = requests.get(url)
        if response.status_code == 200:
            rules.extend(response.text.splitlines())
        else:
            print(f"Failed to fetch rules from {url}")
    return rules


# 分类规则
def classify_rules(rules):
    domain_rules = set()
    domain_suffix_rules = set()
    domain_keyword_rules = set()
    ip_cidr_rules = set()

    for rule in rules:
        rule = rule.strip()
        if rule.startswith("DOMAIN-SUFFIX,"):
            domain_suffix_rules.add(rule.split(",")[1])
        elif rule.startswith("DOMAIN,"):
            domain_rules.add(rule.split(",")[1])
        elif rule.startswith("DOMAIN-KEYWORD,"):
            domain_keyword_rules.add(rule.split(",")[1])
        elif "IP-CIDR" in rule:
            ip_cidr_rules.add(rule.split(",")[1].split(',')[0])
    return domain_rules, domain_suffix_rules, domain_keyword_rules, ip_cidr_rules


# 输出规则
def write_output(output_file, domain_rules, domain_suffix_rules, domain_keyword_rules, ip_cidr_rules):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    # 取出output_file的文件名
    output_file_name = os.path.basename(output_file)
    with open(output_file, "w") as f:
        f.write(f"# NAME {output_file_name} \n")
        f.write(
            f"# Total: {len(domain_suffix_rules) + len(domain_rules) + len(domain_keyword_rules) + len(ip_cidr_rules)} Rules\n")
        for rule in sorted(domain_suffix_rules):
            f.write(f"DOMAIN-SUFFIX,{rule}\n")
        for rule in sorted(domain_rules):
            f.write(f"DOMAIN,{rule}\n")
        for rule in sorted(domain_keyword_rules):
            f.write(f"DOMAIN-KEYWORD,{rule}\n")
        for cidr in sorted(ip_cidr_rules, key=lambda x: str(x)):
            f.write(f"IP-CIDR,{cidr}\n")


# 主函数
def merge(rule_urls: list, output_file: str):
    # 下载和分类规则
    rules = download_rules(rule_urls)
    domain_rules, domain_suffix_rules, domain_keyword_rules, ip_cidr_rules = classify_rules(rules)

    # 优化 IP-CIDR 规则
    optimized_cidrs = optimize_ip_cidr(ip_cidr_rules)

    # 输出优化后的规则
    write_output(output_file, domain_rules, domain_suffix_rules, domain_keyword_rules, optimized_cidrs)


# 合并 NSFW 规则
def merge_nsfw_rules(output_file: str = '../rules/NSFW.list'):
    # 定义规则 URL
    input_files = [
        f'{GLOBAL_MIRROR}/EliceAM/Profiles/main/Clash/RuleSet/NSFW.list',
        f'{GLOBAL_MIRROR}/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Porn.list',
        f'{GLOBAL_MIRROR}/devswork/my-subconverter/master/rules/porn.list',
        f'{GLOBAL_MIRROR}/sounfury/sounfury-Clash_rules/main/list/sexy.list',
    ]
    merge(input_files, output_file)
    logger.info(f"NSFW rules merged to {output_file}")


# 合并 LAN 规则
def merge_lan_rules(output_file: str = '../rules/LAN.list'):
    # 定义规则 URL
    input_files = [
        f'{GLOBAL_MIRROR}/ACL4SSR/ACL4SSR/master/Clash/LocalAreaNetwork.list',
        f'{GLOBAL_MIRROR}/GeQ1an/Rules/master/QuantumultX/Filter/LAN.list',
        f'{GLOBAL_MIRROR}/dler-io/Rules/main/Clash/Provider/LAN.yaml',
    ]
    merge(input_files, output_file)
    logger.info(f"LAN rules merged to {output_file}")


if __name__ == "__main__":
    # merge_nsfw_rules()
    merge_lan_rules()
