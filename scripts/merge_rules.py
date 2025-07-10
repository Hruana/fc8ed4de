import os
import requests
from netaddr import IPSet
from loguru import logger

GLOBAL_MIRROR = 'https://ghfast.top/https://raw.githubusercontent.com'

OUTPUT_RULES_DIR = '../rules/'
BASE_RULES_DIR = f'{OUTPUT_RULES_DIR}base/'


def optimize_ip_cidr(ip_cidr_rules) -> list:
    """
    优化 IP-CIDR 规则
    :param ip_cidr_rules:
    :return:
    """
    ip_set = IPSet(ip_cidr_rules)
    optimized_cidrs = list(ip_set.iter_cidrs())
    return optimized_cidrs


def download_rules(rule_urls: list) -> list:
    """
    下载规则文件
    :param rule_urls:
    :return:
    """
    rules = []
    for url in rule_urls:
        response = requests.get(url)
        if response.status_code == 200:
            rules.extend(response.text.splitlines())
        else:
            logger.error(f'Failed to fetch rules from {url}')
            exit()
    return rules


def classify_rules(rules) -> tuple:
    """
    分类规则
    :param rules:
    :return:
    """
    domain_rules = set()
    domain_suffix_rules = set()
    domain_keyword_rules = set()
    ip_cidr_rules = set()

    for rule in rules:
        rule = rule.strip()
        if rule.startswith('DOMAIN-SUFFIX,'):
            domain_suffix_rules.add(rule.split(',')[1])
        elif rule.startswith('DOMAIN,'):
            domain_rules.add(rule.split(',')[1])
        elif rule.startswith('DOMAIN-KEYWORD,'):
            domain_keyword_rules.add(rule.split(',')[1])
        elif 'IP-CIDR,' in rule:
            ip_cidr_rules.add(rule.split(',')[1].split(',')[0])
    return domain_rules, domain_suffix_rules, domain_keyword_rules, ip_cidr_rules


# 输出规则
def write_output(output_file, domain_rules, domain_suffix_rules, domain_keyword_rules, ip_cidr_rules,
                 additional_rules: list = []):
    output_file = os.path.join(OUTPUT_RULES_DIR, output_file)
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    # 取出output_file的文件名
    output_file_name = os.path.basename(output_file)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f'# NAME {output_file_name} \n')
        total = len(domain_suffix_rules) + len(domain_rules) + len(domain_keyword_rules) + len(ip_cidr_rules) + len(
            additional_rules)
        f.write(f'# Total: {total} Rules\n')
        for rule in additional_rules:
            f.write(f'{rule}\n')
        for rule in sorted(domain_suffix_rules):
            f.write(f'DOMAIN-SUFFIX,{rule}\n')
        for rule in sorted(domain_rules):
            f.write(f'DOMAIN,{rule}\n')
        for rule in sorted(domain_keyword_rules):
            f.write(f'DOMAIN-KEYWORD,{rule}\n')
        for cidr in sorted(ip_cidr_rules, key=lambda x: str(x)):
            f.write(f'IP-CIDR,{cidr}\n')
    logger.info(f'Output {total} rules to {output_file}')


# 主函数
def merge(rule_urls: list, output_file: str, additional_rules: list = []):
    # 下载和分类规则
    rules = download_rules(rule_urls)
    domain_rules, domain_suffix_rules, domain_keyword_rules, ip_cidr_rules = classify_rules(rules)

    # 优化 IP-CIDR 规则
    optimized_cidrs = optimize_ip_cidr(ip_cidr_rules)

    # 输出优化后的规则
    write_output(
        output_file, domain_rules, domain_suffix_rules,
        domain_keyword_rules, optimized_cidrs, additional_rules
    )


def read_base_rules(base_file: str) -> list:
    """
    读取基础规则文件
    :param base_file: 基础规则文件路径
    :return: 规则列表
    """
    base_file = os.path.join(BASE_RULES_DIR, base_file)
    if not os.path.exists(base_file):
        logger.error(f'Base rules file {base_file} does not exist.')
        return []
    with open(base_file, 'r', encoding='utf-8') as f:
        return f.read().splitlines()


def merge_rules():
    options = {
        'NSFW.list': [
            'https://raw.githubusercontent.com/EliceAM/Profiles/main/Clash/RuleSet/NSFW.list',
            'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Porn.list',
            'https://raw.githubusercontent.com/devswork/my-subconverter/master/rules/porn.list',
            'https://raw.githubusercontent.com/sounfury/sounfury-Clash_rules/main/list/sexy.list',
        ],
        'Developer.list': [
            'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/GitHub/GitHub.list',
            'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Docker/Docker.list',
            'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Python/Python.list',
            'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Ubuntu/Ubuntu.list',
        ],
        'AI.list': [
            'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/OpenAI/OpenAI.list',
            'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Claude/Claude.list',
            'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Gemini/Gemini.list',
        ],
        'Anti-Ads.list': [],
        'DNS.list': [],
        'Download.list': [],
        'Inside.list': [],
        'Outside.list': [],
        'TravelUS.list': [],
        'TravelHK.list': [],
        'Media.list': [
            'https://raw.githubusercontent.com/AntonyCyrus/Rule/main/Clash/Music.list',
            'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/TikTok/TikTok.list',
            'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/YouTube/YouTube.list',
            'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/YouTubeMusic/YouTubeMusic.list'
        ],
        'LimitHK.list': [
            'https://raw.githubusercontent.com/AntonyCyrus/Rule/main/Clash/HKMedia.list'
        ],
        'LimitTW.list': [
            'https://raw.githubusercontent.com/AntonyCyrus/Rule/main/Clash/TWMedia.list'
        ],
        'LimitJP.list': [
            'https://raw.githubusercontent.com/AntonyCyrus/Rule/main/Clash/JPMedia.list'
        ],
        'LimitUS.list': [
            'https://raw.githubusercontent.com/AntonyCyrus/Rule/main/Clash/USMedia.list'
        ],
        'LimitKR.list': [
            'https://raw.githubusercontent.com/AntonyCyrus/Rule/main/Clash/KRMedia.list'
        ],
        'LimitIN.list': [
            'https://raw.githubusercontent.com/AntonyCyrus/Rule/main/Clash/INMedia.list'
        ],
        'LimitGB.list': [
            'https://raw.githubusercontent.com/AntonyCyrus/Rule/main/Clash/GBMedia.list'
        ],
        'Stream.list': [
            'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Disney/Disney.list',
            'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Netflix/Netflix.list',
            'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/PrimeVideo/PrimeVideo.list',
        ],
        'AcademicDirect.list': [],
        'AcademicProxy.list': [],
    }

    for file, urls in options.items():
        output_file = os.path.join(OUTPUT_RULES_DIR, file)
        additional_rules = read_base_rules(file)
        merge(urls, output_file, additional_rules)
        logger.info(f'Rules merged to {output_file}')


if __name__ == '__main__':
    merge_rules()
