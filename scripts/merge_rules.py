import os
import requests
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from netaddr import IPSet
from loguru import logger
from typing import List, Tuple, Set

# 虽然定义了 GLOBAL_MIRROR，但原逻辑中未使用，这里保留定义，后续可接管
GLOBAL_MIRROR = 'https://ghfast.top/https://raw.githubusercontent.com'

# 使用 pathlib 处理路径，脚本所在目录的父目录的 rules 子目录
CURRENT_DIR = Path(__file__).resolve().parent
OUTPUT_RULES_DIR = CURRENT_DIR.parent / 'rules'
BASE_RULES_DIR = OUTPUT_RULES_DIR / 'base'


def optimize_ip_cidr(ip_cidr_rules: Set[str]) -> List[str]:
    """
    优化 IP-CIDR 规则
    :param ip_cidr_rules:
    :return:
    """
    try:
        ip_set = IPSet(ip_cidr_rules)
        optimized_cidrs = [str(cidr) for cidr in ip_set.iter_cidrs()]
        return optimized_cidrs
    except Exception as e:
        logger.error(f"Error optimizing IP-CIDR rules: {e}")
        return list(ip_cidr_rules)


def download_single_rule(url: str) -> List[str]:
    """
    下载单个规则文件
    """
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            return response.text.splitlines()
        else:
            logger.error(f'Failed to fetch rules from {url}, status code: {response.status_code}')
            return []
    except Exception as e:
        logger.error(f'Failed to fetch rules from {url}, error: {e}')
        return []


def download_rules(rule_urls: list) -> list:
    """
    并发下载规则文件
    :param rule_urls:
    :return:
    """
    rules = []
    # 使用线程池并发下载
    max_workers = min(10, len(rule_urls) + 1)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(download_single_rule, url): url for url in rule_urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                if result:
                    rules.extend(result)
            except Exception as e:
                logger.error(f'Error downloading {url}: {e}')
    
    return rules


def classify_rules(rules: List[str]) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
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
        # 移除首尾空白
        rule = rule.strip()
        if not rule or rule.startswith('#'):
            continue
            
        try:
            if rule.startswith('DOMAIN-SUFFIX,'):
                parts = rule.split(',')
                if len(parts) >= 2:
                    domain_suffix_rules.add(parts[1].strip())
            elif rule.startswith('DOMAIN,'):
                parts = rule.split(',')
                if len(parts) >= 2:
                    domain_rules.add(parts[1].strip())
            elif rule.startswith('DOMAIN-KEYWORD,'):
                parts = rule.split(',')
                if len(parts) >= 2:
                    domain_keyword_rules.add(parts[1].strip())
            elif 'IP-CIDR' in rule: # 兼容 IP-CIDR 和 IP-CIDR6
                # 通常格式 IP-CIDR,1.2.3.4/24,no-resolve
                parts = rule.split(',')
                if len(parts) >= 2:
                    ip_cidr_rules.add(parts[1].strip())
        except Exception as e:
            logger.warning(f"Error parsing rule '{rule}': {e}")

    return domain_rules, domain_suffix_rules, domain_keyword_rules, ip_cidr_rules


# 输出规则
def write_output(output_file_path: Path, domain_rules, domain_suffix_rules, domain_keyword_rules, ip_cidr_rules,
                 additional_rules: list = []):
    
    output_file_path.parent.mkdir(parents=True, exist_ok=True)
    output_file_name = output_file_path.name
    
    try:
        with open(output_file_path, 'w', encoding='utf-8') as f:
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
        logger.info(f'Output {total} rules to {output_file_path}')
    except Exception as e:
        logger.error(f"Failed to write output file {output_file_path}: {e}")


# 主函数
def merge(rule_urls: list, output_file_path: Path, additional_rules: list = None, blacklist: list = None):
    if additional_rules is None:
        additional_rules = []
    if blacklist is None:
        blacklist = []

    # 下载和分类规则
    rules = download_rules(rule_urls)
    
    # 过滤黑名单规则
    if blacklist:
        blacklist_set = set(b.strip() for b in blacklist if b.strip())
        rules = [r for r in rules if r.strip() not in blacklist_set]
        additional_rules = [r for r in additional_rules if r.strip() not in blacklist_set]

    domain_rules, domain_suffix_rules, domain_keyword_rules, ip_cidr_rules = classify_rules(rules)

    # 优化 IP-CIDR 规则
    optimized_cidrs = optimize_ip_cidr(ip_cidr_rules)

    # 输出优化后的规则
    write_output(
        output_file_path, domain_rules, domain_suffix_rules,
        domain_keyword_rules, optimized_cidrs, additional_rules
    )


def read_base_rules(base_file_name: str) -> list:
    """
    读取基础规则文件
    :param base_file_name: 基础规则文件名称
    :return: 规则列表
    """
    base_file = BASE_RULES_DIR / base_file_name
    if not base_file.exists():
        logger.warning(f'Base rules file {base_file} does not exist.')
        return []
    
    try:
        with open(base_file, 'r', encoding='utf-8') as f:
            lines = f.read().splitlines()
        # 过滤空行和注释行
        return [line.strip() for line in lines if line.strip() and not line.startswith('#')]
    except Exception as e:
        logger.error(f"Error reading base rules file {base_file}: {e}")
        return []


def merge_rules():
    options = {
        'VirtualCurrency.list': [
            'https://raw.githubusercontent.com/iBlack16/iBlack/refs/heads/main/clash/xunibi.list',
            'https://raw.githubusercontent.com/yiyule10/Passwall/main/Clash/virtual%20currency.list',
            'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Binance/Binance.list',
            'https://raw.githubusercontent.com/mexiaow/ACL4SSR/main/Clash/Ruleset/VirtualCurrency.list',
        ],
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
            'http://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Developer.list',
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
        'SocialMedia.list': [
            'https://raw.githubusercontent.com/AntonyCyrus/Rule/main/Clash/SocialMedia.list',
        ],
    }

    # 定义各个文件的黑名单过滤规则（精确匹配每一行规则）
    blacklists = {
        'SocialMedia.list': [
            'DOMAIN-SUFFIX,grok.com',
            'DOMAIN-SUFFIX,askubuntu.com',
            'DOMAIN-SUFFIX,stackoverflow.com',
        ],
        'LimitHK.list': [
            'DOMAIN-SUFFIX,segment.io',
        ],
        'Media.list': [
            'DOMAIN-SUFFIX,trae.ai',
            'DOMAIN-SUFFIX,marscode.com',
            'DOMAIN-SUFFIX,byteoversea.com',
        ],
        'Developer.list': [
            'DOMAIN-SUFFIX,reddit.com',
        ],
        'LimitKR.list': [
            'DOMAIN-SUFFIX,line-cdn.net',
            'DOMAIN-SUFFIX,chocotv.com.tw',
            'DOMAIN-SUFFIX,linetv.tw',
            'DOMAIN,d17lx9ucc6k9fc.cloudfront.net',
            'DOMAIN-SUFFIX,line-scdn.net',
            'DOMAIN-SUFFIX,line-cdn.net',
            'IP-CIDR,147.92.128.0/17',
            'DOMAIN-SUFFIX,line.me',
            'DOMAIN-SUFFIX,linecorp.com',
            'IP-CIDR,203.174.66.64/26',
            'DOMAIN-SUFFIX,naver.jp',
            'IP-CIDR,203.104.103.0/24',
            'IP-CIDR,119.235.236.0/23',
            'IP-CIDR,125.6.190.0/24',
            'IP-CIDR,119.235.235.0/24',
            'IP-CIDR,147.92.128.0/17',
            'IP-CIDR,119.235.235.0/24',
            'IP-CIDR,119.235.236.0/23',
            'DOMAIN-SUFFIX,lin.ee',
            'IP-CIDR,203.174.66.64/26',
            'IP-CIDR,203.104.103.0/24',
            'IP-CIDR,125.6.190.0/24',
            'DOMAIN-SUFFIX,line-apps.com',
            'IP-CIDR,203.174.77.0/24',
            'DOMAIN-SUFFIX,nhncorp.jp',
        ],
        'LimitUS.list': [
            'DOMAIN-SUFFIX,watchespn.com',
            'DOMAIN-SUFFIX,espn.net',
            'DOMAIN-SUFFIX,espn.com',
            'DOMAIN-SUFFIX,espn.co.uk',
            'DOMAIN-SUFFIX,dtci.co',
            'DOMAIN-SUFFIX,dtci.technology',
            'DOMAIN-SUFFIX,espnqa.com',
            'DOMAIN-SUFFIX,espncdn.com',
        ],
        'NSFW.list': [
            'DOMAIN-SUFFIX,instagram.com',
            'DOMAIN-SUFFIX,facebook.com',
        ],
        'LimitTW.list': [
            'DOMAIN-SUFFIX,line-cdn.net',
            'DOMAIN-SUFFIX,line-scdn.net',
            'DOMAIN-SUFFIX,gvt1.com',
        ],
    }

    for file_name, urls in options.items():
        output_file_path = OUTPUT_RULES_DIR / file_name
        additional_rules = read_base_rules(file_name)
        blacklist = blacklists.get(file_name, [])
        merge(urls, output_file_path, additional_rules, blacklist)
        logger.info(f'Rules merged to {output_file_path}')


if __name__ == '__main__':
    merge_rules()

