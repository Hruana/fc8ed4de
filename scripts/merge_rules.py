#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import requests
import yaml
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from netaddr import AddrFormatError, IPNetwork, IPSet
from loguru import logger
from typing import Dict, List, Optional, Set, Tuple

# githubusercontent 加速镜像，默认直连原站。
# 本地调试时通过环境变量注入，例如：
#   GITHUB_RAW_MIRROR=https://ghfast.top/https://raw.githubusercontent.com
# CI（GitHub Actions runner）可直连原站，无需设置。
GLOBAL_MIRROR = os.environ.get('GITHUB_RAW_MIRROR', '').strip().rstrip('/')

RAW_PREFIXES = ('https://raw.githubusercontent.com', 'http://raw.githubusercontent.com')

# 使用 pathlib 处理路径，脚本所在目录的父目录的 rules 子目录
CURRENT_DIR = Path(__file__).resolve().parent
CONFIG_FILE = CURRENT_DIR / 'sources.yaml'
OUTPUT_RULES_DIR = CURRENT_DIR.parent / 'rules'
BASE_RULES_DIR = OUTPUT_RULES_DIR / 'base'

# 允许进入产物的规则类型。不在表内的（URL-REGEX、USER-AGENT、AND/OR/NOT、
# RULE-SET、SUB-RULE 等）会被静默丢弃：它们要么是 Surge/QX 专有语法，要么无法
# 出现在 rule-provider 内部，mihomo 加载会失败。
#
# 这里必须是 mihomo 与 subconverter 支持类型的**交集** —— 产物要先过一遍
# subconverter 的 ruleset 转换。subconverter 的 ClashRuleTypes 不含 IP-SUFFIX /
# PROCESS-PATH（整行静默丢弃），而 DOMAIN-REGEX 虽能通过前缀检查，却会被
# transformRuleToCommon() 按逗号切断 —— 正则里有 `{2,3}` 这种就会被拼坏，
# 导致 mihomo 编译正则失败、整份配置加载报错。所以这三个不收。
# IP-ASN 与 GEOIP 已刻意排除 —— 基础配置里不再提供任何 geo 数据库。
RULE_TYPE_WHITELIST = frozenset({
    'DOMAIN',
    'DOMAIN-SUFFIX',
    'DOMAIN-KEYWORD',
    'IP-CIDR',
    'IP-CIDR6',
    'PROCESS-NAME',
    'DST-PORT',
    'SRC-PORT',
})

# 这些类型只取第一个参数，尾部标记（no-resolve 等）由本脚本统一重建
VALUE_ONLY_TYPES = frozenset({
    'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6',
})


@dataclass
class RuleSet:
    """按类型归类后的规则集合。ip_cidr 内只存裸 CIDR，标记统一在输出时重建。"""
    domain: Set[str] = field(default_factory=set)
    domain_suffix: Set[str] = field(default_factory=set)
    domain_keyword: Set[str] = field(default_factory=set)
    ip_cidr: Set[str] = field(default_factory=set)
    other: Set[str] = field(default_factory=set)

    BUCKETS = ('domain', 'domain_suffix', 'domain_keyword', 'ip_cidr', 'other')

    def any(self) -> bool:
        """是否解析出了至少一条规则"""
        return any(getattr(self, name) for name in self.BUCKETS)


def load_config() -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
    """读取 sources.yaml，返回 (options, blacklists)"""
    if not CONFIG_FILE.exists():
        logger.error(f'配置文件不存在: {CONFIG_FILE}')
        sys.exit(1)

    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f) or {}
    except Exception as e:
        logger.error(f'解析配置文件 {CONFIG_FILE} 失败: {e}')
        sys.exit(1)

    options = {name: (urls or []) for name, urls in (config.get('options') or {}).items()}
    blacklists = {name: (rules or []) for name, rules in (config.get('blacklists') or {}).items()}

    if not options:
        logger.error(f'{CONFIG_FILE.name} 中 options 为空，无事可做')
        sys.exit(1)

    # 写成字符串而非列表时也是 truthy，会被逐字符当 URL 提交，必须提前拦住
    for name, value in options.items():
        if not isinstance(value, list):
            logger.error(f'options.{name} 必须是 URL 列表，实际是 {type(value).__name__}')
            sys.exit(1)
    for name, value in blacklists.items():
        if not isinstance(value, list):
            logger.error(f'blacklists.{name} 必须是规则列表，实际是 {type(value).__name__}')
            sys.exit(1)

    # 黑名单键写错文件名是静默失效的，这里提前拦住
    for name in blacklists:
        if name not in options:
            logger.warning(f'黑名单键 {name} 不在 options 中，该组黑名单不会生效')

    return options, blacklists


def get_session() -> requests.Session:
    """创建一个带有重试机制的requests session"""
    session = requests.Session()
    retry = Retry(
        total=3,
        connect=3,
        read=3,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({'GET', 'HEAD'}),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


def apply_mirror(url: str) -> str:
    """把 githubusercontent 原站地址替换为加速镜像（未配置镜像时原样返回）"""
    if not GLOBAL_MIRROR:
        return url
    for prefix in RAW_PREFIXES:
        if url.startswith(prefix):
            return GLOBAL_MIRROR + url[len(prefix):]
    return url


def optimize_ip_cidr(ip_cidr_rules: Set[str]) -> List[str]:
    """
    合并优化 IP-CIDR 规则。IPSet 做的是精确集合并集，不会扩大覆盖范围。
    返回值顺序由 iter_cidrs() 保证（IPv4 在前、按网络地址升序），保持产物稳定。
    """
    if not ip_cidr_rules:
        return []
    try:
        ip_set = IPSet(ip_cidr_rules)
        return [str(cidr) for cidr in ip_set.iter_cidrs()]
    except Exception as e:
        logger.error(f'Error optimizing IP-CIDR rules: {e}')
        # 失败时也必须给出确定顺序，否则产物会无意义抖动
        return sorted(ip_cidr_rules)


def download_single_rule(url: str, session: requests.Session) -> List[str]:
    """下载单个规则文件。失败时抛出异常，由调用方记录为失败源。"""
    response = session.get(apply_mirror(url), timeout=15)
    response.raise_for_status()
    return response.text.splitlines()


def download_rules(rule_urls: List[str], session: requests.Session) -> Tuple[Dict[str, List[str]], List[str]]:
    """
    并发下载规则文件
    :return: ({URL: 该源的所有行}, 失败的 URL 列表)。按源分开返回，
             便于逐源校验内容有效性并定位到具体是哪个源出了问题。
    """
    rules: Dict[str, List[str]] = {}
    failed: List[str] = []
    if not rule_urls:
        return rules, failed

    max_workers = min(10, len(rule_urls))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(download_single_rule, url, session): url for url in rule_urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                rules[url] = future.result()
            except Exception as e:
                logger.error(f'Failed to fetch rules from {url}, error: {e}')
                failed.append(url)

    return rules, failed


def normalize_cidr(value: str) -> str:
    """
    校验并归一化 CIDR。返回 '' 表示非法或不可接受，由调用方丢弃。
    归一化很关键：上游可能写 `203.174.66.65/26`（带 host bit）或 `2001:0DB8::/32`
    （非压缩 IPv6），文本各异但指同一网段。不归一化会导致黑名单剔除不掉、
    产物里出现同一网段的多种写法。
    """
    try:
        network = IPNetwork(value).cidr
    except (AddrFormatError, ValueError, TypeError, IndexError, KeyError):
        return ''
    # /0 覆盖整个地址族。本项目 23 个规则集都按服务划分，出现 /0 必是上游手误
    # （例如把 1.2.3.4/32 误写成 /0），放行会把全部 IP 流量导向该策略组，
    # 后果远大于漏掉一条规则，所以显式拒绝并告警。
    if network.prefixlen == 0:
        logger.warning(f'丢弃覆盖整个地址族的 IP 规则: {value} -> {network}')
        return ''
    return str(network)


def classify_rules(rules: List[str]) -> RuleSet:
    """
    按类型归类规则，白名单外的类型静默丢弃。
    尾部标记（no-resolve 等）在此剥离，输出时按类型统一重建。
    域名统一转小写（mihomo 匹配前会把待查域名小写，大写变体是死规则）。
    """
    result = RuleSet()

    for raw in rules:
        rule = raw.strip()
        if not rule or rule.startswith('#'):
            continue

        head, sep, rest = rule.partition(',')
        if not sep:
            continue

        rule_type = head.strip().upper()
        rest = rest.strip()
        if rule_type not in RULE_TYPE_WHITELIST or not rest:
            continue

        if rule_type in VALUE_ONLY_TYPES:
            value = rest.split(',')[0].strip()
            if not value:
                continue
            if rule_type == 'DOMAIN-SUFFIX':
                result.domain_suffix.add(value.lower())
            elif rule_type == 'DOMAIN':
                result.domain.add(value.lower())
            elif rule_type == 'DOMAIN-KEYWORD':
                result.domain_keyword.add(value.lower())
            elif rule_type in ('IP-CIDR', 'IP-CIDR6'):
                cidr = normalize_cidr(value)
                if cidr:
                    result.ip_cidr.add(cidr)
        else:
            # PROCESS-NAME / DST-PORT / SRC-PORT：原样保留尾部参数
            result.other.add(f'{rule_type},{rest}')

    return result


def collect_blacklist_cidrs(blacklist: List[str]) -> Tuple[List[str], List[str]]:
    """从黑名单中分离出 IP 网段条目
    :return: (归一化后的 CIDR 列表, 对应的原始条目文本)
    """
    cidrs: List[str] = []
    origins: List[str] = []
    for entry in blacklist:
        head, sep, rest = str(entry).strip().partition(',')
        if not sep or head.strip().upper() not in ('IP-CIDR', 'IP-CIDR6'):
            continue
        cidr = normalize_cidr(rest.split(',')[0].strip())
        if cidr:
            cidrs.append(cidr)
            origins.append(str(entry).strip())
    return cidrs, origins


def apply_blacklist(rules: RuleSet, blacklist: List[str]) -> List[str]:
    """
    剔除黑名单条目。域名等类型按解析后的元素精确剔除；
    IP 网段走 IPSet 集合差 —— 文本精确匹配会被「同一网段的另一种写法」和
    「产物侧被合并成超网」两种情况绕过，集合差不会。
    :return: 一条都没命中的黑名单条目（通常意味着上游已改名，条目该清理了）
    """
    unmatched: List[str] = []

    bl_cidrs, bl_origins = collect_blacklist_cidrs(blacklist)
    ip_entries = set(bl_origins)
    if bl_cidrs and rules.ip_cidr:
        mark = len(unmatched)
        try:
            current = IPSet(rules.ip_cidr)
            remaining = current - IPSet(bl_cidrs)
            # 命中判定必须基于剔除前的 current，不能用 remaining
            for cidr, origin in zip(bl_cidrs, bl_origins):
                if not (IPSet([cidr]) & current):
                    unmatched.append(origin)
            rules.ip_cidr = {str(c) for c in remaining.iter_cidrs()}
        except Exception as e:
            logger.error(f'IP 黑名单集合差计算失败，回退为精确匹配: {e}')
            del unmatched[mark:]  # 丢弃 try 分支里已记录的部分结果，避免重复
            for cidr, origin in zip(bl_cidrs, bl_origins):
                if cidr in rules.ip_cidr:
                    rules.ip_cidr.discard(cidr)
                else:
                    unmatched.append(origin)
    elif bl_cidrs:
        unmatched.extend(bl_origins)

    for entry in blacklist:
        text = str(entry).strip()
        if not text or text.startswith('#') or text in ip_entries:
            continue

        # 用同一个分类器解析黑名单条目，保证与产物侧的归一化完全对称
        parsed = classify_rules([text])
        hit = False
        for bucket in RuleSet.BUCKETS:
            values = getattr(parsed, bucket)
            if not values:
                continue
            target = getattr(rules, bucket)
            for value in values:
                if value in target:
                    target.discard(value)
                    hit = True

        if not hit:
            unmatched.append(text)

    return unmatched


def write_output(output_file_path: Path, rules: RuleSet, optimized_cidrs: List[str]) -> None:
    """输出规则。newline 固定为 LF，避免在 Windows 本地运行时整体翻转成 CRLF。"""
    output_file_path.parent.mkdir(parents=True, exist_ok=True)
    total = (
        len(rules.domain_suffix) + len(rules.domain) + len(rules.domain_keyword)
        + len(optimized_cidrs) + len(rules.other)
    )

    with open(output_file_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(f'# NAME {output_file_path.name} \n')
        f.write(f'# Total: {total} Rules\n')

        for rule in sorted(rules.domain_suffix):
            f.write(f'DOMAIN-SUFFIX,{rule}\n')
        for rule in sorted(rules.domain):
            f.write(f'DOMAIN,{rule}\n')
        for rule in sorted(rules.domain_keyword):
            f.write(f'DOMAIN-KEYWORD,{rule}\n')
        for cidr in optimized_cidrs:
            prefix = 'IP-CIDR6' if ':' in cidr else 'IP-CIDR'
            f.write(f'{prefix},{cidr},no-resolve\n')
        for rule in sorted(rules.other):
            f.write(f'{rule}\n')

    logger.info(f'Output {total} rules to {output_file_path}')


def merge(rule_urls: List[str], output_file_path: Path, session: requests.Session,
          additional_rules: Optional[List[str]] = None,
          blacklist: Optional[List[str]] = None) -> bool:
    """
    合并单个规则文件。出现下列任一情况即跳过写入、保留磁盘上的现有产物，
    避免上游或镜像抖动时把缩水的规则集静默发布出去：
      · 任一远端源 HTTP 层失败
      · 任一远端源返回 200 但解析不出一条规则（镜像错误页、仓库改 HTML 跳转等）
      · 最终结果为 0 条（base 文件丢失或被清空时会这样）
    :return: 是否成功写入
    """
    additional_rules = additional_rules or []
    blacklist = blacklist or []
    name = output_file_path.name

    downloaded, failed = download_rules(rule_urls, session)
    if failed:
        logger.error(
            f'{name}: {len(failed)}/{len(rule_urls)} 个远端源下载失败，'
            f'跳过写入以保护现有产物'
        )
        for url in failed:
            logger.error(f'  失败源: {url}')
        return False

    # HTTP 200 不代表内容是规则。逐源校验，避免错误页被当成「成功但为空」
    empty_sources = [url for url, lines in downloaded.items() if not classify_rules(lines).any()]
    if empty_sources:
        logger.error(
            f'{name}: {len(empty_sources)}/{len(rule_urls)} 个远端源返回 200 但解析不出规则，'
            f'跳过写入以保护现有产物'
        )
        for url in empty_sources:
            logger.error(f'  疑似错误页: {url}')
        return False

    # base 规则与网络规则一起分类，Set 天生去重
    all_lines: List[str] = list(additional_rules)
    for lines in downloaded.values():
        all_lines.extend(lines)
    rules = classify_rules(all_lines)

    unmatched = apply_blacklist(rules, blacklist)
    if unmatched:
        logger.warning(f'{name}: {len(unmatched)} 条黑名单未命中任何规则，建议清理:')
        for entry in unmatched:
            logger.warning(f'  未命中: {entry}')

    if not rules.any():
        logger.error(f'{name}: 合并结果为 0 条规则，跳过写入以保护现有产物')
        return False

    optimized_cidrs = optimize_ip_cidr(rules.ip_cidr)

    try:
        write_output(output_file_path, rules, optimized_cidrs)
    except Exception as e:
        logger.error(f'Failed to write output file {output_file_path}: {e}')
        return False

    return True


def read_base_rules(base_file_name: str) -> List[str]:
    """
    读取基础规则文件
    :param base_file_name: 基础规则文件名称
    :return: 规则列表
    :raises OSError/UnicodeDecodeError/FileNotFoundError: 文件不存在或读不出来时抛出，
        由调用方判为失败。不能吞成空列表 —— 对有远端源的文件，静默返回 [] 会让产物
        丢掉全部手写规则而总数仍 >0，零输出守卫抓不到，等于静默数据丢失。
        本项目约定每个 options 键都有同名 base 文件（内容可以为空），所以「不存在」
        本身就是异常状态。
    """
    base_file = BASE_RULES_DIR / base_file_name
    lines = base_file.read_text(encoding='utf-8').splitlines()
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith('#')]


def merge_rules() -> List[str]:
    """按配置合并全部规则，返回失败的文件名列表"""
    options, blacklists = load_config()
    session = get_session()
    failures: List[str] = []

    if GLOBAL_MIRROR:
        logger.info(f'使用加速镜像: {GLOBAL_MIRROR}')

    for file_name, urls in options.items():
        output_file_path = OUTPUT_RULES_DIR / file_name
        blacklist = blacklists.get(file_name, [])
        try:
            additional_rules = read_base_rules(file_name)
        except Exception as e:
            logger.error(f'{file_name}: 读取 base 规则失败，跳过写入以保护现有产物: {e}')
            failures.append(file_name)
            continue
        if merge(urls, output_file_path, session, additional_rules, blacklist):
            logger.info(f'Rules merged to {output_file_path}')
        else:
            failures.append(file_name)

    return failures


def main() -> int:
    failures = merge_rules()
    if failures:
        logger.error(f'{len(failures)} 个规则文件未更新: {", ".join(failures)}')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
