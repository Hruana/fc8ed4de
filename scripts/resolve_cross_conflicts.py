#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""跨文件规则冲突处理。

同一条规则出现在多个规则集里时，Clash 只会命中 General.ini 里最靠前的那一条，
靠后的副本是死规则。本脚本按 General.ini 的实际 ruleset 顺序自动判定归属：
保留靠前的文件，清理靠后的文件 —— 不需要人工选择。

清理方式取决于规则来源：
  · 规则在 rules/base/<文件> 里  -> 直接从 base 删除
  · 规则来自远端上游            -> 写入 sources.yaml 的 blacklists

同时报告「后缀遮蔽」：靠后文件的规则被靠前文件的 DOMAIN-SUFFIX / DOMAIN-KEYWORD
覆盖。这类只报告不自动处理 —— 是该收窄那条宽泛规则还是接受现状，需要人判断。

用法:
    python resolve_cross_conflicts.py           # 只报告
    python resolve_cross_conflicts.py --apply   # 报告并写入改动
"""

import re
import sys
import yaml
from netaddr import AddrFormatError, IPNetwork, IPSet
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Tuple

CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = CURRENT_DIR.parent
CONFIG_FILE = CURRENT_DIR / 'sources.yaml'
GENERAL_INI = PROJECT_DIR / 'General.ini'
RULES_DIR = PROJECT_DIR / 'rules'
BASE_RULES_DIR = RULES_DIR / 'base'

RULESET_RE = re.compile(r'^\s*ruleset\s*=\s*([^,]+),\s*(.+?)\s*$')
LIST_NAME_RE = re.compile(r'/rules/([A-Za-z0-9_.\-]+\.list)$')


def load_priority() -> List[str]:
    """从 General.ini 解析本项目规则文件的优先级顺序（越靠前优先级越高）"""
    if not GENERAL_INI.exists():
        print(f'错误: 找不到 {GENERAL_INI}')
        return []

    order: List[str] = []
    for line in GENERAL_INI.read_text(encoding='utf-8').splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(';'):
            continue
        matched = RULESET_RE.match(stripped)
        if not matched:
            continue
        target = matched.group(2)
        # []RULE-SET,xxx / []FINAL 是透传引用，不是本项目的规则文件
        if target.startswith('[]'):
            continue
        name_matched = LIST_NAME_RE.search(target)
        if name_matched:
            name = name_matched.group(1)
            if name not in order:
                order.append(name)
    return order


def read_rules(path: Path) -> Set[str]:
    """读取一个规则文件里的有效规则行"""
    rules = set()
    for line in path.read_text(encoding='utf-8').splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith('#'):
            rules.add(stripped)
    return rules


def parse_rule(rule: str) -> Tuple[str, str]:
    """拆出规则类型与第一个参数"""
    head, sep, rest = rule.partition(',')
    if not sep:
        return rule.strip().upper(), ''
    return head.strip().upper(), rest.split(',')[0].strip()


def find_exact_conflicts(
    priority: List[str], file_rules: Dict[str, Set[str]]
) -> Dict[str, Set[str]]:
    """完全相同的规则行出现在多个文件里 -> 除最高优先级外全部判为需清理"""
    owners: Dict[str, List[str]] = defaultdict(list)
    for name in priority:
        for rule in file_rules.get(name, set()):
            owners[rule].append(name)

    to_remove: Dict[str, Set[str]] = defaultdict(set)
    for rule, names in owners.items():
        if len(names) > 1:
            # priority 顺序遍历，names[0] 即优先级最高者
            for loser in names[1:]:
                to_remove[loser].add(rule)
    return to_remove


def find_shadowed(
    priority: List[str], file_rules: Dict[str, Set[str]]
) -> List[Tuple[str, str, str, str]]:
    """靠后文件的域名规则被靠前文件的 DOMAIN-SUFFIX / DOMAIN-KEYWORD 覆盖"""
    shadowed: List[Tuple[str, str, str, str]] = []
    seen_suffix: Dict[str, str] = {}
    seen_keyword: Dict[str, str] = {}

    for name in priority:
        for rule in sorted(file_rules.get(name, set())):
            rule_type, value = parse_rule(rule)
            if rule_type not in ('DOMAIN', 'DOMAIN-SUFFIX') or not value:
                continue

            # seen_suffix / seen_keyword 只含严格靠前文件的宽泛规则，命中即为跨文件遮蔽。
            # 但同层级的 DOMAIN-SUFFIX 完全重复（parent == value）属于「完全重复」，
            # 已由 find_exact_conflicts 自动处理，不该再丢进「需人工判断」列表。
            labels = value.split('.')
            hit = None
            for index in range(len(labels)):
                parent = '.'.join(labels[index:])
                if parent not in seen_suffix:
                    continue
                if rule_type == 'DOMAIN-SUFFIX' and parent == value:
                    break
                hit = (seen_suffix[parent], f'DOMAIN-SUFFIX,{parent}')
                break
            if hit is None:
                for keyword, owner in seen_keyword.items():
                    if keyword in value:
                        hit = (owner, f'DOMAIN-KEYWORD,{keyword}')
                        break
            if hit:
                shadowed.append((name, rule, hit[0], hit[1]))

        # 本文件处理完再登记自己的宽泛规则，避免文件内自遮蔽混进结果。
        # 必须排序遍历：set 迭代顺序随进程变化，否则同一条规则的归因会跨运行漂移。
        for rule in sorted(file_rules.get(name, set())):
            rule_type, value = parse_rule(rule)
            if not value:
                continue
            if rule_type == 'DOMAIN-SUFFIX':
                seen_suffix.setdefault(value, name)
            elif rule_type == 'DOMAIN-KEYWORD':
                seen_keyword.setdefault(value, name)

    return shadowed


def find_ip_shadowed(
    priority: List[str], file_rules: Dict[str, Set[str]]
) -> List[Tuple[str, str, str, str]]:
    """靠后文件的 IP 网段被靠前文件的超网完整包含 -> 恒不可达。

    这类冲突既不是「整行文本相同」（find_exact_conflicts 查不到），也不是域名后缀
    覆盖（find_shadowed 只处理域名类），必须单独按网段做包含判断。
    :return: [(靠后文件, 被遮蔽规则, 靠前文件, 遮蔽它的超网规则)]
    """
    shadowed: List[Tuple[str, str, str, str]] = []
    seen: List[Tuple[IPSet, str, str]] = []  # (网段集合, 所属文件, 原始规则)

    for name in priority:
        own: List[Tuple[IPNetwork, str]] = []
        for rule in sorted(file_rules.get(name, set())):
            rule_type, value = parse_rule(rule)
            if rule_type not in ('IP-CIDR', 'IP-CIDR6') or not value:
                continue
            try:
                network = IPNetwork(value).cidr
            except (AddrFormatError, ValueError, TypeError, IndexError, KeyError):
                continue
            own.append((network, rule))
            for covered, owner, broad in seen:
                if IPSet([network]).issubset(covered):
                    shadowed.append((name, rule, owner, broad))
                    break

        # 同上：本文件处理完再登记，避免文件内自遮蔽
        for network, rule in own:
            seen.append((IPSet([network]), name, rule))

    return shadowed


def strip_from_base(name: str, rules: Set[str]) -> Set[str]:
    """从 rules/base/<name> 中删除指定规则，返回实际删掉的规则"""
    base_file = BASE_RULES_DIR / name
    if not base_file.exists():
        return set()

    with open(base_file, 'r', encoding='utf-8', newline='') as f:
        lines = f.readlines()

    kept: List[str] = []
    removed: Set[str] = set()
    for line in lines:
        stripped = line.strip()
        if stripped in rules:
            removed.add(stripped)
            continue
        kept.append(line)

    if removed:
        with open(base_file, 'w', encoding='utf-8', newline='') as f:
            f.writelines(kept)
    return removed


class _IndentedDumper(yaml.SafeDumper):
    """让序列项在父键下缩进，与手写的 sources.yaml 风格一致。

    默认的 safe_dump 会输出 indentless 序列（`- x` 与父键同列），
    回写时整个文件会被重排版，真正的改动会被淹没在缩进噪声里。
    """

    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


def add_to_blacklist(pending: Dict[str, Set[str]]) -> int:
    """把远端来源的冲突规则写入 sources.yaml 的 blacklists"""
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f) or {}

    blacklists = config.setdefault('blacklists', {})
    added = 0
    for name, rules in pending.items():
        existing = blacklists.get(name) or []
        current = set(existing)
        for rule in sorted(rules):
            if rule not in current:
                existing.append(rule)
                current.add(rule)
                added += 1
        blacklists[name] = existing

    if added:
        with open(CONFIG_FILE, 'w', encoding='utf-8', newline='\n') as f:
            yaml.dump(
                config, f, Dumper=_IndentedDumper, allow_unicode=True,
                sort_keys=False, default_flow_style=False, width=4096,
            )
    return added


def main(argv: List[str]) -> int:
    apply_changes = '--apply' in argv

    priority = load_priority()
    if not priority:
        print('未能从 General.ini 解析出任何规则文件顺序。')
        return 1

    present = {path.name for path in RULES_DIR.glob('*.list')}
    unreferenced = sorted(present - set(priority))
    if unreferenced:
        print(f'提示: 以下产物未被 General.ini 引用，已排除在冲突分析外: {", ".join(unreferenced)}\n')

    file_rules: Dict[str, Set[str]] = {}
    for name in priority:
        path = RULES_DIR / name
        if path.exists():
            file_rules[name] = read_rules(path)
        else:
            print(f'提示: General.ini 引用了 {name}，但产物不存在')

    print(f'优先级顺序 ({len(priority)} 个文件): {" > ".join(priority)}\n')

    to_remove = find_exact_conflicts(priority, file_rules)
    # 两类遮蔽检测都必须在 --apply 改动文件之前算完，否则用的是过期的 file_rules
    shadowed = find_shadowed(priority, file_rules)
    ip_shadowed = find_ip_shadowed(priority, file_rules)

    if not to_remove:
        print('未发现完全重复的跨文件规则。')
    else:
        total = sum(len(rules) for rules in to_remove.values())
        print(f'发现 {total} 条跨文件重复规则，按优先级判定需从以下文件清理:')
        for name in priority:
            if name not in to_remove:
                continue
            rules = to_remove[name]
            print(f'\n  {name} ({len(rules)} 条):')
            for rule in sorted(rules)[:10]:
                print(f'    {rule}')
            if len(rules) > 10:
                print(f'    ...另有 {len(rules) - 10} 条')

        if apply_changes:
            pending_blacklist: Dict[str, Set[str]] = {}
            for name, rules in to_remove.items():
                removed = strip_from_base(name, rules)
                if removed:
                    print(f'\n已从 rules/base/{name} 删除 {len(removed)} 条')
                remaining = rules - removed
                if remaining:
                    pending_blacklist[name] = remaining
            if pending_blacklist:
                added = add_to_blacklist(pending_blacklist)
                print(f'已向 {CONFIG_FILE.name} 的 blacklists 追加 {added} 条')
            print('\n请重新运行 merge_rules.py 生成最新产物。')
        else:
            print('\n（只读模式，未改动任何文件。加 --apply 执行清理）')

    if shadowed:
        print(f'\n另有 {len(shadowed)} 条规则被靠前文件的宽泛规则遮蔽（需人工判断，不自动处理）:')
        grouped: Dict[Tuple[str, str, str], int] = defaultdict(int)
        for loser, _rule, owner, broad in shadowed:
            grouped[(owner, broad, loser)] += 1
        for (owner, broad, loser), count in sorted(grouped.items(), key=lambda x: -x[1])[:15]:
            print(f'  {count:4d} 条  {loser}  <-  {owner} 的 {broad}')

    if ip_shadowed:
        print(f'\n另有 {len(ip_shadowed)} 条 IP 网段被靠前文件的超网完整包含（恒不可达，需人工判断）:')
        for loser, rule, owner, broad in ip_shadowed:
            print(f'  {loser:22s} {rule:38s}  <-  {owner} 的 {broad}')

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
