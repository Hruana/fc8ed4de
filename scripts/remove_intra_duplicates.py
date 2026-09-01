#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""文件内去重：删除单个规则文件里重复出现的规则行，保持原有顺序。

空行与注释行永不参与去重 —— 它们是文件的分节结构，删掉会静默重排排版。
跨文件的规则冲突由 resolve_cross_conflicts.py 处理。

用法:
    python remove_intra_duplicates.py                    # 处理 rules/base/ 下全部 .list
    python remove_intra_duplicates.py a.list b.list      # 只处理指定文件
    python remove_intra_duplicates.py --dry-run          # 只报告，不改文件
"""

import sys
from pathlib import Path
from typing import List, Tuple

CURRENT_DIR = Path(__file__).resolve().parent
BASE_RULES_DIR = CURRENT_DIR.parent / 'rules' / 'base'


def dedupe_file(path: Path, dry_run: bool = False) -> Tuple[int, List[str]]:
    """
    去除单个文件内的重复规则行
    :return: (删除行数, 被删除的规则内容)
    """
    # newline='' 保留每行原始换行符，回写时不会把 CRLF 翻成 LF
    with open(path, 'r', encoding='utf-8', newline='') as f:
        lines = f.readlines()

    kept: List[str] = []
    seen = set()
    removed: List[str] = []

    for line in lines:
        key = line.strip()
        # 空行和注释行属于文件结构，一律保留
        if not key or key.startswith('#'):
            kept.append(line)
            continue
        if key in seen:
            removed.append(key)
            continue
        seen.add(key)
        kept.append(line)

    if removed and not dry_run:
        with open(path, 'w', encoding='utf-8', newline='') as f:
            f.writelines(kept)

    return len(removed), removed


def resolve_targets(args: List[str]) -> List[Path]:
    """把命令行参数解析为待处理文件列表，缺省为 rules/base 下全部 .list"""
    if not args:
        if not BASE_RULES_DIR.is_dir():
            print(f'错误: 默认目录不存在 -> {BASE_RULES_DIR}')
            return []
        return sorted(BASE_RULES_DIR.glob('*.list'))

    targets: List[Path] = []
    for arg in args:
        path = Path(arg)
        if not path.is_absolute():
            # 相对路径优先按 rules/base 解析，其次按当前工作目录
            candidate = BASE_RULES_DIR / arg
            path = candidate if candidate.exists() else path
        if path.is_dir():
            targets.extend(sorted(path.glob('*.list')))
        else:
            targets.append(path)
    return targets


def main(argv: List[str]) -> int:
    dry_run = '--dry-run' in argv
    args = [a for a in argv if not a.startswith('--')]

    targets = resolve_targets(args)
    if not targets:
        print('没有待处理的文件。')
        return 1

    total_removed = 0
    errors = 0
    for path in targets:
        if not path.is_file():
            print(f'跳过: 文件不存在或不是有效文件 -> {path}')
            errors += 1
            continue
        try:
            count, removed = dedupe_file(path, dry_run)
        except Exception as e:
            print(f'处理文件 {path.name} 时出错: {e}')
            errors += 1
            continue

        if not count:
            continue

        total_removed += count
        action = '发现' if dry_run else '删除了'
        print(f'[{path.name}] {action} {count} 行重复内容:')
        for i, rule in enumerate(removed, 1):
            print(f'  {i}. {rule}')

    if not total_removed:
        print(f'检查了 {len(targets)} 个文件，未发现重复行。')
    elif dry_run:
        print(f'\n共发现 {total_removed} 行重复内容（--dry-run 未改动文件）。')
    else:
        print(f'\n共删除 {total_removed} 行重复内容。')

    if errors:
        print(f'{errors} 个目标处理失败。')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
