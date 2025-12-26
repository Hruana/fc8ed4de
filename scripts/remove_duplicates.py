#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from collections import defaultdict

base_dir = os.path.join(os.path.dirname(__file__), '../rules/')


def scan_conflicts():
    # 只扫描一层目录结构下的 .list 文件
    file_lines = {}
    line_files = defaultdict(set)
    for fname in os.listdir(base_dir):
        fpath = os.path.join(base_dir, fname)
        if fname.endswith('.list') and os.path.isfile(fpath):
            with open(fpath, encoding='utf-8') as f:
                lines = set(
                    line.strip()
                    for line in f
                    if line.strip() and not line.strip().startswith('#')
                )
                file_lines[fname] = lines
                for line in lines:
                    line_files[line].add(fname)

    # 找出互相有冲突的文件对
    conflict_pairs = defaultdict(lambda: defaultdict(set))
    for line, files in line_files.items():
        if len(files) > 1:
            files = list(files)
            for i in range(len(files)):
                for j in range(i + 1, len(files)):
                    f1, f2 = files[i], files[j]
                    conflict_pairs[(f1, f2)][line].add(f1)
                    conflict_pairs[(f1, f2)][line].add(f2)
    return conflict_pairs


def remove_conflicts_interactive(conflict_pairs):
    handled = set()
    for (f1, f2), lines_dict in conflict_pairs.items():
        if (f1, f2) in handled or (f2, f1) in handled:
            continue
        lines = list(lines_dict.keys())
        print(f"\n文件冲突: {f1} <-> {f2}")
        print(f"冲突行数: {len(lines)}")
        for line in lines[:10]:
            print(f"  {line}")
        if len(lines) > 10:
            print("  ...更多冲突行未显示...")

        print(f"请选择要保留的文件（输入1或2）：")
        print(f"1. 保留 {f1}，删除 {f2} 中的冲突内容")
        print(f"2. 保留 {f2}，删除 {f1} 中的冲突内容")
        choice = input("你的选择: ").strip()
        if choice == '1':
            to_keep, to_del = f1, f2
        elif choice == '2':
            to_keep, to_del = f2, f1
        else:
            print("输入无效，跳过本组冲突。")
            handled.add((f1, f2))
            continue

        # 获取要删除文件的全部内容
        del_path = os.path.join(base_dir, to_del)
        keep_path = os.path.join(base_dir, to_keep)
        with open(keep_path, encoding='utf-8') as f:
            keep_lines = set(
                line.strip()
                for line in f
                if line.strip() and not line.strip().startswith('#')
            )
        # 只删除与保留文件重复的有效内容行，保留空行和注释行
        keep_content_lines = set(
            line.strip()
            for line in open(keep_path, encoding='utf-8')
            if line.strip() and not line.strip().startswith('#')
        )
        new_del_lines = []
        with open(del_path, encoding='utf-8') as f:
            for line in f:
                stripped = line.strip()
                # 保留空行和注释行
                if not stripped or stripped.startswith('#'):
                    new_del_lines.append(line)
                # 有效内容行且与保留文件冲突则删除，否则保留
                elif stripped not in keep_content_lines:
                    new_del_lines.append(line)
                # 冲突行则跳过
        with open(del_path, 'w', encoding='utf-8') as f:
            f.writelines(new_del_lines)
        print(f"已删除 {to_del} 中与 {to_keep} 冲突的内容行。")
        handled.add((f1, f2))


def main():
    conflict_pairs = scan_conflicts()
    if not conflict_pairs:
        print("未发现文件冲突。")
    else:
        remove_conflicts_interactive(conflict_pairs)


if __name__ == '__main__':
    main()
