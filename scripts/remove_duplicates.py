#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pathlib import Path
from collections import defaultdict
from typing import Dict, Set, Tuple, List

# 使用 pathlib 定位 rules 目录
CURRENT_DIR = Path(__file__).resolve().parent
BASE_DIR = CURRENT_DIR.parent / 'rules'


def scan_conflicts() -> Dict[Tuple[str, str], Dict[str, Set[str]]]:
    # 只扫描一层目录结构下的 .list 文件
    file_lines: Dict[str, Set[str]] = {}
    line_files: Dict[str, Set[str]] = defaultdict(set)
    
    if not BASE_DIR.exists():
        print(f"Directory {BASE_DIR} does not exist.")
        return {}

    for fpath in BASE_DIR.iterdir():
        if fpath.is_file() and fpath.suffix == '.list':
            fname = fpath.name
            try:
                # 显式使用 utf-8 读取
                content = fpath.read_text(encoding='utf-8')
                lines = set()
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped and not stripped.startswith('#'):
                        lines.add(stripped)
                
                file_lines[fname] = lines
                for line in lines:
                    line_files[line].add(fname)
            except Exception as e:
                print(f"Error reading file {fname}: {e}")

    # 找出互相有冲突的文件对
    conflict_pairs: Dict[Tuple[str, str], Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
    for line, files_set in line_files.items():
        files = list(files_set)
        if len(files) > 1:
            for i in range(len(files)):
                for j in range(i + 1, len(files)):
                    f1, f2 = files[i], files[j]
                    # 确保 f1, f2 顺序一致，避免重复 (A, B) 和 (B, A)
                    # 这里保持原逻辑直接加入 conflict_pairs
                    conflict_pairs[(f1, f2)][line].add(f1)
                    conflict_pairs[(f1, f2)][line].add(f2)
    return conflict_pairs


def remove_conflicts_interactive(conflict_pairs: Dict[Tuple[str, str], Dict[str, Set[str]]]):
    handled: Set[Tuple[str, str]] = set()
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
        del_path = BASE_DIR / to_del
        keep_path = BASE_DIR / to_keep
        
        try:
            # 读取保留文件的内容用于比对
            keep_content_lines = set()
            with open(keep_path, encoding='utf-8') as f:
                 for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith('#'):
                        keep_content_lines.add(stripped)
            
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
                    # 冲突行则跳过 implicit
            
            with open(del_path, 'w', encoding='utf-8') as f:
                f.writelines(new_del_lines)
            print(f"已删除 {to_del} 中与 {to_keep} 冲突的内容行。")
            
        except Exception as e:
             print(f"Error processing files {to_keep} and {to_del}: {e}")

        handled.add((f1, f2))


def main():
    conflict_pairs = scan_conflicts()
    if not conflict_pairs:
        print("未发现文件冲突。")
    else:
        remove_conflicts_interactive(conflict_pairs)


if __name__ == '__main__':
    main()
