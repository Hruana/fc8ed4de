#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pathlib import Path
import sys

def remove_duplicates_from_file(file_path: str):
    """去除单个文本文件内的重复行，保持原有顺序"""
    path = Path(file_path)
    
    if not path.exists() or not path.is_file():
        print(f"错误: 文件不存在或不是一个有效的文件 -> {file_path}")
        return
        
    try:
        # 读取原文件内容
        with open(path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        new_lines = []
        seen = set()
        removed_count = 0
        
        # 遍历每一行，去重并保持顺序
        duplicated_lines = []
        for line in lines:
            if line not in seen:
                seen.add(line)
                new_lines.append(line)
            else:
                removed_count += 1
                duplicated_lines.append(line.strip() if line.strip() else "<空行>")
                
        # 写回原文件
        if removed_count > 0:
            with open(path, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
            
            print(f"成功: [{path.name}] 删除了 {removed_count} 行重复内容。")
            print("删除的具体重复内容如下:")
            for i, dup_line in enumerate(duplicated_lines, 1):
                print(f"  {i}. {dup_line}")
        else:
            print(f"[{path.name}] 未发现重复行，无需修改。")
            
    except Exception as e:
         print(f"处理文件 {path.name} 时出错: {e}")

if __name__ == '__main__':
    # 获取脚本同级目录并定位到根目录下的 rules\base\Inside.list
    CURRENT_DIR = Path(__file__).resolve().parent
    TARGET_FILE = CURRENT_DIR.parent / 'rules' / 'base' / 'Inside.list'
    
    # 执行单文件去重
    remove_duplicates_from_file(str(TARGET_FILE))
