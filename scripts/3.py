# 文件 A
file_a = 'Outside.list'  # 输入文件 A
# 其他文件列表
other_files = ['Developer.list', 'Download.list', 'Inside.list', 'TravelHK.list', 'TravelUS.list', 'NSFW.list']  # 其他文件名

# 读取文件 A 的内容
with open(file_a, 'r', encoding='utf-8') as f:
    lines_a = f.readlines()

# 读取其他文件的内容并存储在集合中
lines_to_remove = set()
for other_file in other_files:
    with open(other_file, 'r', encoding='utf-8') as f:
        # 使用 strip 去掉行首尾的空白字符（包括换行符）
        lines_to_remove.update(line.strip() for line in f)

# 过滤文件 A 中的行
remaining_lines = [line for line in lines_a if line.strip() not in lines_to_remove]

# 将剩余的行写回文件 A
with open(file_a, 'w', encoding='utf-8') as f:
    f.writelines(remaining_lines)

print(f"文件 A 中的行已根据其他文件进行过滤。")
