import random

# 读取文本文件
input_file = 'NSFW.list'  # 输入文件名
output_file = 'NSFW-NEW.list'  # 输出文件名

# 使用集合去重
with open(input_file, 'r', encoding='utf-8') as infile:
    lines = infile.readlines()

# 去重
unique_lines = set(line.strip() for line in lines)

# 将去重后的内容转为列表并打乱顺序
shuffled_lines = list(unique_lines)
random.shuffle(shuffled_lines)

# 写入新文件
with open(output_file, 'w', encoding='utf-8') as outfile:
    for line in shuffled_lines:
        outfile.write(line + '\n')

print(f"新内容已写入 {output_file}")
