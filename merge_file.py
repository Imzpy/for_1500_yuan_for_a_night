import glob
import os
import sys

import os
import glob


def merge_files(directory_path, extensions, output_file=None):
    if not extensions:
        print("扩展名列表为空，未进行任何搜索。")
        return

    # 动态生成搜索模式
    patterns = [os.path.join(directory_path, '**', f'*{ext}') for ext in extensions]
    print(f"搜索模式: {patterns}")

    # 收集所有匹配文件
    matched_files = []
    for pattern in patterns:
        files = glob.glob(pattern, recursive=True)
        matched_files.extend(files)
        print(f"扩展名 '{pattern.split("/")[-1]}' 匹配到 {len(files)} 个文件。")

    matched_files = list(set(matched_files))  # 去重（如果扩展名重叠）
    matched_files.sort()  # 按路径排序

    if not matched_files:
        print(f"在目录 '{directory_path}' 及其子目录中未找到任何匹配文件（扩展名: {extensions}）。")
        return

    print(f"找到 {len(matched_files)} 个文件，开始合并...")

    # 自动生成输出文件名，如果未指定
    if output_file is None:
        first_ext = extensions[0].lstrip('.')  # 如 '.java' -> 'java'
        output_file = f'merged_{first_ext}_files.{first_ext}'

    output_path = os.path.join(directory_path, output_file)

    with open(output_path, 'wb') as outfile:
        for file_path in matched_files:
            relative_path = os.path.relpath(file_path, directory_path)
            # 动态分隔符，根据扩展名调整注释
            ext = os.path.splitext(file_path)[1]
            outfile.write(
                f"\n// ==================== 文件: {relative_path} (扩展名: {ext}) ====================\n\n".encode(
                    "utf-8"))
            try:
                with open(file_path, 'rb') as infile:
                    content = infile.read()
                    outfile.write(content)
                    outfile.write(b'\n')
            except Exception as e:
                print(f"读取文件 '{file_path}' 时出错: {e}")
                continue

    print(f"合并完成！输出文件: '{output_path}'")
    print(f"总共处理了 {len(matched_files)} 个文件（扩展名: {extensions}）。")


all_file = [
    ".js",
    ".html",
    ".java",
    ".kt"
]
merge_files(r"D:\desktop\保活\1127\pangle\raw\com\bytedance", all_file)
