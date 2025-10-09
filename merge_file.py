import glob
import os
import sys


def merge_java_files(directory_path, output_file='merged_java_files.java'):
    """
    递归合并指定目录及其子目录下所有 .java 文件到一个输出文件中。

    Args:
        directory_path (str): 要扫描的目录路径，默认为当前目录。
        output_file (str): 输出文件名，默认为 'merged_java_files.java'。

    Returns:
        None: 直接写入文件并打印结果。
    """
    # 构建递归 .java 文件的 glob 模式
    java_pattern = os.path.join(directory_path, '**', '*.java')
    # 获取所有 .java 文件列表（递归=True）
    java_files = glob.glob(java_pattern, recursive=True)

    # 按文件路径排序，确保输出顺序一致
    java_files.sort()

    if not java_files:
        print(f"在目录 '{directory_path}' 及其子目录中未找到任何 .java 文件。")
        return

    print(f"找到 {len(java_files)} 个 .java 文件，开始合并...")

    # 以写入模式打开输出文件（覆盖现有文件）
    with open(os.path.join(directory_path, output_file), 'wb') as outfile:
        for java_file in java_files:
            # 添加文件路径作为分隔符（以 Java 注释形式）
            relative_path = os.path.relpath(java_file, directory_path)
            outfile.write(f"\n// ==================== 文件: {relative_path} ====================\n\n".encode("utf-8"))

            # 读取并写入文件内容
            try:
                with open(java_file, 'rb') as infile:
                    content = infile.read()
                    outfile.write(content)
                    outfile.write(b'\n')
            except Exception as e:
                print(f"读取文件 '{java_file}' 时出错: {e}")
                continue

    print(f"合并完成！输出文件: '{output_file}'")
    print(f"总共处理了 {len(java_files)} 个文件。")


merge_java_files(r"D:\desktop\wgsdk\sdk1\3\dex\src")
