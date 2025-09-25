
import os
import shutil
from collections import defaultdict
import javalang  # 用于解析Java包名
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

def get_java_files(directory):
    """获取目录下所有.java文件路径"""
    return [os.path.join(root, f) for root, _, files in os.walk(directory) for f in files if f.endswith('.java')]

def read_code(file_path):
    """读取Java文件内容，忽略读取错误"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read().strip()  # 去除前后空白
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return ""  # 返回空字符串，跳过

def extract_package(java_code):
    """从Java代码中提取包名，使用javalang解析"""
    try:
        tree = javalang.parse.parse(java_code)
        if tree.package:
            return tree.package.name.replace('.', '_')  # 将.替换为_，用于文件名前缀
        return ""  # 无包名，返回空
    except javalang.parser.JavaSyntaxError:
        print("Syntax error in extracting package.")
        return ""  # 语法错误，返回空

def flatten_and_rename_copy(src_dir, dst_dir):
    """将src_dir的文件扁平复制到dst_dir根目录，文件名添加包名前缀"""
    if os.path.exists(dst_dir):
        shutil.rmtree(dst_dir)  # 清空目标目录，如果存在
    os.makedirs(dst_dir, exist_ok=True)

    files = get_java_files(src_dir)
    for src_file in files:
        code = read_code(src_file)
        if not code:
            continue
        package_prefix = extract_package(code)
        orig_name = os.path.basename(src_file)
        new_name = f"{package_prefix}_{orig_name}" if package_prefix else orig_name
        dst_path = os.path.join(dst_dir, new_name)

        # 复制文件
        try:
            shutil.copy(src_file, dst_path)
            print(f"Copied and renamed: {src_file} -> {dst_path}")
        except Exception as e:
            print(f"Copy failed for {src_file}: {e}")

def align_filenames(cp_dir_a, cp_dir_b, threshold=0.8, backup=False):
    """基于源码文本相似度对齐cp_dir_b的文件名到cp_dir_a（原地重命名）"""
    files_a = get_java_files(cp_dir_a)
    files_b = get_java_files(cp_dir_b)

    # 读取所有文件内容作为raw text
    texts_a = [read_code(f) for f in files_a if read_code(f)]
    texts_b = [read_code(f) for f in files_b if read_code(f)]

    if not texts_a or not texts_b:
        print("No valid Java files found in copied directories.")
        return {}

    # TF-IDF 向量化（直接用raw text）
    vectorizer = TfidfVectorizer(analyzer='char_wb', ngram_range=(2, 4))  # 使用字符n-gram提升代码相似度准确性
    tfidf_matrix = vectorizer.fit_transform(texts_a + texts_b)
    tfidf_a = tfidf_matrix[:len(texts_a)]
    tfidf_b = tfidf_matrix[len(texts_a):]

    # 计算相似度矩阵
    similarity_matrix = cosine_similarity(tfidf_b, tfidf_a)

    # 匹配并输出/原地重命名
    matches = defaultdict(list)
    for i, sim_row in enumerate(similarity_matrix):
        max_sim = max(sim_row) if sim_row.size > 0 else 0
        if max_sim >= threshold:
            j = sim_row.argmax()
            orig_file = files_a[j]
            orig_name = os.path.basename(orig_file)
            target_file = files_b[i]
            new_path = os.path.join(os.path.dirname(target_file), orig_name)

            if target_file == new_path:
                print(f"Already matched: {target_file} (similarity: {max_sim:.4f})")
                continue

            # 备份原文件（可选）
            if backup and os.path.exists(target_file):
                backup_path = target_file + ".bak"
                try:
                    shutil.copy(target_file, backup_path)
                    print(f"Backed up: {target_file} -> {backup_path}")
                except Exception as e:
                    print(f"Backup failed for {target_file}: {e}")

            # 原地重命名
            try:
                os.rename(target_file, new_path)
                matches[target_file].append((orig_file, max_sim))
                print(f"Matched and renamed in place: {target_file} -> {new_path} (highest similarity: {max_sim:.4f})")
            except FileExistsError:
                print(f"Rename skipped: {new_path} already exists (similarity: {max_sim:.4f})")
            except Exception as e:
                print(f"Rename failed for {target_file}: {e}")
        else:
            print(f"No match for {files_b[i]} (highest similarity: {max_sim:.4f})")

    # 输出所有最高相似度结果总结
    print("\nSummary of highest similarities:")
    for i, sim_row in enumerate(similarity_matrix):
        max_sim = max(sim_row) if sim_row.size > 0 else 0
        j = sim_row.argmax() if sim_row.size > 0 else -1
        match_info = f"{files_a[j]} ({max_sim:.4f})" if j >= 0 else "None"
        print(f"{files_b[i]} -> Highest match: {match_info}")

    return matches

# 示例用法
if __name__ == "__main__":
    dir_a = r"D:\desktop\bh\topon\riseup"  # 替换为待对齐目录
    dir_b = r"D:\desktop\bh\topon\topon"  # 替换为参考目录（Windows路径示例）
    dir_a_cp =  r"D:\desktop\bh\topon\riseup_cp" # 替换为dir_a复制目标目录
    dir_b_cp =  r"D:\desktop\bh\topon\topon_cp"  # 替换为dir_b复制目标目录

    # 先复制并扁平化、重命名
    flatten_and_rename_copy(dir_a, dir_a_cp)
    flatten_and_rename_copy(dir_b, dir_b_cp)

    # 然后对比并在dir_b_cp中原地重命名
    align_filenames(dir_a_cp, dir_b_cp, threshold=0.75, backup=True)  # 可调整阈值和备份







