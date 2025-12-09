import json
import sys

import pandas as pd
from pandas import Series


def main():
    input_file = r"D:\desktop\保活\1127\log_18436_1010053665"

    allData = []
    with open(input_file, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                allData.append(data)
            except json.JSONDecodeError as e:
                print(f"第{line_num}行JSON解析失败: {e}", file=sys.stderr)

    data_series = [Series(d) for d in allData]
    df = pd.DataFrame(data_series, columns=["tid", "name", "invoke", "return", "args", "stack"])
    df.to_excel(input_file + ".xlsx", index=False, engine="openpyxl")


if __name__ == "__main__":
    main()
