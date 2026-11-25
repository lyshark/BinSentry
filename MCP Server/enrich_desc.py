# -*- coding: utf-8 -*-
"""用 C++ 接口表的英文 usage 补齐 binsentry_interfaces.json 里为空的 desc。

不依赖 fastmcp（build_interfaces.py 需要导入 mcp_server，缺依赖时跑不了）。
口径与 build_interfaces.py 一致：只在 desc 为空时填充，不覆盖人工维护的说明。

用法：
    python enrich_desc.py           # 原地补齐
    python enrich_desc.py --check   # 只统计，不写文件
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CPP = HERE.parent / "binsentry_commands.cpp"
TARGET = HERE / "binsentry_interfaces.json"


def load_cpp_catalog() -> dict[str, str]:
    text = CPP.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"g_ifaceItems\[\]\s*=\s*\{", text)
    if not m:
        raise SystemExit("[enrich] binsentry_commands.cpp 中找不到 g_ifaceItems")
    block = text[m.end():]
    end = block.find("\n\t};")
    if end > 0:
        block = block[:end]
    pairs = dict(re.findall(r'\{\s*"([^"]+)"\s*,\s*"((?:[^"\\]|\\.)*)"\s*\}', block))
    return {k: v.replace('\\"', '"').replace("\\\\", "\\") for k, v in pairs.items()}


def main() -> int:
    check = "--check" in sys.argv
    cpp = load_cpp_catalog()
    data = json.loads(TARGET.read_text(encoding="utf-8"))
    empty_before = sum(1 for e in data.values() if not e.get("desc"))
    filled = 0
    for name, entry in data.items():
        if not entry.get("desc") and cpp.get(name):
            entry["desc"] = cpp[name]
            filled += 1
    rest = sum(1 for e in data.values() if not e.get("desc"))
    print(f"[enrich] 接口 {len(data)} 条 | 空说明 {empty_before} → {rest} | 本次补齐 {filled}")
    if check:
        print("[enrich] --check：未写入")
        return 0
    TARGET.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"[enrich] 已写入 {TARGET.name}（{TARGET.stat().st_size / 1024:.0f} KB）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
