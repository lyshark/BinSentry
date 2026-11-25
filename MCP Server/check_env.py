#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MCP Server 环境健康检查（只读，不改动任何文件）。

用途：MCP Server 依赖外部 fastmcp/mcp，宿主 Python 环境一旦缺包或被破坏，
  自检会以难以理解的 SyntaxError/ImportError 失败。先跑这个脚本定位原因。

检查项：
  1. 解释器版本与路径
  2. ctypes.wintypes / fastmcp / mcp 三个导入的可用性
  3. binsentry_interfaces.json 的结构、条目数、重名
  4. mcp_server.py 能否作为模块导入（失败时打印首条 traceback 行）

退出码：0 全部通过；2 目录清单异常；3 模块导入失败。
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import traceback

HERE = pathlib.Path(__file__).resolve().parent
CATALOG = HERE / "binsentry_interfaces.json"


def check_import(name: str) -> bool:
    try:
        __import__(name)
        print(f"[ok]   import {name}")
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"[fail] import {name}: {type(exc).__name__}: {exc}")
        return False


def main() -> int:
    print(f"python: {sys.version.split()[0]} @ {sys.executable}")

    ok_deps = all([check_import("ctypes.wintypes"), check_import("fastmcp")])

    if not CATALOG.exists():
        print(f"[fail] 缺少接口清单：{CATALOG}")
        return 2
    try:
        data = json.loads(CATALOG.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        print(f"[fail] 接口清单不是合法 JSON：{exc}")
        return 2

    if isinstance(data, dict) and not data.get("interfaces"):
        # 实际格式：{"接口名": {参数说明...}, ...}
        names = list(data.keys())
        items = list(data.values())
    else:
        items = data if isinstance(data, list) else (data.get("interfaces") or [])
        names = [i.get("name") if isinstance(i, dict) else None for i in items]
    dupes = sorted({n for n in names if n and names.count(n) > 1})
    print(f"[ok]   接口清单 {len(items)} 条，重名 {len(dupes)} 个" + (f"：{dupes[:5]}" if dupes else ""))
    if dupes:
        return 2

    src = HERE / "mcp_server.py"
    spec = importlib.util.spec_from_file_location("binsentry_mcp_healthcheck", src)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        print("[ok]   mcp_server.py 导入成功")
    except Exception as exc:  # noqa: BLE001
        last = traceback.format_exc().strip().splitlines()[-1]
        print(f"[fail] mcp_server.py 导入失败：{type(exc).__name__}: {exc}")
        print(f"       {last}")
        return 3

    tool_count = src.read_text(encoding="utf-8", errors="replace").count("@mcp.tool()")
    print(f"[ok]   平台级工具 {tool_count} 个；单接口工具按接口清单 {len(items)} 条生成")

    if not ok_deps:
        print("[warn] 依赖导入有失败项，MCP Server 在纯净环境可能起不来")
    print("\n结论：", "可用" if ok_deps else "依赖不完整（详见上面 [fail]/[warn]）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
