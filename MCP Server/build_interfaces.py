# -*- coding: utf-8 -*-
"""生成 / 更新 binsentry_interfaces.json —— MCP 工具说明数据源
================================================================

数据来源（优先级由高到低）：

1. ``__init__.py``            权威：接口清单、Python 方法签名、payload 键名映射
2. ``binsentry_interfaces.json``（旧版）
                              权威：接口英文说明、参数含义、出参、result 字段结构
3. ``ifaces.db.js``（官网接口库）
                              补充：中文用途、所属 API 类、Python / HTTP 调用示例
4. ``binsentry_commands.cpp`` 兜底：``g_ifaceItems`` 里的英文 usage
                              仅当某接口的 ``desc`` 为空时填入，保证 MCP 工具说明不空

只有当接口在旧版 JSON 中不存在时，才用接口库的示例值兜底生成参数说明，
因此本脚本对已有条目是「增量补全」，不会覆盖人工维护过的权威内容。

用法：
    python build_interfaces.py            # 原地更新 binsentry_interfaces.json
    python build_interfaces.py --check    # 只报告差异，不写文件
    python build_interfaces.py --db PATH  # 指定接口库 ifaces.db.js 路径

注意：本脚本只同步「接口/签名/示例」结构，参数语义、类型、必填与返回字段由
``enrich_interfaces.py`` 依据 C++ 源码补齐；生成后请按顺序执行
``python enrich_interfaces.py`` 和 ``python mcp_server.py --verify``。
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
TARGET = HERE / "binsentry_interfaces.json"

# 接口库候选路径（官网构建产物，可能位于仓库上层的展示站目录）
DB_CANDIDATES = [
    HERE / "ifaces.db.js",
    HERE.parent / "ifaces.db.js",
    HERE.parent / "HTML" / "ifaces.db.js",
    HERE.parent.parent / "HTML" / "ifaces.db.js",
]


def load_server_module():
    """复用 mcp_server 的内省逻辑，保证生成口径与 MCP Server 完全一致。

    生成器只需要 FastMCP 的装饰器壳；未安装 fastmcp 时注入最小桩，
    这样维护脚本不必为了改 JSON 额外安装 MCP 运行时。
    """
    try:
        import fastmcp  # noqa: F401
    except (ImportError, SyntaxError):
        import sys
        import types
        stub = types.ModuleType("fastmcp")

        class _StubFastMCP:
            def __init__(self, *args, **kwargs):
                pass

            def tool(self, *args, **kwargs):
                if args and callable(args[0]):
                    return args[0]
                return lambda fn: fn

            def run(self, *args, **kwargs):
                pass

        stub.FastMCP = _StubFastMCP
        stub.Context = object
        sys.modules["fastmcp"] = stub
    spec = importlib.util.spec_from_file_location("mcp_server", HERE / "mcp_server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_db(path: Optional[Path]) -> Dict[str, Dict[str, Any]]:
    """解析 ifaces.db.js（window.__IFACES__ = [...]）为 {接口名: 条目}。"""
    candidates = [path] if path else DB_CANDIDATES
    for cand in candidates:
        if cand and cand.exists():
            text = cand.read_text(encoding="utf-8")
            match = re.search(r"__IFACES__\s*=\s*(\[.*?\]);", text, re.S)
            if not match:
                raise SystemExit(f"[build] 无法在 {cand} 中定位 __IFACES__ 数组")
            entries = json.loads(match.group(1))
            print(f"[build] 接口库: {cand}（{len(entries)} 条）")
            return {e["name"]: e for e in entries if e.get("name")}
    print("[build] 未找到接口库 ifaces.db.js，仅使用旧版 JSON 数据（中文用途/示例不可用）")
    return {}


def load_cpp_catalog() -> Dict[str, str]:
    """从 C++ 接口表 g_ifaceItems 提取 {接口名: 英文用法}。

    这是 Status / 控制台 Help 的同一份数据源，用来兜底填充分类为 ExtraApi、
    人工从未写过说明的接口，避免 MCP 工具描述为空。
    """
    for cand in (HERE.parent / "binsentry_commands.cpp",):
        if not cand.exists():
            continue
        text = cand.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"g_ifaceItems\[\]\s*=\s*\{", text)
        if not m:
            continue
        block = text[m.end():]
        end = block.find("\n\t};")
        if end > 0:
            block = block[:end]
        pairs = dict(re.findall(r'\{\s*"([^"]+)"\s*,\s*"((?:[^"\\]|\\.)*)"\s*\}', block))
        # 还原 C++ 字符串转义（当前用法文本里只有少量 \" 与 \\）
        out = {k: v.replace('\\"', '"').replace("\\\\", "\\") for k, v in pairs.items()}
        print(f"[build] C++ 接口表: {cand.name}（{len(out)} 条用法）")
        return out
    print("[build] 未找到 binsentry_commands.cpp，接口英文说明无法兜底")
    return {}


def _example_params(db_entry: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """接口库请求示例里的 {参数键: 该键的示例值描述}。"""
    if not db_entry:
        return {}
    try:
        body = json.loads(db_entry.get("json") or "{}")
    except (json.JSONDecodeError, ValueError):
        return {}
    raw = body.get("params")
    if not isinstance(raw, dict):
        return {}
    out: Dict[str, str] = {}
    for key, value in raw.items():
        shown = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        out[key] = f"（示例：{shown}）"
    return out


def _req_example(db_entry: Optional[Dict[str, Any]]) -> str:
    if not db_entry:
        return ""
    try:
        body = json.loads(db_entry.get("json") or "{}")
    except (json.JSONDecodeError, ValueError):
        return db_entry.get("json", "")
    return json.dumps(body, ensure_ascii=False, indent=2)


def build(db_path: Optional[Path]) -> Dict[str, Dict[str, Any]]:
    server = load_server_module()
    db = load_db(db_path)
    cpp_desc = load_cpp_catalog()
    category_map = getattr(server, "_CATEGORY_CN", None) or getattr(server, "CATEGORY_CN", {})
    payload_aliases = getattr(server, "_PAYLOAD_KEY_ALIASES", None) or getattr(server, "PAYLOAD_KEY_ALIASES", {})
    old: Dict[str, Dict[str, Any]] = {}
    if TARGET.exists():
        old = json.loads(TARGET.read_text(encoding="utf-8"))
    print(f"[build] 旧版 JSON: {len(old)} 条 | 客户端接口: "
          f"{len(server._collect_methods())} 条")

    result: Dict[str, Dict[str, Any]] = {}
    added: List[str] = []
    legacy_only_params: List[str] = []

    for cls, method_name, func, _tool_name in server._collect_methods():
        interface = server._interface_of(cls, method_name)
        info = old.get(interface, {})
        db_entry = db.get(interface)

        usage = (db_entry or {}).get("usage", "") or info.get("usage", "")
        # 分类统一用 API 类名；旧版 JSON 里的 session/sys 等短码另存备查
        legacy_code = info.get("category_code") or info.get("category") or ""
        category_code = legacy_code if legacy_code not in category_map else info.get("category_code", "")
        category = cls.__name__
        category_cn = info.get("category_cn") or category_map.get(category, "")

        # --- 参数：以方法签名为准，描述尽量取旧版权威文案 ---
        sig = server.inspect.signature(func)
        key_map = server._payload_key_map(func)
        legacy_params = {
            p.get("name"): p.get("desc", "") for p in info.get("params", []) if p.get("name")
        }
        demo = _example_params(db_entry)
        params: List[Dict[str, str]] = []
        seen: set = set()
        for pname, p in sig.parameters.items():
            if pname == "self" or p.kind in (
                server.inspect.Parameter.VAR_POSITIONAL,
                server.inspect.Parameter.VAR_KEYWORD,
            ):
                continue
            key = key_map.get(pname) or payload_aliases.get(pname, pname)
            if key in seen:
                continue
            seen.add(key)
            desc = legacy_params.get(key) or demo.get(key) or ""
            params.append({"name": key, "desc": desc})
        # 旧版里签名中已不存在的历史参数：保留在末尾，避免丢信息
        for key, desc in legacy_params.items():
            if key not in seen:
                params.append({"name": key, "desc": desc})
                legacy_only_params.append(f"{interface}.{key}")

        entry = dict(info)
        entry.update({
            "category": category,
            "category_cn": category_cn,
            "category_code": category_code,
            "usage": usage,
            "desc": info.get("desc", "") or cpp_desc.get(interface, "") or "",
            "method": method_name,
            "params": params,
            "outputs": info.get("outputs", []) or [],
            "fields": info.get("fields", []) or [],
            "req_example": info.get("req_example") or _req_example(db_entry),
            "out_example": info.get("out_example", "") or "",
            "py_example": (db_entry or {}).get("py", "") or info.get("py_example", ""),
        })
        if not info:
            added.append(interface)
        result[interface] = entry

    # 接口表里有、但 SDK 未单独封装的接口（如 50 条断点属性命令）：
    # 登记为“通用调用”条目，否则 binsentry_call 会按 CATALOG 判成未知接口而拒绝。
    for iface, usage in cpp_desc.items():
        if iface in result:
            continue
        db_entry = db.get(iface) or {}
        demo = _example_params(db_entry or None)
        params = [{"name": k, "desc": v} for k, v in demo.items()] or [
            {"name": "address", "desc": "（示例：0x401000）"}
        ]
        result[iface] = {
            "category": db_entry.get("cls") or "GenericApi",
            "category_cn": "通用调用（binsentry_call）",
            "category_code": "",
            "usage": db_entry.get("usage") or usage,
            "desc": usage,
            "method": db_entry.get("method") or "",
            "params": params,
            "outputs": ["state", "message"],
            "fields": [{"field": "state", "type": "bool"}, {"field": "message", "type": "string"}],
            "req_example": db_entry.get("json") or "",
            "out_example": "",
            "py_example": db_entry.get("py") or "",
            "via_generic_call": True,
        }
        if iface not in old:
            added.append(iface)

    dropped = sorted(set(old) - set(result))
    print(f"[build] 生成 {len(result)} 条 | 新增 {len(added)} 条 | 移除 {len(dropped)} 条")
    if added:
        print("[build] 新增接口: " + ", ".join(added))
    if dropped:
        print("[build] 客户端已不存在的接口（已移除）: " + ", ".join(dropped))
    if legacy_only_params:
        print(f"[build] 提醒: {len(legacy_only_params)} 个旧版参数不在方法签名中，已保留："
              + ", ".join(legacy_only_params[:20]))
    if db:
        missing = sorted(set(result) - set(db))
        if missing:
            print(f"[build] 提醒: {len(missing)} 个接口无接口库用途说明: " + ", ".join(missing[:20]))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="生成 binsentry_interfaces.json")
    parser.add_argument("--check", action="store_true", help="只报告差异，不写文件")
    parser.add_argument("--db", type=Path, default=None, help="ifaces.db.js 路径")
    args = parser.parse_args()

    data = build(args.db)
    if args.check:
        print("[build] --check：未写入文件")
        return
    TARGET.write_text(
        json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
    )
    print(f"[build] 已写入 {TARGET.name}（{TARGET.stat().st_size / 1024:.0f} KB）")


if __name__ == "__main__":
    main()
