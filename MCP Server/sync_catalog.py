# -*- coding: utf-8 -*-
"""把 C++ 接口表里“未经 SDK 封装”的接口登记进 binsentry_interfaces.json。

背景：MCP 的 ``binsentry_call`` 会先按 CATALOG（即本 JSON）校验接口名，
不在 JSON 里的接口会被当成“未知接口”直接拒绝。断点属性命令
（``Set/Get/Reset*Breakpoint*``）由属性表分发、没有 SDK 方法，因此此前
MCP 侧完全不可达。本脚本为这些接口生成“通用调用”条目，使其：

* 出现在 ``binsentry_list_interfaces``；
* 可被 ``binsentry_call(interface=..., params=...)`` 调用；
* 描述/参数/示例来自官网接口库与 C++ usage。

不依赖 fastmcp，纯 Python 环境即可运行。

用法：
    python sync_catalog.py            # 补齐缺失接口
    python sync_catalog.py --check    # 只报告差异
"""
from __future__ import annotations

import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
CPP = HERE.parent / "binsentry_commands.cpp"
DB = HERE.parent / "HTML" / "ifaces.db.js"
TARGET = HERE / "binsentry_interfaces.json"


def load_cpp_catalog() -> dict[str, str]:
    text = CPP.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"g_ifaceItems\[\]\s*=\s*\{", text)
    if not m:
        raise SystemExit("[sync] binsentry_commands.cpp 中找不到 g_ifaceItems")
    block = text[m.end():]
    end = block.find("\n\t};")
    if end > 0:
        block = block[:end]
    pairs = dict(re.findall(r'\{\s*"([^"]+)"\s*,\s*"((?:[^"\\]|\\.)*)"\s*\}', block))
    return {k: v.replace('\\"', '"').replace("\\\\", "\\") for k, v in pairs.items()}


def load_web_db() -> dict[str, dict]:
    if not DB.exists():
        return {}
    m = re.search(r"__IFACES__\s*=\s*(\[.*?\]);", DB.read_text(encoding="utf-8"), re.S)
    if not m:
        return {}
    return {e["name"]: e for e in json.loads(m.group(1)) if e.get("name")}


def build_entry(name: str, usage: str, web: dict | None) -> dict:
    web = web or {}
    py = web.get("py", "")
    json_example = web.get("json", "")
    try:
        payload = json.loads(json_example).get("params", {}) if json_example else {}
    except (ValueError, AttributeError):
        payload = {}
    if not payload:
        payload = {"address": "0x401000", "value": ""}
    params = [
        {"name": k, "desc": "（示例：" + (v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)) + "）"}
        for k, v in payload.items()
    ]
    return {
        "category": web.get("cls") or "GenericApi",
        "category_cn": "通用调用（binsentry_call）",
        "category_code": "",
        "usage": web.get("usage") or usage,
        "desc": usage,
        "method": web.get("method") or "",
        "params": params,
        "outputs": ["state", "message"],
        "fields": [
            {"field": "state", "type": "bool"},
            {"field": "message", "type": "string"},
        ],
        "req_example": json_example
        or json.dumps({"interface": name, "params": payload}, ensure_ascii=False, indent=2),
        "out_example": "",
        "py_example": py,
        "via_generic_call": True,
    }


def main() -> int:
    check = "--check" in __import__("sys").argv
    cpp = load_cpp_catalog()
    web = load_web_db()
    data = json.loads(TARGET.read_text(encoding="utf-8"))
    missing = [n for n in cpp if n not in data]
    print(f"[sync] JSON {len(data)} 条 | 接口表 {len(cpp)} 条 | 待补 {len(missing)} 条")
    if missing:
        print("[sync] 新增: " + ", ".join(missing))
    if check:
        print("[sync] --check：未写入")
        return 0 if not missing else 1
    for name in missing:
        data[name] = build_entry(name, cpp[name], web.get(name))
    TARGET.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"[sync] 已写入 {TARGET.name}（{len(data)} 条，"
          f"{TARGET.stat().st_size / 1024:.0f} KB）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
