# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import importlib.util
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
TARGET = HERE / "binsentry_interfaces.json"
DB_CANDIDATES = [
    HERE / "ifaces.db.js",
    HERE.parent / "ifaces.db.js",
    HERE.parent.parent / "HTML" / "ifaces.db.js",
]

def load_server_module():
    spec = importlib.util.spec_from_file_location("mcp_server", HERE / "mcp_server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def load_db(path: Optional[Path]) -> Dict[str, Dict[str, Any]]:
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

def _example_params(db_entry: Optional[Dict[str, Any]]) -> Dict[str, str]:
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
    old: Dict[str, Dict[str, Any]] = {}
    if TARGET.exists():
        old = json.loads(TARGET.read_text(encoding="utf-8"))
    print(f"[build] 旧版 JSON: {len(old)} 条 | 客户端接口: "
          f"{len(server._collect_methods())} 条")

    result: Dict[str, Dict[str, Any]] = {}
    added: List[str] = []
    legacy_only_params: List[str] = []

    for cls, method_name, func, _tool_name in server._collect_methods():
        interface = server._interface_of(func, method_name)
        info = old.get(interface, {})
        db_entry = db.get(interface)

        usage = (db_entry or {}).get("usage", "") or info.get("usage", "")
        # 分类统一用 API 类名；旧版 JSON 里的 session/sys 等短码另存备查
        legacy_code = info.get("category_code") or info.get("category") or ""
        category_code = legacy_code if legacy_code not in server._CATEGORY_CN else info.get("category_code", "")
        category = cls.__name__
        category_cn = info.get("category_cn") or server._CATEGORY_CN.get(category, "")

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
            key = key_map.get(pname) or server._PAYLOAD_KEY_ALIASES.get(pname, pname)
            if key in seen:
                continue
            seen.add(key)
            desc = legacy_params.get(key) or demo.get(key) or ""
            params.append({"name": key, "desc": desc})
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
            "desc": info.get("desc", "") or "",
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