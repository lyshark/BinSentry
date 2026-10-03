# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import os
import re
import typing
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from fastmcp import FastMCP

_LIB_PATH = Path(__file__).resolve().parent / "__init__.py"
_spec = importlib.util.spec_from_file_location("binsentry", _LIB_PATH)
_binsentry = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_binsentry)
_IFACE_INFO_PATH = Path(__file__).resolve().parent / "binsentry_interfaces.json"
_IFACE_INFO: Dict[str, Dict[str, Any]] = {}
if _IFACE_INFO_PATH.exists():
    try:
        _IFACE_INFO = json.loads(_IFACE_INFO_PATH.read_text(encoding="utf-8"))
    except Exception:
        _IFACE_INFO = {}

_CATEGORY_CN: Dict[str, str] = {
    "DebugSessionApi": "会话管理",
    "ExecutionControlApi": "运行控制",
    "BreakPointApi": "断点体系",
    "MemoryApi": "内存读写",
    "ModulePeApi": "模块与 PE 解析",
    "RegisterThreadApi": "寄存器与线程",
    "StackTraceApi": "调用栈与追踪",
    "SymbolVarApi": "符号与标注",
    "SystemApi": "系统能力",
    "DisasmXrefApi": "反汇编与交叉引用",
    "LogConfigApi": "日志与配置",
    "AuthApi": "鉴权",
    "ExtraApi": "扩展接口",
}

mcp = FastMCP(
    "BinSentry MCP Server",
    instructions=(
        "BinSentry（远程调试插件）的 MCP 封装。"
        "所有工具通过 HTTP 调用 BinSentry 后端（默认 http://127.0.0.1:6891），"
        "覆盖系统信息、进程与模块、内存读写、反汇编与交叉引用、断点、"
        "调试会话、寄存器与线程、堆栈与跟踪、执行控制、日志与符号等能力。"
        "调用返回 BinSentry 后端的 JSON 结果（已解析为对象）。"
        "工具名即 Python 客户端方法名，参数 Schema 由方法签名生成，"
        "工具描述内含接口名、中文用途、参数含义、调用与请求体示例、返回结构。"
    ),
)

_client: "BinSentryClient" = _binsentry.BinSentryClient(
    address=os.environ.get("BINSENTRY_ADDRESS", "127.0.0.1"),
    port=int(os.environ.get("BINSENTRY_PORT", "6891")),
    api_key=os.environ.get("BINSENTRY_API_KEY"),
)

def _invoke(fn: Callable[[], str]) -> Any:
    try:
        raw = fn()
    except Exception as exc:
        return {"status": "error", "message": f"调用失败: {exc}"}
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return {"status": "ok", "raw": raw}
    return raw

_SKIP_METHODS = {"custom_post", "bind", "set_server"}

def _collect_methods() -> List[tuple]:
    found: Dict[str, List[tuple]] = {}
    order: List[str] = []

    for cls in _binsentry.BinSentryClient.__mro__:
        if cls is object:
            continue
        for name, val in cls.__dict__.items():
            if name.startswith("_") or name in _SKIP_METHODS:
                continue
            if isinstance(val, (staticmethod, classmethod)):
                val = val.__func__
            if not callable(val):
                continue
            if name not in found:
                found[name] = []
                order.append(name)
            found[name].append((cls, name, val))

    result: List[tuple] = []
    for name in order:
        entries = found[name]
        if len(entries) == 1:
            cls, method_name, func = entries[0]
            result.append((cls, method_name, func, name))
            continue
        for cls, method_name, func in entries:
            prefix = re.sub(r"Api$", "", cls.__name__).lower()
            result.append((cls, method_name, func, f"{prefix}_{name}"))
    return result


_PRIMITIVES = {int: "int", str: "str", bool: "bool", float: "float", type(None): "None"}

def _render_annotation(ann: Any) -> str:
    if ann is inspect.Parameter.empty:
        return "Any"
    if ann in _PRIMITIVES:
        return _PRIMITIVES[ann]
    try:
        return repr(ann)
    except Exception:
        return "Any"

def _interface_of(func: Callable, method_name: str) -> str:
    try:
        src = inspect.getsource(func)
    except (OSError, TypeError):
        return method_name
    m = re.search(r'"interface":\s*"([^"]+)"', src)
    return m.group(1) if m else method_name

_PAYLOAD_KEY_ALIASES = {
    "len_": "len",
    "hex_": "hex",
    "type_": "type",
    "def_": "def",
    "id_": "id",
    "max_num": "max",
    "watch_id": "id",
    "start": "start",
    "end": "end",
}

_ENVELOPE_KEYS = {"interface", "params"}

def _payload_key_map(func: Callable) -> Dict[str, str]:
    try:
        src = inspect.getsource(func)
        valid = {pname for pname, _ in _tool_params(inspect.signature(func))}
    except (OSError, TypeError, ValueError):
        return {}

    origin: Dict[str, str] = {}
    for var, param in re.findall(r"(\w+)\s*=\s*validate_hex_address\((\w+)\)", src):
        origin[var] = param

    pair_re = re.compile(
        r'"(?P<key>\w+)"\s*:\s*'
        r'(?:validate_hex_address\((?P<wrapped>\w+)\)|(?P<plain>[A-Za-z_]\w*))'
    )
    assign_re = re.compile(
        r'payload\["(?P<key>\w+)"\]\s*=\s*'
        r'(?:validate_hex_address\((?P<wrapped>\w+)\)|(?P<plain>[A-Za-z_]\w*))'
    )

    mapping: Dict[str, str] = {}
    for rx in (pair_re, assign_re):
        for m in rx.finditer(src):
            key = m.group("key")
            if key in _ENVELOPE_KEYS:
                continue
            token = m.group("wrapped") or m.group("plain")
            param = origin.get(token, token)
            if param in valid:
                mapping.setdefault(param, key)
    return mapping

def _clean_pdesc(text: str) -> str:
    s = text.strip()
    for _ in range(2):
        if s.startswith("（") and s.endswith("）"):
            s = s[1:-1].strip()
        elif s.startswith("(") and s.endswith(")"):
            s = s[1:-1].strip()
        else:
            break
    return s

def _pretty_example(raw: str) -> str:
    if not raw:
        return ""
    try:
        return json.dumps(json.loads(raw), ensure_ascii=False, indent=2)
    except (json.JSONDecodeError, ValueError, TypeError):
        return raw

def _tool_params(sig: inspect.Signature) -> List[tuple]:
    out: List[tuple] = []
    for pname, p in sig.parameters.items():
        if pname == "self" or p.kind in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            continue
        out.append((pname, p))
    return out

def _render_default(p: inspect.Parameter) -> str:
    if p.default is inspect.Parameter.empty:
        return ""
    if p.default is None or isinstance(p.default, (str, int, float, bool, bytes)):
        return f" = {p.default!r}"
    return ""

def _build_tool_source(cls, method_name: str, func: Callable, final_name: str) -> str:
    sig = inspect.signature(func)
    params: List[str] = []
    kwargs: List[str] = []
    doc_lines: List[str] = []

    interface = _interface_of(func, method_name)
    info = _IFACE_INFO.get(interface, {})
    usage = info.get("usage", "") or ""
    html_desc = info.get("desc", "") or ""
    category = info.get("category", "") or cls.__name__
    category_cn = info.get("category_cn", "") or _CATEGORY_CN.get(category, "")
    html_params = {p.get("name"): p.get("desc", "") for p in info.get("params", [])}
    py_example = info.get("py_example", "") or ""
    req_example = _pretty_example(info.get("req_example", "") or "")
    outputs = info.get("outputs", []) or []
    fields = info.get("fields", []) or []

    if usage:
        doc_lines.append(usage)
    if html_desc and html_desc != usage:
        doc_lines.append(html_desc)
    cat_label = f"{category_cn}（{category}）" if category_cn else category
    doc_lines.append(f"接口: {interface} | 分类: {cat_label} | 方法: {cls.__name__}.{method_name}")

    key_map = _payload_key_map(func)
    sig_params = _tool_params(sig)
    for pname, p in sig_params:
        params.append(f"{pname}: {_render_annotation(p.annotation)}{_render_default(p)}")
        kwargs.append(f"{pname}={pname}")

    if params:
        doc_lines.append("")
        doc_lines.append("参数：")
        for pname, p in sig_params:
            ann_str = _render_annotation(p.annotation)
            key = key_map.get(pname) or _PAYLOAD_KEY_ALIASES.get(pname, pname)
            pdesc = _clean_pdesc(html_params.get(key) or html_params.get(pname) or "")
            if p.default is inspect.Parameter.empty:
                line = f"- {pname}（{ann_str}）：必填"
            else:
                line = f"- {pname}（{ann_str}，默认 {p.default!r}）：可选"
            if pdesc:
                line += f"。{pdesc}"
            doc_lines.append(line)

    if py_example:
        doc_lines.append("")
        doc_lines.append(f"调用示例：{py_example}")

    if req_example:
        doc_lines.append("")
        doc_lines.append("请求体示例：")
        doc_lines.append(req_example)

    if outputs:
        doc_lines.append("")
        doc_lines.append("出参：" + ", ".join(outputs))

    if fields:
        doc_lines.append("")
        doc_lines.append("返回结构（result 字段）：")
        doc_lines.append(", ".join(f"{f['field']}({f['type']})" for f in fields))

    doc_lines.append("")
    doc_lines.append("返回：BinSentry 后端的 JSON 结果（已解析为对象）。")
    doc = "\n".join(doc_lines).strip()

    return (
        f"def {final_name}({', '.join(params)}) -> Any:\n"
        f"    {_as_docstring(doc)}\n"
        f"    return _invoke(lambda: _client.{method_name}({', '.join(kwargs)}))\n"
    )

def _as_docstring(doc: str) -> str:
    return repr(doc)

def _register_tools() -> int:
    methods = _collect_methods()
    for cls, method_name, func, final_name in methods:
        src = _build_tool_source(cls, method_name, func, final_name)
        ns: Dict[str, Any] = {}
        exec(compile(src, f"<binsentry_tool:{final_name}>", "exec"), globals(), ns)
        tool_fn = ns[final_name]
        tool_fn.__name__ = final_name
        tool_fn.__qualname__ = final_name
        mcp.tool()(tool_fn)
    return len(methods)

def _coverage() -> Dict[str, int]:
    stats = {"total": 0, "usage": 0, "params": 0, "fields": 0}
    for cls, method_name, func, _ in _collect_methods():
        interface = _interface_of(func, method_name)
        info = _IFACE_INFO.get(interface, {})
        stats["total"] += 1
        if info.get("usage") or info.get("desc"):
            stats["usage"] += 1
        if any(p.get("desc") for p in info.get("params", []) or []):
            stats["params"] += 1
        if info.get("fields"):
            stats["fields"] += 1
    return stats

_TOOL_COUNT = _register_tools()
_COVERAGE = _coverage()

@mcp.tool()
def ping_backend() -> Dict[str, Any]:
    ok = _client.config.is_server_available()
    return {
        "status": "ok" if ok else "error",
        "message": f"BinSentry 后端 {'可达' if ok else '不可达'}：{_client.config.server_addr}",
    }

@mcp.tool()
def set_server(address: str, port: int = 6891) -> Dict[str, Any]:
    _client.set_server(address, port)
    return {"status": "ok", "message": f"BinSentry 后端已切换至 {_client.config.server_addr}"}

def main() -> None:
    parser = argparse.ArgumentParser(description="BinSentry MCP Server（fastmcp / HTTP transport）")
    parser.add_argument("--backend-address", default=os.environ.get("BINSENTRY_ADDRESS", "127.0.0.1"),
                        help="BinSentry 后端地址（默认 127.0.0.1）")
    parser.add_argument("--backend-port", type=int, default=int(os.environ.get("BINSENTRY_PORT", "6891")),
                        help="BinSentry 后端端口（默认 6891）")
    parser.add_argument("--api-key", default=os.environ.get("BINSENTRY_API_KEY"),
                        help="BinSentry API Key（可选）")
    parser.add_argument("--host", default=os.environ.get("MCP_HOST", "127.0.0.1"),
                        help="MCP 服务监听地址（默认 127.0.0.1）")
    parser.add_argument("--mcp-port", type=int, default=int(os.environ.get("MCP_PORT", "8000")),
                        help="MCP 服务监听端口（默认 8000）")
    args = parser.parse_args()

    global _client
    _client = _binsentry.BinSentryClient(
        address=args.backend_address, port=args.backend_port, api_key=args.api_key
    )

    print(f"[binsentry-mcp] 已注册 {_TOOL_COUNT} 个 BinSentry 工具 + 2 个运维工具"
          f"（共 {_TOOL_COUNT + 2} 个，无重名）")
    print(f"[binsentry-mcp] 接口库覆盖: 用途 {_COVERAGE['usage']}/{_COVERAGE['total']}"
          f" | 参数说明 {_COVERAGE['params']}/{_COVERAGE['total']}"
          f" | 返回结构 {_COVERAGE['fields']}/{_COVERAGE['total']}")
    print(f"[binsentry-mcp] BinSentry 后端: {_client.config.server_addr}")
    print(f"[binsentry-mcp] MCP HTTP 端点: http://{args.host}:{args.mcp_port}/mcp")
    mcp.run(transport="http", host=args.host, port=args.mcp_port)


if __name__ == "__main__":
    main()