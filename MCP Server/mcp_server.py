# -*- coding: utf-8 -*-
"""
BinSentry MCP Server（Python / FastMCP）
================================================================

将 BinSentry 远端调试 API 的**全部对外接口**（441 个，13 个 API 类）
逐一暴露为 MCP 工具，供任意 MCP 客户端（Claude Desktop / Cursor / 自研 Agent 等）调用。

设计要点
--------
1. **全量覆盖**：以 binsentry_interfaces.json（500 条接口清单）为分母，
   启动时自动内省 Python SDK 客户端（同目录 __init__.py）的每个 API 方法，
   按方法真实签名生成参数 Schema；启动后立即校验覆盖率，缺失即告警/退出。
2. **参数 Schema 真实**：工具参数名、类型、默认值取自 SDK 方法签名，
   不做二次猜测；payload 键名（如 len_ -> len）由方法源码推导，仅用于文档说明。
3. **兜底通道**：``binsentry_call`` 允许按原始接口名 + params 直接调用，
   用于覆盖清单外的新接口或调试原始报文。
4. **运维工具**：连通性探测、后端地址切换、超时调整、接口清单查询。
5. **传输方式可自由选择**：``--transport stdio|sse|http|auto``（``http`` 即
   Streamable HTTP，别名 ``streamable-http``）；SSE 默认 ``/sse``（消息端点
   ``/messages/``），HTTP 默认 ``/mcp``，路径可用 ``--mcp-path`` 或
   ``MCP_PATH`` / ``MCP_SSE_PATH`` / ``MCP_HTTP_PATH`` 覆盖；``auto`` 在终端里
   起 HTTP、被客户端以管道拉起时走 stdio。

后端约定
--------
BinSentry 后端（默认 http://127.0.0.1:6891）接受：

    POST /  {"interface": "<接口名>", "params": {...}}
    头部 X-API-Key: <密钥>

返回 {"status": "ok|error", "result": {...}, "timestamp": ...}。

用法
----
    python mcp_server.py                         # stdio 传输（客户端拉起）
    python mcp_server.py --transport http --mcp-port 8000   # Streamable HTTP → /mcp
    python mcp_server.py --transport sse  --mcp-port 8001   # SSE → /sse
    python mcp_server.py --transport auto        # 终端→HTTP，管道→stdio
    python mcp_server.py --list-transports       # 查看当前环境支持的传输与端点
    python mcp_server.py --install-deps          # 只安装 fastmcp 等依赖后退出
    python mcp_server.py --verify                # 只做接口覆盖校验并退出
    python mcp_server.py --list-tools            # 输出工具清单 JSON 并退出

依赖缺失时怎么办
----------------
启动服务（stdio/http/sse/auto）时若检测到未安装 fastmcp，会按 requirements.txt
自动执行 ``python -m pip install``，装完自动重启进程继续用所选传输启动；
``--no-auto-install`` 可关闭该行为；``--install-deps`` 可只装依赖后退出。
静态检查（--verify/--list-tools/--list-transports）不会触发安装。

环境变量（与命令行等价，命令行优先）
------------------------------------
    BINSENTRY_ADDRESS / BINSENTRY_PORT / BINSENTRY_API_KEY / BINSENTRY_TIMEOUT
    MCP_TRANSPORT / MCP_HOST / MCP_PORT / MCP_PATH / MCP_SSE_PATH / MCP_HTTP_PATH
    MCP_AUTO_INSTALL=0 关闭自动安装；pip 自身的 PIP_INDEX_URL / PIP_TRUSTED_HOST
    等变量对自动安装同样生效
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import hashlib
import importlib.util
import inspect
import json
import logging
import math
import os
import re
import sys
import subprocess
import tempfile
import time
import typing  # 供动态生成的工具注解（typing.Optional[...] 等）在 eval 时解析
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlsplit, urlunsplit

_FASTMCP_IMPORT_ERROR: Optional[str] = None
_FASTMCP_MISSING_MODULE: Optional[str] = None

try:
    from fastmcp import Context, FastMCP
    _FASTMCP_AVAILABLE = True
except (ImportError, SyntaxError) as exc:
    # 维护/CI 只需要工具清单和覆盖报告；未装 MCP 运行时时仍允许
    # --verify / --list-tools，真正启动服务前会自动安装（见 _ensure_runtime）。
    # SyntaxError 用于识别依赖包文件损坏（例如安装中断留下的半截文件）。
    _FASTMCP_AVAILABLE = False
    _FASTMCP_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"
    _FASTMCP_MISSING_MODULE = getattr(exc, "name", None)

    class _FallbackMCP:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def tool(self, *args: Any, **kwargs: Any):
            if args and callable(args[0]):
                return args[0]
            return lambda fn: fn

        def run(self, *args: Any, **kwargs: Any):
            raise RuntimeError("fastmcp 未安装，无法启动 MCP 传输")

    FastMCP = _FallbackMCP  # type: ignore[assignment]
    Context = object  # type: ignore[assignment]

try:
    from memdiff import diff_buffers
except ImportError:  # 以模块方式从其它工作目录加载时，补齐同目录搜索路径
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from memdiff import diff_buffers

# ---------------------------------------------------------------------------
# 0. 常量与日志
# ---------------------------------------------------------------------------

HERE = Path(__file__).resolve().parent
SDK_PATH = HERE / "__init__.py"
CATALOG_PATH = HERE / "binsentry_interfaces.json"

LOG = logging.getLogger("binsentry.mcp")

# 继承链上的 API 类 -> 中文能力名（与官网「13 个 API 类」口径一致）
CATEGORY_CN: Dict[str, str] = {
    "SystemApi": "系统能力",
    "LogConfigApi": "日志与配置",
    "SymbolVarApi": "符号与标注",
    "BreakPointApi": "断点体系",
    "DebugSessionApi": "调试会话",
    "RegisterThreadApi": "寄存器与线程",
    "ModulePeApi": "模块与 PE 解析",
    "MemoryApi": "内存读写",
    "DisasmXrefApi": "反汇编与交叉引用",
    "StackTraceApi": "调用栈与追踪",
    "ExecutionControlApi": "运行控制",
    "AuthApi": "鉴权",
    "ExtraApi": "扩展接口",
}

# 内部方法 / 由运维工具单独暴露的方法，不注册为接口工具
SKIP_METHODS = {"custom_post", "bind", "set_server", "stream_events"}

# Python 参数名 -> 后端 payload 键名（常规情况由源码推导，此处仅为兜底）
PAYLOAD_KEY_ALIASES = {
    "len_": "len",
    "hex_": "hex",
    "type_": "type",
    "def_": "def",
    "id_": "id",
    "max_num": "max",
    "watch_id": "id",
    "include_all": "all",
    "established_only": "establishedOnly",
}

# payload 中的信封字段，不属于接口参数
ENVELOPE_KEYS = {"interface", "params"}


# ---------------------------------------------------------------------------
# 1. 加载 SDK 客户端与接口清单
# ---------------------------------------------------------------------------


def _load_sdk() -> Any:
    """以文件方式加载同目录 Python SDK 客户端（避免包名冲突）。"""
    if not SDK_PATH.exists():
        raise SystemExit(f"[binsentry-mcp] 缺少 SDK 客户端: {SDK_PATH}")
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    spec = importlib.util.spec_from_file_location("binsentry_sdk", SDK_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit(f"[binsentry-mcp] 无法加载 SDK: {SDK_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SDK = _load_sdk()


def _load_catalog() -> Dict[str, Dict[str, Any]]:
    """接口清单：接口名 -> 说明（用途、参数含义、返回结构等）。"""
    if not CATALOG_PATH.exists():
        LOG.warning("接口清单不存在，工具描述将退化为基础信息: %s", CATALOG_PATH)
        return {}
    try:
        data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - 清单损坏不应阻塞服务启动
        LOG.warning("接口清单解析失败（%s），工具描述将退化", exc)
        return {}
    return data if isinstance(data, dict) else {}


CATALOG: Dict[str, Dict[str, Any]] = _load_catalog()


# ---------------------------------------------------------------------------
# 2. 接口名解析（AST，确定性，不依赖源码反射字符串）
# ---------------------------------------------------------------------------


def _build_interface_index() -> Dict[Tuple[str, str], str]:
    """{(类名, 方法名): 接口名}；同名方法继承覆盖时以派生类为准。"""
    tree = ast.parse(SDK_PATH.read_text(encoding="utf-8"))
    index: Dict[Tuple[str, str], str] = {}
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        for fn in node.body:
            if not isinstance(fn, ast.FunctionDef):
                continue
            for sub in ast.walk(fn):
                if not isinstance(sub, ast.Dict):
                    continue
                for key, value in zip(sub.keys, sub.values):
                    if (
                        isinstance(key, ast.Constant)
                        and key.value == "interface"
                        and isinstance(value, ast.Constant)
                        and isinstance(value.value, str)
                    ):
                        index[(node.name, fn.name)] = value.value
    return index


INTERFACE_INDEX = _build_interface_index()


def _interface_of(cls: type, method_name: str) -> str:
    """接口名；AST 缺失时回退到方法名（保证工具仍可注册）。"""
    return INTERFACE_INDEX.get((cls.__name__, method_name), method_name)


# ---------------------------------------------------------------------------
# 3. 方法收集与参数映射
# ---------------------------------------------------------------------------


def _collect_methods() -> List[Tuple[type, str, Any, str]]:
    """[(定义类, 方法名, 函数对象, 工具名)]

    按继承链由派生类到基类收集；同名方法加类名前缀去重，保证工具名全局唯一。
    """
    found: Dict[str, List[Tuple[type, str, Any]]] = {}
    order: List[str] = []

    for cls in SDK.BinSentryClient.__mro__:
        if cls is object or not cls.__module__.startswith(SDK.__name__):
            continue
        for name, value in cls.__dict__.items():
            if name.startswith("_") or name in SKIP_METHODS:
                continue
            if isinstance(value, (staticmethod, classmethod)):
                value = value.__func__
            if not callable(value):
                continue
            if name not in found:
                found[name] = []
                order.append(name)
            found[name].append((cls, name, value))

    result: List[Tuple[type, str, Any, str]] = []
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


METHODS = _collect_methods()


def _payload_key_map(func: Any) -> Dict[str, str]:
    """{Python 参数名: 后端 payload 键名}，用于生成准确的参数说明。

    覆盖 SDK 中的三种写法：
        {"interface": "X", "params": {"key": param}}
        {"key": validate_hex_address(param)}
        payload["key"] = param
    """
    try:
        source = inspect.getsource(func)
        signature = inspect.signature(func)
    except (OSError, TypeError, ValueError):
        return {}

    valid = {name for name, _ in _tool_params(signature)}

    origin: Dict[str, str] = {}
    for var, param in re.findall(r"(\w+)\s*=\s*validate_hex_address\((\w+)\)", source):
        origin[var] = param

    pair_re = re.compile(
        r'"(?P<key>\w+)"\s*:\s*(?:validate_hex_address\((?P<wrapped>\w+)\)|(?P<plain>[A-Za-z_]\w*))'
    )
    assign_re = re.compile(
        r'payload\["(?P<key>\w+)"\]\s*=\s*'
        r'(?:validate_hex_address\((?P<wrapped>\w+)\)|(?P<plain>[A-Za-z_]\w*))'
    )

    mapping: Dict[str, str] = {}
    for pattern in (pair_re, assign_re):
        for match in pattern.finditer(source):
            key = match.group("key")
            if key in ENVELOPE_KEYS:
                continue
            token = match.group("wrapped") or match.group("plain")
            param = origin.get(token, token)
            if param in valid:
                mapping.setdefault(param, key)
    # 少数参数在源码里没有直接的 payload 字面量（例如条件构造开关），
    # 用显式别名补齐，保证文档里的后端键名与工具参数一致。
    for param in valid:
        alias = PAYLOAD_KEY_ALIASES.get(param)
        if alias:
            mapping.setdefault(param, alias)
    return mapping


def _tool_params(signature: inspect.Signature) -> List[Tuple[str, inspect.Parameter]]:
    """工具暴露的参数（剔除 self 与 *args/**kwargs）。"""
    out: List[Tuple[str, inspect.Parameter]] = []
    for name, param in signature.parameters.items():
        if name == "self" or param.kind in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            continue
        out.append((name, param))
    return out


_PRIMITIVE_NAMES = {int: "int", str: "str", bool: "bool", float: "float", type(None): "None"}


def _render_annotation(annotation: Any) -> str:
    """把类型注解渲染为可 eval 的源码文本。"""
    if annotation is inspect.Parameter.empty:
        return "Any"
    if annotation in _PRIMITIVE_NAMES:
        return _PRIMITIVE_NAMES[annotation]
    try:
        return repr(annotation)
    except Exception:  # noqa: BLE001
        return "Any"


def _render_field(field: Dict[str, Any]) -> str:
    """返回字段的紧凑渲染：``name(type)``，数组附带元素字段，十六进制显式标注。"""
    typ = field.get("type", "") or ""
    if field.get("format") == "hex":
        typ = f"hex {typ}".strip()
    if field.get("itemType"):
        typ = f"{typ}<{field['itemType']}>"
    label = f"{field.get('field')}({typ})"
    items = field.get("items") or []
    if items:
        label += " {" + ", ".join(str(x) for x in items) + "}"
    return label


def _render_default(param: inspect.Parameter) -> str:
    """渲染默认值；不可安全内联的默认值省略（退化为必填，调用方显式传参）。"""
    if param.default is inspect.Parameter.empty:
        return ""
    if param.default is None or isinstance(param.default, (str, int, float, bool, bytes)):
        return f" = {param.default!r}"
    return ""


def _clean_pdesc(text: str) -> str:
    """去掉参数描述最外层的一到两层括号。"""
    value = (text or "").strip()
    for _ in range(2):
        if value.startswith("（") and value.endswith("）"):
            value = value[1:-1].strip()
        elif value.startswith("(") and value.endswith(")"):
            value = value[1:-1].strip()
        else:
            break
    return value


def _pretty_json(raw: str) -> str:
    if not raw:
        return ""
    try:
        return json.dumps(json.loads(raw), ensure_ascii=False, indent=2)
    except (json.JSONDecodeError, ValueError, TypeError):
        return raw


def _as_literal(text: str) -> str:
    """说明文本以字符串字面量嵌入生成源码（示例含反斜杠，必须转义）。"""
    return repr(text)


# ---------------------------------------------------------------------------
# 4. 客户端实例与调用封装
# ---------------------------------------------------------------------------

_client: Any = SDK.BinSentryClient(
    address=os.environ.get("BINSENTRY_ADDRESS", "127.0.0.1"),
    port=int(os.environ.get("BINSENTRY_PORT", "6891")),
    api_key=os.environ.get("BINSENTRY_API_KEY"),
)
_client.config.timeout = float(os.environ.get("BINSENTRY_TIMEOUT", "5"))


def _invoke(fn) -> Any:
    """执行 SDK 方法，把返回的 JSON 文本解析为对象；任何异常转为结构化错误。"""
    try:
        raw = fn()
    except Exception as exc:  # noqa: BLE001 - 工具层不允许异常逃逸
        LOG.exception("接口调用失败")
        return {"status": "error", "message": f"调用失败: {exc}"}
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return {"status": "ok", "raw": raw}
    return raw


# ---------------------------------------------------------------------------
# 5. 单个工具源码生成（保留真实签名，FastMCP 据此生成参数 Schema）
# ---------------------------------------------------------------------------


def _build_tool_source(cls: type, method_name: str, func: Any, tool_name: str) -> str:
    signature = inspect.signature(func)
    interface = _interface_of(cls, method_name)
    info = CATALOG.get(interface, {})

    usage = info.get("usage", "") or ""
    desc = info.get("desc", "") or ""
    category = info.get("category", "") or cls.__name__
    category_cn = info.get("category_cn", "") or CATEGORY_CN.get(category, "")
    doc_params = {p.get("name"): p.get("desc", "") for p in info.get("params", []) or []}
    py_example = info.get("py_example", "") or ""
    req_example = _pretty_json(info.get("req_example", "") or "")
    outputs = info.get("outputs", []) or []
    fields = info.get("fields", []) or []

    doc: List[str] = []
    if usage:
        doc.append(usage)
    if desc and desc != usage:
        doc.append(desc)
    cat_label = f"{category_cn}（{category}）" if category_cn else category
    doc.append(f"接口: {interface} | 分类: {cat_label} | 方法: {cls.__name__}.{method_name}")

    key_map = _payload_key_map(func)
    params = _tool_params(signature)

    if params:
        doc.append("")
        doc.append("参数：")
        for name, param in params:
            ann = _render_annotation(param.annotation)
            key = key_map.get(name) or PAYLOAD_KEY_ALIASES.get(name, name)
            pdesc = _clean_pdesc(doc_params.get(key) or doc_params.get(name) or "")
            required = param.default is inspect.Parameter.empty
            line = f"- {name}（{ann}）：必填" if required else f"- {name}（{ann}，默认 {param.default!r}）：可选"
            if pdesc:
                line += f"。{pdesc}"
            doc.append(line)

    if py_example:
        doc.extend(["", f"调用示例：{py_example}"])
    if req_example:
        doc.extend(["", "请求体示例：", req_example])
    if outputs:
        doc.extend(["", "出参：" + ", ".join(outputs)])
    if fields:
        doc.extend(["", "返回结构（result 字段）：",
                    ", ".join(_render_field(f) for f in fields)])

    doc.extend(["", "返回：BinSentry 后端 JSON 结果（已解析为对象）。"])

    args = [f"{name}: {_render_annotation(p.annotation)}{_render_default(p)}" for name, p in params]
    call_args = [f"{name}={name}" for name, _ in params]
    return (
        f"def {tool_name}({', '.join(args)}) -> Any:\n"
        f"    {_as_literal(chr(10).join(doc).strip())}\n"
        f"    return _invoke(lambda: _client.{method_name}({', '.join(call_args)}))\n"
    )


# ---------------------------------------------------------------------------
# 6. FastMCP 实例与批量注册
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "BinSentry MCP Server",
    instructions=(
        "BinSentry（远端调试 API）的 MCP 封装，覆盖其全部对外接口。"
        f"共 {len(CATALOG) or '500'} 个接口，分属 13 个 API 类："
        "系统能力、日志与配置、符号与标注、断点体系、调试会话、寄存器与线程、"
        "模块与 PE 解析、内存读写、反汇编与交叉引用、调用栈与追踪、运行控制、鉴权、扩展接口。"
        "工具名即 SDK 方法名（snake_case），工具描述内含接口名、中文用途、参数含义、"
        "请求体示例与返回结构。通用兜底工具 binsentry_call 可按原始接口名调用。"
        "所有工具均转发到 BinSentry 后端（默认 127.0.0.1:6891），返回已解析的 JSON 对象。"
    ),
)


def _register_tools() -> List[Dict[str, Any]]:
    """注册全部接口工具，返回注册清单。"""
    registry: List[Dict[str, Any]] = []
    for cls, method_name, func, tool_name in METHODS:
        source = _build_tool_source(cls, method_name, func, tool_name)
        # globals 必须是本模块字典：生成的函数体要引用 _invoke / _client（后者运行时会被重建），
        # locals 用独立字典承接函数名，避免污染模块命名空间。
        namespace: Dict[str, Any] = {}
        code = compile(source, f"<binsentry:{tool_name}>", "exec")
        exec(code, globals(), namespace)  # noqa: S102 - 源码由本模块确定性生成
        tool_fn = namespace[tool_name]
        tool_fn.__name__ = tool_name
        tool_fn.__qualname__ = tool_name
        mcp.tool()(tool_fn)
        registry.append({
            "tool": tool_name,
            "interface": _interface_of(cls, method_name),
            "category": cls.__name__,
            "class": cls.__name__,
            "method": method_name,
        })
    return registry


REGISTRY: List[Dict[str, Any]] = _register_tools()


def _coverage() -> Dict[str, Any]:
    """接口覆盖率报告（以接口清单为分母）。

    带 `via_generic_call` 的接口由 `binsentry_call` 通用入口覆盖（主要是断点属性
    的 50 条低层命令，逐条封装只会产生大量同构工具），单独列出，不算缺口。
    """
    covered = {item["interface"] for item in REGISTRY}
    expected = set(CATALOG) if CATALOG else covered
    missing_all = sorted(expected - covered)
    generic_only = sorted(x for x in missing_all if CATALOG.get(x, {}).get("via_generic_call"))
    missing = sorted(set(missing_all) - set(generic_only))
    unknown = sorted(covered - expected)

    doc_total = doc_usage = doc_params = doc_fields = 0
    param_total = param_documented = 0
    missing_param_docs: List[str] = []
    missing_fields: List[str] = []
    for item in REGISTRY:
        info = CATALOG.get(item["interface"], {})
        doc_total += 1
        if info.get("usage") or info.get("desc"):
            doc_usage += 1
        params = info.get("params", []) or []
        param_total += len(params)
        documented = [p for p in params if p.get("desc")]
        param_documented += len(documented)
        # 一条接口的全部参数都有说明才算“参数说明完整”；无参数接口视为完整
        if len(documented) == len(params):
            doc_params += 1
        else:
            missing_param_docs.append(item["interface"])
        if info.get("fields"):
            doc_fields += 1
        else:
            missing_fields.append(item["interface"])

    return {
        "interfaces": len(expected),
        "tools": len(REGISTRY),
        "missing": missing,
        "generic_only": generic_only,
        "unknown": unknown,
        "doc_usage": doc_usage,
        "doc_params": doc_params,
        "doc_fields": doc_fields,
        "doc_total": doc_total,
        "param_total": param_total,
        "param_documented": param_documented,
        "missing_param_docs": sorted(missing_param_docs),
        "missing_fields": sorted(missing_fields),
    }


COVERAGE = _coverage()


# ---------------------------------------------------------------------------
# 7. 运维工具
# ---------------------------------------------------------------------------


@mcp.tool()
def binsentry_ping() -> Dict[str, Any]:
    """探测 BinSentry 后端是否可达（仅 TCP 连通性，不发起接口调用）。"""
    ok = _client.config.is_server_available()
    return {
        "status": "ok" if ok else "error",
        "reachable": ok,
        "backend": _client.config.server_addr,
        "message": f"BinSentry 后端{'可达' if ok else '不可达'}：{_client.config.server_addr}",
    }


@mcp.tool()
def binsentry_set_server(address: str, port: int = 6891, api_key: Optional[str] = None) -> Dict[str, Any]:
    """运行时切换 BinSentry 后端地址（可同时更新 API Key）。

    Args:
        address: 后端主机，如 127.0.0.1
        port: 后端端口，默认 6891
        api_key: 可选，新的 X-API-Key
    """
    host = (address or "").strip()
    if not host:
        return {"status": "error", "message": "address 不能为空"}
    try:
        port_num = int(port)
    except (TypeError, ValueError):
        return {"status": "error", "message": "port 必须是 1-65535 的整数"}
    if not (1 <= port_num <= 65535):
        return {"status": "error", "message": "port 必须在 1-65535 范围内"}
    _client.set_server(host, port_num)
    if api_key:
        _client.config.set_api_key(api_key)
    return {"status": "ok", "backend": _client.config.server_addr}


@mcp.tool()
def binsentry_set_timeout(seconds: float) -> Dict[str, Any]:
    """调整后端请求超时（秒）。耗时接口（全内存搜索、模块分析等）可临时调大。

    Args:
        seconds: 超时秒数，须大于 0
    """
    try:
        seconds_value = float(seconds)
    except (TypeError, ValueError):
        return {"status": "error", "message": "seconds 必须是大于 0 的数值"}
    if not math.isfinite(seconds_value) or seconds_value <= 0:
        return {"status": "error", "message": "seconds 必须大于 0"}
    _client.config.timeout = seconds_value
    return {"status": "ok", "timeout": _client.config.timeout}


@mcp.tool()
def binsentry_list_interfaces(
    category: Optional[str] = None,
    keyword: Optional[str] = None,
    with_detail: bool = False,
) -> Dict[str, Any]:
    """查询接口清单：按 API 类或关键字筛选，返回接口名与所属方法。

    Args:
        category: 可选，API 类名（如 MemoryApi）或中文能力名（如 内存读写）
        keyword: 可选，在接口名 / 用途 / 方法名中做不区分大小写的包含匹配
        with_detail: 是否附带参数、出参与返回字段等详细说明（参数含类型/必填/语义，
                    返回字段含类型、hex 标注与数组元素字段）
    """
    rows: List[Dict[str, Any]] = []
    by_iface = {item["interface"]: item for item in REGISTRY}
    for iface, info in CATALOG.items():
        cat = info.get("category", "")
        cat_cn = info.get("category_cn", "") or CATEGORY_CN.get(cat, "")
        if category and category not in (cat, cat_cn):
            continue
        haystack = f"{iface} {info.get('usage', '')} {info.get('desc', '')} {by_iface.get(iface, {}).get('tool', '')}".lower()
        if keyword and keyword.lower() not in haystack:
            continue
        row = {
            "interface": iface,
            "tool": by_iface.get(iface, {}).get("tool"),
            "method": by_iface.get(iface, {}).get("method"),
            "category": cat,
            "category_cn": cat_cn,
            "usage": info.get("usage", ""),
        }
        if with_detail:
            row.update({
                "params": [p.get("name") for p in info.get("params", []) or []],
                "paramMeta": [
                    {
                        "name": p.get("name"),
                        "type": p.get("type"),
                        "required": p.get("required"),
                        "desc": p.get("desc"),
                    }
                    for p in info.get("params", []) or []
                ],
                "outputs": info.get("outputs", []) or [],
                "fields": [f.get("field") for f in info.get("fields", []) or []],
                "fieldMeta": [
                    {
                        "field": f.get("field"),
                        "type": f.get("type"),
                        "format": f.get("format"),
                        "items": f.get("items"),
                    }
                    for f in info.get("fields", []) or []
                ],
            })
        rows.append(row)

    return {"status": "ok", "count": len(rows), "backend": _client.config.server_addr, "interfaces": rows}


@mcp.tool()
def binsentry_call(interface: str, params: Optional[Dict[str, Any]] = None,
                   timeout_seconds: Optional[float] = None) -> Any:
    """按原始接口名直接调用 BinSentry（兜底通道，用于清单外接口或调试原始报文）。

    Args:
        interface: 接口名，如 SystemInfo / ReadMemoryValue
        params: 接口参数对象，键名与 BinSentry 协议一致（可为空）
        timeout_seconds: 可选，本次调用的超时覆盖（秒）
    """
    name = (interface or "").strip()
    if not name:
        return {"status": "error", "message": "interface 不能为空"}
    if CATALOG and name not in CATALOG:
        return {
            "status": "error",
            "message": f"未知接口: {name}（共 {len(CATALOG)} 个接口，可用 binsentry_list_interfaces 查询）",
        }
    payload = {"interface": name, "params": params or {}}
    try:
        raw = _client.custom_post(payload, timeout=timeout_seconds)
    except TypeError:  # 兼容不支持 timeout 参数的旧客户端
        raw = _client.custom_post(payload)
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "message": f"调用失败: {exc}"}
    return _invoke(lambda: raw)



# ---------------------------------------------------------------------------
# 7.5 工作流门面：把常用多步调试收敛为任务级工具（低层接口仍全部保留）
# ---------------------------------------------------------------------------


def _wf(res: Any) -> Dict[str, Any]:
    """统一取出后端 result；异常对象原样返回，便于工作流透传。"""
    if isinstance(res, dict) and isinstance(res.get("result"), dict):
        return res["result"]
    return res if isinstance(res, dict) else {"state": False, "message": str(res)}


def _wf_ok(res: Any) -> bool:
    return _wf(res).get("state") is True


def _wf_error(res: Any) -> Dict[str, Any]:
    body = _wf(res)
    return {"status": "error", "message": body.get("message") or "operation failed", "detail": res}


WORKFLOW_TOOL_NAMES = [
    "binsentry_start_debug", "binsentry_attach_debug", "binsentry_stop_debug",
    "binsentry_session_status",
    "binsentry_inspect_address", "binsentry_resolve_symbol", "binsentry_read_typed",
    "binsentry_memory_snapshot", "binsentry_memory_diff",
    "binsentry_crash_triage", "binsentry_breakpoint_and_wait", "binsentry_run_to",
    "binsentry_load_pdb_and_types",
]

LEASE_EVENT_TOOL_NAMES = [
    "binsentry_event_subscribe", "binsentry_event_poll", "binsentry_wait_event",
    "binsentry_event_stream", "binsentry_event_unsubscribe", "binsentry_lease_acquire",
    "binsentry_lease_renew", "binsentry_lease_release", "binsentry_lease_status",
]


def _session_active() -> bool:
    return _wf(_invoke(lambda: _client.status(brief=True))).get("sessionActive") is True


def _wait_stop_ms(timeout_seconds: int) -> Any:
    """WaitStop 的 timeout 是毫秒；HTTP 客户端超时必须比它更长，否则会先超时。"""
    ms = max(1000, int(timeout_seconds) * 1000)
    http_timeout = max(10, ms // 1000 + 5)
    return _invoke(lambda: _client.custom_post(
        {"interface": "WaitStop", "params": {"timeout": ms}}, timeout=http_timeout))


def _wf_stopped(event: Any) -> bool:
    """WaitStop 的 state=true 只表示命令执行成功；超时时 stopped=false/reason=timeout。"""
    body = _wf(event)
    return body.get("state") is True and body.get("stopped") is not False and body.get("reason") != "timeout"


def _module_brief(limit: int = 12) -> Dict[str, Any]:
    res = _wf(_invoke(lambda: _client.modules()))
    mods = res.get("modules", []) if isinstance(res.get("modules"), list) else []
    names = [m.get("name") for m in mods[:limit] if isinstance(m, dict)]
    return {"count": len(mods), "names": names}


@mcp.tool()
def binsentry_start_debug(path: str, args: str = "", cwd: str = "",
                          timeout_seconds: int = 20) -> Dict[str, Any]:
    """启动并等待目标停在初始断点：自动清理旧会话 -> Debug -> WaitStop -> Status。

    Args:
        path: 目标 EXE 绝对路径
        args: 命令行参数（可选）
        cwd: 工作目录（可选）
        timeout_seconds: 等待初始停顿的秒数，默认 20
    """
    if _session_active():
        _invoke(lambda: _client.stop())
    start = _invoke(lambda: _client.debug(path, args, cwd))
    if not _wf_ok(start):
        return _wf_error(start)
    event = _wait_stop_ms(timeout_seconds)
    status = _invoke(lambda: _client.status(brief=True))
    return {
        "status": "ok" if _wf_stopped(event) else "warning",
        "pid": _wf(status).get("pid"),
        "stopped": _wf(status).get("stopped"),
        "start": start,
        "wait": event,
        "session": status,
        "message": "目标已启动并停顿" if _wf_stopped(event) else "目标已启动，但在超时内未收到停顿事件",
    }


@mcp.tool()
def binsentry_attach_debug(pid: int, timeout_seconds: int = 20) -> Dict[str, Any]:
    """附加到现有进程并等待首次停顿：清理旧会话 -> Attach -> WaitStop -> Status。

    Args:
        pid: 目标进程 ID
        timeout_seconds: 等待首次停顿的秒数，默认 20
    """
    if _session_active():
        _invoke(lambda: _client.stop())
    attach = _invoke(lambda: _client.attach(pid))
    if not _wf_ok(attach):
        return _wf_error(attach)
    event = _wait_stop_ms(timeout_seconds)
    status = _invoke(lambda: _client.status(brief=True))
    return {"status": "ok" if _wf_stopped(event) else "warning",
            "pid": pid, "attach": attach, "wait": event, "session": status}


@mcp.tool()
def binsentry_stop_debug(mode: str = "detach") -> Dict[str, Any]:
    """结束当前调试会话：detach 保留目标进程，terminate 终止目标，force 强制关闭。

    与 `binsentry_start_debug` / `binsentry_attach_debug` 配对使用，避免调用方
    必须记住底层 Detach/Stop/ForceClose 的差异。

    Args:
        mode: detach（默认，目标继续运行）| terminate（终止目标进程）| force（强制关闭）
    """
    mode_cn = (mode or "").strip().lower()
    actions = {
        "detach": ("Detach", lambda: _client.detach()),
        "terminate": ("Stop", lambda: _client.stop()),
        "force": ("ForceClose", lambda: _client.force_close()),
    }
    if mode_cn not in actions:
        return {"status": "error", "message": f"mode 必须是 {', '.join(actions)}"}
    if not _session_active():
        return {"status": "warning", "message": "当前没有调试会话", "mode": mode_cn}
    interface, call = actions[mode_cn]
    raw = _invoke(call)
    body = _wf(raw)
    after = _invoke(lambda: _client.status(brief=True))
    return {
        "status": "ok" if body.get("state") is True else "error",
        "interface": interface,
        "mode": mode_cn,
        "active": _wf(after).get("sessionActive") is True,
        "detail": raw,
        "session": after,
        "message": body.get("message") or ("调试会话已结束" if body.get("state") else "结束会话失败"),
    }


@mcp.tool()
def binsentry_session_status(include_modules: bool = True, module_limit: int = 12) -> Dict[str, Any]:
    """会话总览：状态 + 线程列表 + 模块数量/名称摘要。

    `session` 为 Status 原始结果，含 `detachPending` / `lastDetachMs`
    等分离观测字段。

    Args:
        include_modules: 是否附带模块摘要，默认 True
        module_limit: 模块名称最多返回几个，默认 12
    """
    status = _invoke(lambda: _client.status(brief=True))
    threads = _invoke(lambda: _client.threads())
    active = _wf(status).get("sessionActive") is True
    payload: Dict[str, Any] = {"status": "ok" if active else "warning",
                               "active": active, "session": status, "threads": threads}
    if not active:
        payload["message"] = "当前没有调试会话"
    if include_modules:
        payload["modules"] = _module_brief(max(1, module_limit))
    return payload


@mcp.tool()
def binsentry_inspect_address(address: str, count: int = 6, read_size: int = 8) -> Dict[str, Any]:
    """查看一个地址：符号、地址信息、反汇编、原始内存、页权限。

    Args:
        address: 地址、PDB 符号名或 module:offset（如 0x401000、main、app.exe:0x1000）
        count: 反汇编指令条数，默认 6
        read_size: 读取原始字节数（1/2/4/8），默认 8
    """
    addr = _wf_address(address)
    parts = {
        "symbol": _invoke(lambda: _client.symbol(addr)),
        "addr_info": _invoke(lambda: _client.get_addr_info(addr)),
        "disassembly": _invoke(lambda: _client.disassemble_at(addr, max(1, count))),
        "memory": _invoke(lambda: _client.read_memory_value(addr, read_size)),
        "page_rights": _invoke(lambda: _client.get_page_rights(addr)),
    }
    failed = [k for k, v in parts.items() if not _wf_ok(v)]
    return {
        "status": "error" if len(failed) >= 3 else ("warning" if failed else "ok"),
        "address": addr,
        "failed_parts": failed,
        **parts,
    }


def _wf_find_symbol(expr: str) -> Optional[Dict[str, Any]]:
    """ExprEvaluator 无法解析时，退回 PDB 符号表做精确名匹配。

    支持 `name`、`module!name` 两种写法；模块名只用于筛选同名符号。
    """
    module_filter = ""
    name = expr.strip()
    if "!" in name:
        module_filter, name = name.split("!", 1)
    if not name:
        return None
    enum = _invoke(lambda: _client.enum_symbols(name, 100))
    if not _wf_ok(enum):
        return None
    symbols = _wf(enum).get("symbols") or []
    candidates = [s for s in symbols if str(s.get("name", "")).lower() == name.lower()]
    if not candidates:
        return None
    chosen = candidates[0]
    if module_filter:
        chosen = None
        for cand in candidates:
            info = _wf(_invoke(lambda c=cand: _client.get_symbol_info(c.get("address"))))
            if module_filter.lower() in str(info.get("module", "")).lower():
                chosen = cand
                break
        if not chosen:
            return None
    addr = chosen.get("address")
    return {
        "status": "success",
        "result": {
            "command": "EnumSymbols",
            "state": True,
            "name": chosen.get("name"),
            "address": addr,
            "addressHex": hex(addr) if isinstance(addr, int) else addr,
            "size": chosen.get("size", 0),
            "message": "Symbol resolved (PDB symbol table)",
        },
        "source": "enum_symbols",
    }


@mcp.tool()
def binsentry_resolve_symbol(expr: str) -> Dict[str, Any]:
    """按符号/表达式取地址，并附地址所属模块与页信息。

    Args:
        expr: 符号名、PDB 全局变量（如 g_node）、module:offset（如 app.exe:0x1000）或地址表达式
    """
    sym = _invoke(lambda: _client.symbol(expr))
    body = _wf(sym)
    if body.get("state") is not True:
        fallback = _wf_find_symbol(expr)
        if fallback:
            sym = fallback
            body = _wf(sym)
    addr = body.get("address") or body.get("value") or body.get("addressHex")
    payload: Dict[str, Any] = {"status": "ok" if body.get("state") is True else "error",
                               "expr": expr, "symbol": sym}
    if addr:
        payload["addr_info"] = _invoke(lambda: _client.get_addr_info(addr))
    return payload


_MEMORY_MAX_BYTES = 64 * 1024 * 1024


def _local_path(path: str) -> str:
    """把用户给的路径规范成 MCP 主机上的绝对路径（支持 ~ 与 %TEMP% 等变量）。"""
    return os.path.abspath(os.path.expandvars(os.path.expanduser(str(path))))


def _memory_timeout(size: int, timeout_seconds: float) -> float:
    """DumpMemory 的 HTTP 超时：未显式指定时按镜像大小自动放大，避免大块转储误超时。"""
    if timeout_seconds and float(timeout_seconds) > 0:
        return float(timeout_seconds)
    return float(max(15, 10 + int(size) // (8 * 1024 * 1024)))


def _sha256_file(path: str) -> str:
    sha = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def _publish_no_overwrite(temp_path: str, dest_path: str) -> None:
    """把同目录临时文件发布为 dest_path，且绝不覆盖已存在的目标。

    仅用 os.path.exists 预检再 os.replace 存在 TOCTOU：两个并发快照可能都通过
    预检，后一个静默覆盖前一个。这里依赖文件系统的原子零覆盖语义：
    Windows 的 os.rename 在目标已存在时返回 FileExistsError；POSIX 的 rename
    会覆盖，因此改用同卷硬链接发布。两种路径都不需要用户态“先查后写”。
    """
    if os.name == "nt":
        os.rename(temp_path, dest_path)
        return
    os.link(temp_path, dest_path)
    try:
        os.unlink(temp_path)
    except OSError:
        pass


def _probe_memory_range(addr: str, size: int) -> Optional[Dict[str, Any]]:
    """在 DumpMemory 前验证首/尾字节可读。

    TitanEngine 的 DumpMemory 对不可读地址可能仍写出全零文件并返回成功；
    不先探测会把“无效地址”伪装成合法快照，后续差分全是假差异。
    """
    try:
        base = _addr_to_int(addr)
    except ValueError as exc:
        return {"status": "error", "message": str(exc), "address": addr}
    points = [base] if size <= 1 else [base, base + int(size) - 1]
    for point in points:
        raw = _invoke(lambda p=point: _client.read_memory_value(hex(p), 1))
        if not _wf_ok(raw):
            return {"status": "error",
                    "message": f"地址 {hex(point)} 不可读，拒绝生成/比较快照",
                    "address": addr, "probe": raw}
    return None


def _addr_to_int(value: Union[int, str]) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        return int(text, 0)
    except ValueError:
        resolved = _wf_find_symbol(text)
        if resolved:
            body = _wf(resolved)
            addr = body.get("address")
            if addr is None:
                addr = body.get("addressHex")
            if addr is not None:
                return int(str(addr), 0)
    raise ValueError(f"无法解析地址: {value}")


def _wf_address(value: Union[int, str]) -> str:
    """把地址/符号统一成后端可接受的地址字符串。"""
    if isinstance(value, int):
        return hex(value)
    text = str(value).strip()
    try:
        int(text, 0)
        return text
    except ValueError:
        pass
    found = _wf_find_symbol(text)
    if found:
        body = _wf(found)
        addr = body.get("addressHex") or body.get("address")
        if addr is not None:
            return str(addr)
    return text


@mcp.tool()
def binsentry_read_typed(name: str, address: str, depth: int = 0) -> Dict[str, Any]:
    """按类型读取内存：同时返回类型布局和该地址的类型化字段值。

    Args:
        name: 类型名（手工 AddType 或 LoadPDB 自动导入均可）
        address: 结构体/联合体实例地址或 PDB 符号名
        depth: 嵌套展开深度，0 表示默认
    """
    addr = _wf_address(address)
    info = _invoke(lambda: _client.get_type_info(name))
    if not _wf_ok(info):
        return _wf_error(info)
    data = _invoke(lambda: _client.get_type_data(name, addr, depth))
    return {"status": "ok" if _wf(data).get("state") is True else "error",
            "name": name, "address": addr, "type": info, "data": data}


@mcp.tool()
def binsentry_memory_snapshot(
    address: str,
    size: int,
    path: str,
    write_metadata: bool = True,
    overwrite: bool = False,
    timeout_seconds: float = 0,
) -> Dict[str, Any]:
    """把目标进程的一段内存落盘为快照，并可选写同名 .meta.json。

    这是 `DumpMemory` 的任务级封装：快照文件可用于后续
    `binsentry_memory_diff`，适合脱壳前后、打补丁前后做字节级对照。
    落盘采用同目录临时文件 + 原子发布；转储失败不会破坏已有快照，默认模式也不会
    覆盖并发创建的快照。

    Args:
        address: 起始地址或符号名
        size: 字节数，1 .. 64MB
        path: 服务端可写的绝对路径（MCP 与 BinSentry 通常在同一台机器）
        write_metadata: 是否写 `<path>.meta.json`（地址/大小/SHA-256/时间）
        overwrite: 目标已存在时是否覆盖；默认 False，防止误删旧快照
        timeout_seconds: HTTP 超时覆盖，0 表示按大小自动计算
    """
    if size < 1 or size > _MEMORY_MAX_BYTES:
        return {"status": "error", "message": f"size 必须在 1..{_MEMORY_MAX_BYTES} 之间"}
    path_abs = _local_path(path)
    meta_path = path_abs + ".meta.json"
    if os.path.isdir(path_abs):
        return {"status": "error", "message": f"快照路径是目录: {path_abs}"}
    if os.path.exists(path_abs) and not overwrite:
        return {"status": "error",
                "message": f"快照已存在: {path_abs}；如需覆盖请传 overwrite=True",
                "path": path_abs}
    parent = os.path.dirname(path_abs)
    if not os.path.isdir(parent):
        return {"status": "error", "message": f"父目录不存在: {parent}"}

    addr = _wf_address(address)
    probe = _probe_memory_range(addr, int(size))
    if probe:
        probe["path"] = path_abs
        return probe
    try:
        fd, tmp_path = tempfile.mkstemp(prefix=".binsentry_snapshot_", suffix=".part", dir=parent)
        os.close(fd)
        os.unlink(tmp_path)  # 让 DumpMemory 自己创建，避免“文件已存在”失败
    except OSError as exc:
        return {"status": "error", "message": f"无法创建临时快照: {exc}", "path": path_abs}

    try:
        payload = {"interface": "DumpMemory",
                   "params": {"address": addr, "size": int(size), "path": tmp_path}}
        raw = _invoke(lambda: _client.custom_post(
            payload, timeout=_memory_timeout(int(size), timeout_seconds)))
        body = _wf(raw)
        if body.get("state") is not True:
            return {"status": "error", "message": body.get("message") or "DumpMemory failed",
                    "detail": raw, "path": path_abs}
        if not os.path.isfile(tmp_path):
            return {"status": "error", "message": "后端返回成功但临时快照不存在",
                    "path": path_abs, "detail": raw}
        actual = os.path.getsize(tmp_path)
        if actual != int(size):
            return {"status": "error",
                    "message": f"快照实际大小 {actual} 与请求 {size} 不一致（可能越过内存区域边界）",
                    "path": path_abs, "requestedSize": int(size), "actualSize": actual}
        sha = _sha256_file(tmp_path)
        meta = {
            "path": path_abs,
            "address": addr,
            "size": int(size),
            "actualSize": actual,
            "sha256": sha,
            "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        meta_tmp = ""
        if write_metadata:
            try:
                fd, meta_tmp = tempfile.mkstemp(prefix=".binsentry_meta_", suffix=".part", dir=parent)
                os.close(fd)
                with open(meta_tmp, "w", encoding="utf-8") as fh:
                    json.dump(meta, fh, ensure_ascii=False, indent=2)
            except OSError as exc:
                try:
                    if meta_tmp and os.path.exists(meta_tmp):
                        os.unlink(meta_tmp)
                except OSError:
                    pass
                return {"status": "error", "message": f"写入元数据临时文件失败: {exc}",
                        "path": path_abs, "snapshotWritten": False}
        try:
            if overwrite:
                os.replace(tmp_path, path_abs)
            else:
                _publish_no_overwrite(tmp_path, path_abs)
        except FileExistsError:
            try:
                if meta_tmp and os.path.exists(meta_tmp):
                    os.unlink(meta_tmp)
            except OSError:
                pass
            return {"status": "error",
                    "message": f"快照已存在（并发创建）: {path_abs}；如需覆盖请传 overwrite=True",
                    "path": path_abs, "snapshotWritten": False}
        except OSError as exc:
            try:
                if meta_tmp and os.path.exists(meta_tmp):
                    os.unlink(meta_tmp)
            except OSError:
                pass
            return {"status": "error", "message": f"快照原子发布失败: {exc}",
                    "path": path_abs, "snapshotWritten": False}
        if write_metadata:
            try:
                if overwrite:
                    os.replace(meta_tmp, meta_path)
                else:
                    _publish_no_overwrite(meta_tmp, meta_path)
            except FileExistsError:
                try:
                    if os.path.exists(meta_tmp):
                        os.unlink(meta_tmp)
                    if os.path.exists(path_abs):
                        os.unlink(path_abs)  # 保留无元数据的新快照没有意义，回滚本次发布
                except OSError:
                    pass
                return {"status": "error",
                        "message": f"元数据已存在（并发创建）: {meta_path}；已回滚本次快照",
                        "path": path_abs, "snapshotWritten": False}
            except OSError as exc:
                try:
                    if os.path.exists(meta_tmp):
                        os.unlink(meta_tmp)
                    if os.path.exists(meta_path):
                        os.unlink(meta_path)  # 旧元数据已与新快照不匹配
                except OSError:
                    pass
                return {"status": "error", "message": f"快照已写入，但元数据发布失败: {exc}",
                        "path": path_abs, "snapshotWritten": True}
        else:
            old_meta = path_abs + ".meta.json"
            if os.path.exists(old_meta):
                try:
                    os.unlink(old_meta)
                except OSError as exc:
                    return {"status": "error",
                            "message": f"快照已写入，但旧元数据删除失败: {exc}",
                            "path": path_abs, "snapshotWritten": True}
            meta_path = ""
    finally:
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except OSError:
            pass

    return {"status": "ok", "state": True, "message": "Memory snapshot saved",
            "metadataPath": meta_path, "metadataStatus": "verified" if write_metadata else "absent",
            "atomic": True, **meta}


@mcp.tool()
def binsentry_memory_diff(
    address: str,
    snapshot_path: str,
    size: int = 0,
    max_ranges: int = 64,
    max_hex_bytes: int = 32,
    save_current_path: str = "",
    verify_metadata: bool = True,
    timeout_seconds: float = 0,
) -> Dict[str, Any]:
    """把当前内存与磁盘快照做字节级对比，返回合并后的差异区间。

    典型用法：先用 `binsentry_memory_snapshot` 保存“脱壳前/补丁前”的镜像，
    运行目标后再用本工具对比同一地址；结果含差异字节数、比例、区间偏移、
    新旧字节摘要和 SHA-256，适合判断是否真的完成解密/还原。

    Args:
        address: 起始地址或符号名（应与生成快照时一致）
        snapshot_path: `binsentry_memory_snapshot` 生成的文件
        size: 对比字节数；0 表示取快照文件长度，最大 64MB
        max_ranges: 最多返回多少个差异区间（1..4096）
        max_hex_bytes: 每个区间最多展示多少字节；0 表示不展示十六进制摘要
        save_current_path: 可选，把当前内存另存到该路径；留空则使用临时文件并删除
        verify_metadata: 是否校验同名 `.meta.json` 的地址/大小/哈希（默认 True）
        timeout_seconds: HTTP 超时覆盖，0 表示按对比大小自动计算
    """
    snap_abs = _local_path(snapshot_path)
    if not os.path.isfile(snap_abs):
        return {"status": "error", "message": f"快照文件不存在: {snap_abs}"}
    snap_size = os.path.getsize(snap_abs)
    if snap_size < 1 or snap_size > _MEMORY_MAX_BYTES:
        return {"status": "error", "message": f"快照大小非法: {snap_size}"}
    if size and int(size) != snap_size:
        return {"status": "error",
                "message": f"size={size} 与快照文件大小 {snap_size} 不一致；请传 0 或使用相同大小"}
    try:
        max_ranges_i = int(max_ranges)
        max_hex_i = int(max_hex_bytes)
    except (TypeError, ValueError):
        return {"status": "error", "message": "max_ranges/max_hex_bytes 必须是整数"}
    if not 1 <= max_ranges_i <= 4096:
        return {"status": "error", "message": "max_ranges 必须在 1..4096 之间"}
    if not 0 <= max_hex_i <= 4096:
        return {"status": "error", "message": "max_hex_bytes 必须在 0..4096 之间"}
    compare_size = int(size) if size else snap_size

    addr = _wf_address(address)
    try:
        base = _addr_to_int(addr)
    except ValueError as exc:
        return {"status": "error", "message": str(exc), "address": addr}

    metadata: Dict[str, Any] = {}
    metadata_status = "disabled" if not verify_metadata else "missing"
    metadata_verified = False
    metadata_warning = ""
    meta_path = snap_abs + ".meta.json"
    if verify_metadata and os.path.isfile(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as fh:
                metadata = json.load(fh)
        except (OSError, ValueError) as exc:
            return {"status": "error", "message": f"快照元数据不可读: {exc}", "metadataPath": meta_path}
        if not isinstance(metadata, dict):
            return {"status": "error", "message": "快照元数据不是 JSON 对象", "metadataPath": meta_path}
        checked = 0
        missing = []
        meta_size = metadata.get("actualSize", metadata.get("size"))
        if meta_size is None:
            missing.append("size")
        else:
            try:
                meta_size_i = int(meta_size)
            except (TypeError, ValueError):
                return {"status": "error", "message": f"快照元数据大小非法: {meta_size!r}",
                        "metadataPath": meta_path}
            if meta_size_i != snap_size:
                return {"status": "error",
                        "message": f"快照元数据大小 {meta_size_i} 与文件 {snap_size} 不一致",
                        "metadataPath": meta_path}
            checked += 1
        meta_sha = str(metadata.get("sha256") or "").strip()
        if not meta_sha:
            missing.append("sha256")
        else:
            if meta_sha.lower() != _sha256_file(snap_abs):
                return {"status": "error", "message": "快照 SHA-256 与元数据不一致，文件可能已被替换",
                        "metadataPath": meta_path}
            checked += 1
        meta_addr = metadata.get("address")
        if meta_addr is None:
            missing.append("address")
        else:
            try:
                meta_int = _addr_to_int(meta_addr)
            except ValueError:
                return {"status": "error", "message": f"快照元数据地址无法解析: {meta_addr!r}",
                        "metadataPath": meta_path}
            if meta_int != base:
                return {"status": "error",
                        "message": f"比较地址 {hex(base)} 与快照元数据地址 {hex(meta_int)} 不一致",
                        "metadataPath": meta_path}
            checked += 1
        metadata_verified = checked == 3
        metadata_status = "verified" if metadata_verified else "incomplete"
        if not metadata_verified:
            metadata_warning = "快照元数据缺少 " + "/".join(missing) + "，本次仅按字节比较"

    probe = _probe_memory_range(addr, compare_size)
    if probe:
        return probe

    current_path = _local_path(save_current_path) if save_current_path else ""
    cleanup = False
    if not current_path:
        fd, current_path = tempfile.mkstemp(prefix="binsentry_diff_", suffix=".bin")
        os.close(fd)
        os.unlink(current_path)
        cleanup = True
    try:
        payload = {"interface": "DumpMemory",
                   "params": {"address": addr, "size": compare_size, "path": current_path}}
        raw = _invoke(lambda: _client.custom_post(
            payload, timeout=_memory_timeout(compare_size, timeout_seconds)))
        body = _wf(raw)
        if body.get("state") is not True:
            return {"status": "error", "message": body.get("message") or "DumpMemory failed", "detail": raw}
        if not os.path.isfile(current_path):
            return {"status": "error", "message": "当前内存转储文件不存在", "path": current_path}

        with open(snap_abs, "rb") as fh:
            old = fh.read()
        with open(current_path, "rb") as fh:
            new = fh.read()
        result = diff_buffers(old, new, max_ranges=max_ranges_i, max_hex_bytes=max_hex_i)
        for item in result.get("ranges", []):
            item["address"] = base + int(item.get("offset", 0))
            item["addressHex"] = hex(item["address"])
        result.update({
            "status": "ok",
            "state": True,
            "message": "Memory diff completed",
            "snapshotPath": snap_abs,
            "currentPath": current_path if save_current_path else "",
            "oldSha256": _sha256_file(snap_abs),
            "newSha256": _sha256_file(current_path),
            "address": addr,
            "metadataPath": meta_path if os.path.isfile(meta_path) else "",
            "metadataStatus": metadata_status,
            "metadataVerified": metadata_verified,
        })
        if metadata_warning:
            result["metadataWarning"] = metadata_warning
        return result
    finally:
        if cleanup:
            try:
                os.unlink(current_path)
            except OSError:
                pass


@mcp.tool()
def binsentry_crash_triage(address: str = "", timeout_seconds: int = 0) -> Dict[str, Any]:
    """停机现场取证：状态、寄存器、调用栈、SEH、模块摘要、故障地址反汇编。

    Args:
        address: 故障地址；留空时自动取寄存器 eip/rip/cip
        timeout_seconds: 大于 0 时先等待停顿（秒），默认 0 表示当前已停顿
    """
    wait = None
    if timeout_seconds > 0:
        wait = _wait_stop_ms(timeout_seconds)
    status = _invoke(lambda: _client.status(brief=True))
    stopped = _wf(status).get("stopped") is True
    reg = _invoke(lambda: _client.register())
    regs = _wf(reg).get("registers", {}) if isinstance(_wf(reg).get("registers"), dict) else {}
    rip = _wf_address(address) if address else (regs.get("ripHex") or regs.get("eipHex") or regs.get("cipHex") or regs.get("ipHex"))
    stack = _invoke(lambda: _client.stack(12)) if stopped else None
    seh = _invoke(lambda: _client.seh_list()) if stopped else None
    payload: Dict[str, Any] = {
        "status": "ok" if stopped and _wf_ok(reg) else "warning",
        "wait": wait,
        "session": status,
        "registers": reg,
        "stack": stack,
        "seh": seh,
        "modules": _module_brief(12),
        "fault_address": rip,
    }
    if not stopped:
        payload["note"] = "目标仍在运行；调用 Pause 或设置 timeout_seconds 等待停顿后再取栈和 SEH"
    if rip:
        payload["disassembly"] = _invoke(lambda: _client.disassemble_at(rip, 8))
        payload["symbol"] = _invoke(lambda: _client.symbol(rip))
        payload["page_rights"] = _invoke(lambda: _client.get_page_rights(rip))
    return payload


@mcp.tool()
def binsentry_breakpoint_and_wait(address: str, timeout_seconds: int = 20,
                                  temporary: bool = False) -> Dict[str, Any]:
    """下软件断点并继续运行，等待命中后返回断点信息与会话状态。

    Args:
        address: 断点地址/符号
        timeout_seconds: 等待命中的秒数，默认 20
        temporary: 是否一次性断点，默认 False
    """
    # SetBreakPoint 的临时断点参数在低层用 temp，SDK 未单独封装时走通用入口
    addr = _wf_address(address)
    params: Dict[str, Any] = {"address": addr}
    if temporary:
        params["temp"] = 1
    bp = _invoke(lambda: _client.custom_post({"interface": "SetBreakPoint", "params": params}))
    if not _wf_ok(bp):
        return _wf_error(bp)
    run = _invoke(lambda: _client.run())
    if not _wf_ok(run):
        return _wf_error(run)
    event = _wait_stop_ms(timeout_seconds)
    # GetBreakpointInfo 只管硬件断点；软件断点清单要查 ShowBreakPoint
    shown = _invoke(lambda: _client.show_breakpoint())
    all_bps = _wf(shown).get("breakpoints") or []
    matched = []
    for b in all_bps:
        if not isinstance(b, dict):
            continue
        try:
            same = int(str(b.get("addressHex", "")), 16) == int(str(addr), 16)
        except ValueError:
            same = str(b.get("addressHex", "")).lower() == str(addr).lower()
        if same:
            matched.append(b)
    return {"status": "ok" if _wf_stopped(event) else "warning",
            "address": addr, "breakpoint": bp, "run": run, "wait": event,
            "software_breakpoints": shown, "matched": matched,
            "session": _invoke(lambda: _client.status(brief=True))}


@mcp.tool()
def binsentry_run_to(address: str, timeout_seconds: int = 20) -> Dict[str, Any]:
    """运行到指定地址并在停顿后返回状态、寄存器和反汇编。

    Args:
        address: 目标地址/符号
        timeout_seconds: 等待停顿的秒数，默认 20
    """
    addr = _wf_address(address)
    run = _invoke(lambda: _client.run_to(addr))
    if not _wf_ok(run):
        return _wf_error(run)
    event = _wait_stop_ms(timeout_seconds)
    reg = _invoke(lambda: _client.register())
    regs = _wf(reg).get("registers", {}) if isinstance(_wf(reg).get("registers"), dict) else {}
    rip = regs.get("ripHex") or regs.get("eipHex") or regs.get("cipHex")
    return {"status": "ok" if _wf_stopped(event) else "warning",
            "address": addr, "run": run, "wait": event, "registers": reg,
            "disassembly": _invoke(lambda: _client.disassemble_at(rip, 5)) if rip else None,
            "session": _invoke(lambda: _client.status(brief=True))}


@mcp.tool()
def binsentry_load_pdb_and_types(path: str, base: Union[int, str] = "", type_limit: int = 30) -> Dict[str, Any]:
    """加载 PDB（自动导入类型）并返回类型库摘要。

    Args:
        path: PDB 文件路径
        base: 可选模块基址；留空使用当前首个模块
        type_limit: 最多返回多少个类型名，默认 30
    """
    load = _invoke(lambda: _client.load_pdb(path, base))
    if not _wf_ok(load):
        return _wf_error(load)
    types = _invoke(lambda: _client.get_types())
    body = _wf(types)
    rows = body.get("types", []) if isinstance(body.get("types"), list) else []
    return {"status": "ok", "load": load,
            "types_count": len(rows),
            "types": rows[:max(0, type_limit)]}


@mcp.tool()
def binsentry_event_subscribe(types: str = "process_start,exception,paused,stopped",
                              all_events: bool = False) -> Dict[str, Any]:
    """创建独立事件订阅邮箱，返回 subId；之后用该 subId 轮询，不会抢别的客户端事件。

    Args:
        types: 逗号分隔事件类型；all_events=True 时忽略
        all_events: 订阅全部事件
    """
    res = _invoke(lambda: _client.subscribe_event(types if not all_events else "", 1 if all_events else 0))
    if not _wf_ok(res):
        return _wf_error(res)
    body = _wf(res)
    return {"status": "ok", "sub_id": body.get("subId"), "types": body.get("types"),
            "subscription": res}


@mcp.tool()
def binsentry_event_poll(sub_id: int, max_events: int = 50) -> Dict[str, Any]:
    """从指定订阅邮箱取事件；返回后该邮箱中的这批事件被消费，其他订阅不受影响。

    Args:
        sub_id: binsentry_event_subscribe 返回的订阅 ID
        max_events: 本次最多取多少条
    """
    res = _invoke(lambda: _client.get_events(max_events, sub_id))
    return {"status": "ok" if _wf_ok(res) else "error", "sub_id": sub_id, "events": res}


@mcp.tool()
def binsentry_wait_event(sub_id: int, max_events: int = 20, timeout_seconds: int = 20) -> Dict[str, Any]:
    """等待该订阅邮箱出现事件（200ms 轮询），用于代替盲目 sleep。

    Args:
        sub_id: 订阅 ID
        max_events: 一次最多取多少条
        timeout_seconds: 最长等待秒数，默认 20
    """
    deadline = time.time() + max(1, min(60, timeout_seconds))
    polls = 0
    while time.time() < deadline:
        res = _invoke(lambda: _client.get_events(max_events, sub_id))
        body = _wf(res)
        polls += 1
        if _wf_ok(res) and body.get("count", 0) > 0:
            return {"status": "ok", "sub_id": sub_id, "polls": polls, "events": res}
        if not _wf_ok(res):
            return _wf_error(res)
        time.sleep(0.2)
    return {"status": "warning", "sub_id": sub_id, "polls": polls,
            "message": "no event within timeout", "events": None}


@mcp.tool()
async def binsentry_event_stream(ctx: Context, sub_id: int, timeout_seconds: int = 30,
                                 max_events: int = 50) -> Dict[str, Any]:
    """通过后端 SSE 持续接收事件，并在收到时立即发送 MCP log 通知。

    与 binsentry_wait_event 不同，本工具在调用期间保持 SSE 长连接；每条事件
    都会通过 `notifications/message`（客户端日志）主动推送，不需要客户端轮询。
    工具在超时或达到 max_events 后返回本次收到的事件摘要。

    Args:
        sub_id: 订阅 ID（先用 binsentry_event_subscribe 创建）
        timeout_seconds: 最长保持连接的秒数，默认 30，最大 600
        max_events: 收到多少条 debug 事件后返回；0 表示只受超时限制
    """
    timeout_seconds = max(1, min(600, int(timeout_seconds)))
    max_events = max(0, int(max_events))
    loop = asyncio.get_running_loop()
    queue: "asyncio.Queue[Any]" = asyncio.Queue()
    collected: List[Dict[str, Any]] = []

    def worker() -> None:
        try:
            for item in _client.stream_events(sub_id, timeout_seconds, max_events):
                loop.call_soon_threadsafe(queue.put_nowait, ("item", item))
        except Exception as exc:  # noqa: BLE001 - 工具需把连接错误转成结构化结果
            loop.call_soon_threadsafe(queue.put_nowait, ("error", str(exc)))
        finally:
            loop.call_soon_threadsafe(queue.put_nowait, ("done", None))

    worker_task = asyncio.create_task(asyncio.to_thread(worker))
    notified = 0
    error_message = None
    try:
        await ctx.log("BinSentry event stream opened (subId=%d, timeout=%ds)"
                      % (sub_id, timeout_seconds), level="info")
        while True:
            kind, item = await queue.get()
            if kind == "done":
                break
            if kind == "error":
                error_message = str(item)
                break
            if not isinstance(item, dict):
                continue
            if item.get("event") == "ready":
                await ctx.log(json.dumps({"kind": "ready", "subId": sub_id}, ensure_ascii=False),
                              level="info")
            elif item.get("event") == "debug":
                payload = item.get("data")
                collected.append(payload if isinstance(payload, dict) else {"raw": payload})
                notified += 1
                await ctx.log(json.dumps({"kind": "debug_event", "event": payload},
                                         ensure_ascii=False), level="info")
            elif item.get("event") == "error":
                error_message = str(item.get("data"))
                break
    finally:
        try:
            await worker_task
        except Exception:
            pass

    if error_message:
        return {"status": "error", "sub_id": sub_id, "message": error_message,
                "event_count": len(collected), "events": collected}
    status = "ok" if collected else "warning"
    return {"status": status, "sub_id": sub_id, "mode": "sse+mcp-log-notification",
            "notifications_sent": notified, "event_count": len(collected),
            "events": collected,
            "message": None if collected else "no event within timeout"}


@mcp.tool()
def binsentry_event_unsubscribe(sub_id: int, all_events: bool = False) -> Dict[str, Any]:
    """取消事件订阅；取消后该 subId 的邮箱被删除。

    Args:
        sub_id: 订阅 ID
        all_events: 取消全部订阅（此时忽略 sub_id）
    """
    res = _invoke(lambda: _client.unsubscribe_event(sub_id, 1 if all_events else 0))
    return {"status": "ok" if _wf_ok(res) else "error", "unsubscribe": res}


def _lease_result(res: Any, lease_id: str = "") -> Dict[str, Any]:
    body = _wf(res)
    top_ok = isinstance(res, dict) and res.get("status") == "success"
    return {"status": "ok" if top_ok else "error",
            "lease_id": (body.get("leaseId") if top_ok else None) or lease_id,
            "owner": body.get("owner"),
            "remaining_ms": body.get("remainingMs"),
            "message": body.get("message"),
            "lease": res}


@mcp.tool()
def binsentry_lease_acquire(owner: str = "", ttl_seconds: int = 300) -> Dict[str, Any]:
    """获取独占会话租约，成功后自动把 leaseId 注入后续 SDK 请求。

    Args:
        owner: 持有者标识，如 agent-a
        ttl_seconds: 有效期秒数，默认 300
    """
    res = _invoke(lambda: _client.acquire_lease(owner or f"mcp-{os.getpid()}", ttl_seconds))
    out = _lease_result(res)
    if out["status"] == "ok" and out["lease_id"]:
        _client.config.set_lease(out["lease_id"])
    return out


@mcp.tool()
def binsentry_lease_renew(lease_id: str = "", ttl_seconds: int = 300) -> Dict[str, Any]:
    """续租；lease_id 留空时使用当前 SDK 会话里的租约。

    Args:
        lease_id: 租约 ID，可留空
        ttl_seconds: 新的有效期秒数
    """
    lid = lease_id or getattr(_client.config, "lease", "")
    res = _invoke(lambda: _client.renew_lease(lid, ttl_seconds))
    out = _lease_result(res, lid)
    if out["status"] == "ok" and out["lease_id"]:
        _client.config.set_lease(out["lease_id"])
    return out


@mcp.tool()
def binsentry_lease_release(lease_id: str = "") -> Dict[str, Any]:
    """释放租约；成功后清空当前 SDK 会话里的 leaseId。

    Args:
        lease_id: 租约 ID，可留空使用当前租约
    """
    lid = lease_id or getattr(_client.config, "lease", "")
    res = _invoke(lambda: _client.release_lease(lid))
    out = _lease_result(res, lid)
    if out["status"] == "ok":
        _client.config.set_lease("")
    return out


@mcp.tool()
def binsentry_lease_status() -> Dict[str, Any]:
    """查询当前是否有客户端持有会话租约。"""
    res = _invoke(lambda: _client.lease_status())
    body = _wf(res)
    return {"status": "ok", "active": body.get("active") is True,
            "lease_id": body.get("leaseId") or None, "owner": body.get("owner") or None,
            "remaining_ms": body.get("remainingMs"), "lease": res}


@mcp.tool()
def binsentry_server_info() -> Dict[str, Any]:
    """查看 MCP 服务自身的接口覆盖情况与当前后端配置。"""
    return {
        "status": "ok",
        "server": "BinSentry MCP Server",
        "backend": _client.config.server_addr,
        "timeout": _client.config.timeout,
        "interfaces_expected": COVERAGE["interfaces"],
        "interface_tools": COVERAGE["tools"],
        "generic_call_interfaces": len(COVERAGE["generic_only"]),
        "workflow_tools": len(WORKFLOW_TOOL_NAMES),
        "lease_event_tools": len(LEASE_EVENT_TOOL_NAMES),
        "ops_tools": 6,
        "tools_registered": COVERAGE["tools"] + len(WORKFLOW_TOOL_NAMES) + len(LEASE_EVENT_TOOL_NAMES) + 6,
        "lease_id": getattr(_client.config, "lease", "") or None,
        "missing_interfaces": COVERAGE["missing"],
        "unknown_interfaces": COVERAGE["unknown"],
        "doc_coverage": {
            "usage": f"{COVERAGE['doc_usage']}/{COVERAGE['doc_total']}",
            "params": f"{COVERAGE['doc_params']}/{COVERAGE['doc_total']}",
            "fields": f"{COVERAGE['doc_fields']}/{COVERAGE['doc_total']}",
        },
        "categories": _category_stats(),
    }


# ---------------------------------------------------------------------------
# 8. 统计与启动报告
# ---------------------------------------------------------------------------


def _category_stats() -> Dict[str, Dict[str, Any]]:
    """按 API 类统计接口数与已注册工具数。"""
    stats: Dict[str, Dict[str, Any]] = {}
    for iface, info in CATALOG.items():
        cat = info.get("category") or "?"
        stats.setdefault(cat, {"interfaces": 0, "tools": 0})["interfaces"] += 1
    for item in REGISTRY:
        stats.setdefault(item["category"], {"interfaces": 0, "tools": 0})["tools"] += 1
    return {
        cat: {**value, "category_cn": CATEGORY_CN.get(cat, "")}
        for cat, value in sorted(stats.items())
    }


def _report(detail: bool = False) -> str:
    """生成接口覆盖报告文本（写入 stderr，避免污染 stdio 传输的 stdout）。"""
    expected = COVERAGE["interfaces"]
    tools = COVERAGE["tools"]
    generic = len(COVERAGE["generic_only"])
    effective = tools + generic
    ratio = (effective / expected * 100) if expected else 0.0
    lines = [
        f"接口覆盖 {effective}/{expected}（{ratio:.1f}%）"
        f" · 具名 {tools} + 通用 {generic}",
        f"调用信息 用途 {COVERAGE['doc_usage']}/{COVERAGE['doc_total']}"
        f" · 参数 {COVERAGE['param_documented']}/{COVERAGE['param_total']}"
        f" · 返回 {COVERAGE['doc_fields']}/{COVERAGE['doc_total']}",
    ]
    if COVERAGE["missing"]:
        lines.append(f"缺失接口 {len(COVERAGE['missing'])} 个：" + ", ".join(COVERAGE["missing"]))
    if COVERAGE["missing_param_docs"]:
        lines.append(f"参数说明不全 {len(COVERAGE['missing_param_docs'])} 个："
                     + ", ".join(COVERAGE["missing_param_docs"][:15]))
    if COVERAGE["missing_fields"]:
        lines.append(f"返回结构缺失 {len(COVERAGE['missing_fields'])} 个："
                     + ", ".join(COVERAGE["missing_fields"][:15]))
    if COVERAGE["unknown"]:
        lines.append(f"清单外接口 {len(COVERAGE['unknown'])} 个：" + ", ".join(COVERAGE["unknown"]))
    if detail:
        for cat, value in _category_stats().items():
            label = value.get("category_cn") or cat
            lines.append(f"  {_pad(label, 16)} 接口 {value['interfaces']:>3} · 工具 {value['tools']:>3}")
    return "\n".join(lines)


def _dump_tools() -> None:
    """把工具清单以 JSON 输出到 stdout（供 CI / 前端比对）。"""
    workflow_tools = list(WORKFLOW_TOOL_NAMES) + list(LEASE_EVENT_TOOL_NAMES) + [
        "binsentry_ping", "binsentry_set_server", "binsentry_set_timeout",
        "binsentry_list_interfaces", "binsentry_call", "binsentry_server_info",
    ]
    payload = {
        "coverage": {k: v for k, v in COVERAGE.items()},
        "categories": _category_stats(),
        "tools": REGISTRY,
        "workflowTools": workflow_tools,
        "workflowToolCount": len(workflow_tools),
    }
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=1) + "\n")


# ---------------------------------------------------------------------------
# 9. 入口
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 9. 传输模式选择（stdio / sse / http / auto）
# ---------------------------------------------------------------------------

TRANSPORT_ALIASES: Dict[str, str] = {
    "stdio": "stdio",
    "sse": "sse",
    "http": "http",
    "streamable-http": "http",
    "streamable_http": "http",
    "streamablehttp": "http",
    "auto": "auto",
}

TRANSPORT_LABEL = {
    "stdio": "stdio（标准输入输出，客户端以 command/args 拉起）",
    "sse": "SSE（HTTP 长连接，默认端点 /sse）",
    "http": "Streamable HTTP（默认端点 /mcp）",
    "auto": "自动（终端里→HTTP，被管道/客户端拉起→stdio）",
}

TRANSPORT_DEFAULT_PATH = {"sse": "/sse", "http": "/mcp"}


def _transport_arg(value: str) -> str:
    """命令行/环境变量里的传输写法归一化（大小写与别名都接受）。"""
    key = (value or "").strip().lower()
    if key not in TRANSPORT_ALIASES:
        raise argparse.ArgumentTypeError(
            f"不支持的传输方式 {value!r}；可选：stdio、sse、http"
            "（别名 streamable-http）、auto"
        )
    return TRANSPORT_ALIASES[key]


def _port_arg(value: Any) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(f"端口必须是整数：{value!r}")
    if not 0 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"端口超出范围 0-65535：{port}")
    return port


def _normalize_path(path: str) -> str:
    value = (path or "").strip()
    if not value:
        return ""
    return value if value.startswith("/") else "/" + value


def _fastmcp_transport_support() -> Optional[set]:
    """探测当前 fastmcp 的 run() 支持哪些传输名。

    返回 None 表示源码不可探测（按 fastmcp>=2 的约定处理：stdio/sse/
    streamable-http 可用）；未安装 fastmcp 时返回空集合。
    """
    if not _FASTMCP_AVAILABLE:
        return set()
    try:
        source = inspect.getsource(mcp.run)
    except (OSError, TypeError):
        return None
    low = source.lower()
    found = set()
    if "stdio" in low:
        found.add("stdio")
    if "sse" in low:
        found.add("sse")
    if "streamable-http" in low or "streamable_http" in low:
        found.add("streamable-http")
    if re.search(r"['\"]http['\"]", low):
        found.add("http")
    return found or None


def _runtime_transport(mode: str) -> str:
    """把用户口径的 stdio/sse/http 映射成当前 fastmcp 认识的传输名。"""
    if mode == "stdio":
        return "stdio"
    support = _fastmcp_transport_support()
    if mode == "sse":
        if support is None or "sse" in support:
            return "sse"
        raise RuntimeError(
            "当前 fastmcp 不支持 SSE 传输；请改用 --transport http 或升级 fastmcp"
        )
    # http（Streamable HTTP）
    if support is None:
        return "streamable-http"
    if "streamable-http" in support:
        return "streamable-http"
    if "http" in support:
        return "http"
    raise RuntimeError(
        "当前 fastmcp 不支持 Streamable HTTP 传输；请改用 --transport stdio 或升级 fastmcp"
    )


def _resolve_endpoint_path(mode: str, cli_path: Optional[str]) -> str:
    """路径优先级：--mcp-path > MCP_PATH > 分传输环境变量 > 内置默认。"""
    candidate = _normalize_path(cli_path) or _normalize_path(os.environ.get("MCP_PATH", ""))
    if not candidate:
        env_name = "MCP_SSE_PATH" if mode == "sse" else "MCP_HTTP_PATH"
        candidate = _normalize_path(os.environ.get(env_name, ""))
    return candidate or TRANSPORT_DEFAULT_PATH.get(mode, "/")


def _endpoint_url(host: str, port: int, path: str) -> str:
    host_part = host or "127.0.0.1"
    if ":" in host_part and not host_part.startswith("["):
        host_part = f"[{host_part}]"
    return f"http://{host_part}:{port}{path}"


def _endpoint_base(url: str) -> str:
    """去掉路径，只保留 scheme://host:port，用于 SSE 消息端点等固定路径。"""
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return url.rstrip("/")
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _transport_rows(host: str, port: int, cli_path: Optional[str]) -> List[Dict[str, Any]]:
    """当前环境下三种传输的可用性与端点信息（供 --list-transports 展示）。"""
    rows: List[Dict[str, Any]] = []
    for mode in ("stdio", "sse", "http"):
        row: Dict[str, Any] = {
            "mode": mode,
            "label": TRANSPORT_LABEL[mode],
            "path": None,
            "endpoint": None,
            "supported": False,
            "runtime": None,
        }
        if _FASTMCP_AVAILABLE:
            try:
                row["runtime"] = _runtime_transport(mode)
                row["supported"] = True
            except RuntimeError:
                row["supported"] = False
        if mode != "stdio":
            path = _resolve_endpoint_path(mode, cli_path)
            row["path"] = path
            row["endpoint"] = _endpoint_url(host, port, path)
        rows.append(row)
    rows.append({
        "mode": "auto",
        "label": TRANSPORT_LABEL["auto"],
        "path": None,
        "endpoint": None,
        "supported": bool(_FASTMCP_AVAILABLE),
        "runtime": "stdio 或 http",
    })
    return rows


def _display_width(text: str) -> int:
    """中日韩全角字符按 2 列计算，避免终端里表格错位。"""
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in text)


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _display_width(text))


def _print_transports(host: str, port: int, cli_path: Optional[str]) -> None:
    """打印传输清单：模式、fastmcp 传输名、端点、客户端配法。"""
    rows = _transport_rows(host, port, cli_path)
    if not _FASTMCP_AVAILABLE:
        print(f"fastmcp 不可用（{_FASTMCP_IMPORT_ERROR or '未安装'}），以下为静态说明；修复后才能真正监听：")
        print("  python -m pip install --force-reinstall -r requirements.txt")
        print("  （或直接以 stdio/http/sse 启动，默认会自动安装；--no-auto-install 可关闭）")
        print()
    print(_pad("模式", 8) + _pad("状态", 8) + _pad("fastmcp 传输名", 22) + "端点")
    for row in rows:
        state = "可用" if row["supported"] else "不可用"
        target = row["endpoint"] or "—（不监听网络）"
        print(_pad(row["mode"], 8) + _pad(state, 8)
              + _pad(str(row["runtime"] or "-"), 22) + target)
    print()
    if port == 0:
        print("提示：端口 0 表示由系统分配，上面端点中的 :0 需以启动日志里的实际端口替换")
    print("路径优先级：--mcp-path > MCP_PATH > MCP_SSE_PATH/MCP_HTTP_PATH > 内置默认")
    sse_base = _endpoint_base(_endpoint_url(host, port, "/sse"))
    print(f"SSE 消息端点：{sse_base}/messages/（由 /sse 的 endpoint 事件下发）")
    print("auto 规则：stdin 是终端→http；被客户端以管道拉起→stdio")
    print()
    print("客户端配置示例（mcpServers 片段）：")
    print(json.dumps({
        "binsentry-stdio": {
            "command": "python",
            "args": [str(HERE / "mcp_server.py")],
        },
        "binsentry-http": {"url": _endpoint_url(host, port, _resolve_endpoint_path("http", cli_path))},
        "binsentry-sse": {"url": _endpoint_url(host, port, _resolve_endpoint_path("sse", cli_path))},
    }, ensure_ascii=False, indent=1))


# ---------------------------------------------------------------------------
# 9.5 控制台美化：启动面板与日志配色
# ---------------------------------------------------------------------------

_ANSI_ENABLED = False


def _enable_ansi() -> bool:
    """仅在真正的终端上启用 ANSI；管道、重定向与 CI 保持纯文本。"""
    global _ANSI_ENABLED
    if os.environ.get("NO_COLOR") or not sys.stderr.isatty():
        _ANSI_ENABLED = False
        return False
    if os.name == "nt":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-12)  # STD_ERROR_HANDLE
            mode = ctypes.c_uint32()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                _ANSI_ENABLED = False
                return False
            if not mode.value & 0x0004:  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
            _ANSI_ENABLED = True
        except Exception:
            _ANSI_ENABLED = False
    else:
        _ANSI_ENABLED = True
    return _ANSI_ENABLED


def _style(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _ANSI_ENABLED else text


class _ColorFormatter(logging.Formatter):
    """只给日志级别上色，时间戳压成灰色，消息本身保持原色。"""

    _LEVEL_COLOR = {"DEBUG": "90", "INFO": "36", "WARNING": "33", "ERROR": "31", "CRITICAL": "1;31"}

    def format(self, record: logging.LogRecord) -> str:
        if not _ANSI_ENABLED:
            return super().format(record)
        level = record.levelname
        color = self._LEVEL_COLOR.get(level)
        stamp = f"\033[90m[{self.formatTime(record, self.datefmt)}]\033[0m"
        level_text = _style(level, color) if color else level
        padding = " " * max(0, 7 - len(level))
        message = record.getMessage()
        if record.exc_info:
            message += "\n" + self.formatException(record.exc_info)
        return f"{stamp} {level_text}{padding} {message}"


def _panel_chars() -> Dict[str, str]:
    """终端编码支持制表符就用制表符，否则退回 ASCII，避免 cp936 花屏。"""
    encoding = sys.stderr.encoding or "utf-8"
    try:
        "┌─┐│└┘".encode(encoding)
        return {"tl": "┌", "tr": "┐", "bl": "└", "br": "┘", "h": "─", "v": "│"}
    except (UnicodeEncodeError, LookupError):
        return {"tl": "+", "tr": "+", "bl": "+", "br": "+", "h": "-", "v": "|"}


def _print_panel(title: str, rows: List[Tuple[str, str]]) -> None:
    """打印一个按显示宽度对齐的信息面板（stderr，不污染协议 stdout）。"""
    box = _panel_chars()
    label_width = max((_display_width(label) for label, _ in rows), default=0)
    content = [f"{_pad(label, label_width)}  {value}" for label, value in rows]
    inner = max([_display_width(text) for text in content] + [_display_width(title)]) + 2
    lines = [
        _style(title, "1;36"),
        box["tl"] + box["h"] * inner + box["tr"],
    ]
    for text in content:
        lines.append(f"{box['v']} {_pad(text, inner - 2)} {box['v']}")
    lines.append(box["bl"] + box["h"] * inner + box["br"])
    sys.stderr.write("\n".join(lines) + "\n")
    sys.stderr.flush()


def _print_startup_panel(mode_label: str, endpoint: Optional[str] = None,
                         runtime: Optional[str] = None) -> None:
    """启动时把后端、覆盖、文档、传输、端点收进一个面板。"""
    expected = COVERAGE["interfaces"]
    tools = COVERAGE["tools"]
    generic = len(COVERAGE["generic_only"])
    effective = tools + generic
    ratio = (effective / expected * 100) if expected else 0.0
    rows: List[Tuple[str, str]] = [
        ("后端", f"{_client.config.server_addr}    超时 {_client.config.timeout:.1f}s"),
        ("接口", f"{effective}/{expected}（{ratio:.1f}%）    具名 {tools} + 通用 {generic}"),
        ("文档", f"用途 {COVERAGE['doc_usage']}/{COVERAGE['doc_total']}"
                 f" · 参数 {COVERAGE['param_documented']}/{COVERAGE['param_total']}"
                 f" · 返回 {COVERAGE['doc_fields']}/{COVERAGE['doc_total']}"),
        ("传输", mode_label + (f"（fastmcp={runtime}）" if runtime else "")),
    ]
    if endpoint:
        rows.append(("端点", endpoint))
        rows.append(("客户端", f'{{"binsentry": {{"url": "{endpoint}"}}}}'))
        if mode_label == "SSE":
            rows.append(("消息", f"{_endpoint_base(endpoint)}/messages/"))
    else:
        rows.append(("说明", "stdout 仅协议消息，日志全部走 stderr"))
    _print_panel("BinSentry MCP Server", rows)


def _invoke_run(transport: str, endpoint: Optional[Dict[str, Any]] = None) -> None:
    """调用 fastmcp.run，并按当前版本能力裁剪参数。"""
    try:
        signature = inspect.signature(mcp.run)
    except (TypeError, ValueError):
        signature = None

    def accepts(name: str) -> bool:
        if signature is None:
            return True
        params = signature.parameters
        if name in params:
            return True
        return any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())

    kwargs: Dict[str, Any] = {"transport": transport}
    ignored: List[str] = []
    if endpoint:
        for key, value in endpoint.items():
            if accepts(key):
                kwargs[key] = value
            else:
                ignored.append(f"{key}={value}")
    if ignored:
        LOG.warning("当前 fastmcp 的 run() 不接受 %s，已忽略；"
                    "如需固定监听地址/端口/路径请升级 fastmcp 或改用其设置项",
                    ", ".join(ignored))
    if accepts("show_banner"):
        kwargs["show_banner"] = False
    try:
        mcp.run(**kwargs)
    except KeyboardInterrupt:
        LOG.info("收到 Ctrl+C，MCP 传输已停止")


def _run_server(args: argparse.Namespace) -> int:
    """按用户选择的传输方式启动 MCP 服务。"""
    mode = args.transport
    if mode == "auto":
        mode = "http" if sys.stdin.isatty() else "stdio"
        LOG.info("auto：stdin %s终端，选用 %s",
                 "是" if sys.stdin.isatty() else "不是", mode)

    if mode == "stdio":
        _print_startup_panel("stdio")
        _invoke_run("stdio")
        return 0

    runtime = _runtime_transport(mode)
    path = _resolve_endpoint_path(mode, args.mcp_path)
    endpoint = _endpoint_url(args.host, args.mcp_port, path)
    _print_startup_panel({"http": "Streamable HTTP", "sse": "SSE"}.get(mode, mode),
                         endpoint, runtime)
    if args.mcp_port == 0:
        LOG.warning("端口设为 0：实际端口由系统分配，面板里的 :0 需以运行日志为准；"
                    "需要固定客户端 URL 时请改用固定端口")
    _invoke_run(runtime, {"host": args.host, "port": args.mcp_port, "path": path})
    return 0


# ---------------------------------------------------------------------------
# 10. 运行依赖自动安装
# ---------------------------------------------------------------------------

_DEPS_REEXEC_FLAG = "MCP_DEPS_REEXEC"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in ("0", "false", "no", "off", "")


def _requirements_file() -> Path:
    return HERE / "requirements.txt"


def _run_pip(cmd: List[str], timeout: int = 900) -> Tuple[int, str]:
    """执行 pip 并把输出收进内存（stdout 必须留给 MCP 协议通道）。"""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return proc.returncode, proc.stdout or ""
    except subprocess.TimeoutExpired:
        return 124, f"pip 执行超时（>{timeout}s），请检查网络或手动安装"
    except OSError as exc:
        return 127, f"无法执行 pip：{exc}"


def _tail(text: str, limit: int = 2500) -> str:
    value = (text or "").strip()
    return value if len(value) <= limit else "…\n" + value[-limit:]


def _install_dependencies() -> bool:
    """按 requirements.txt 安装依赖；pip 缺失时先 ensurepip 再重试一次。"""
    requirements = _requirements_file()
    if requirements.is_file():
        cmd = [sys.executable, "-m", "pip", "install",
               "--disable-pip-version-check", "-r", str(requirements)]
    else:
        cmd = [sys.executable, "-m", "pip", "install",
               "--disable-pip-version-check", "fastmcp>=3.4", "fastapi", "uvicorn"]
    LOG.info("检测到 fastmcp 未安装，开始自动安装依赖：%s",
             subprocess.list2cmdline(cmd))
    code, output = _run_pip(cmd)
    if code != 0 and "no module named pip" in output.lower():
        LOG.warning("当前 Python 没有 pip，尝试 ensurepip 后重试")
        _run_pip([sys.executable, "-m", "ensurepip", "--upgrade"], timeout=300)
        code, output = _run_pip(cmd)
    if code != 0:
        LOG.error("自动安装依赖失败（退出码 %s）。可手动执行：\n  %s\n最后输出：\n%s",
                  code, subprocess.list2cmdline(cmd), _tail(output))
        return False
    LOG.info("依赖安装完成（fastmcp / fastapi / uvicorn）")
    return True


def _fastmcp_importable() -> bool:
    """安装完成后在当前解释器里能否找到 fastmcp（不真正 import）。"""
    importlib.invalidate_caches()
    try:
        return importlib.util.find_spec("fastmcp") is not None
    except (ImportError, AttributeError, ValueError):
        return False


def _redo_process() -> int:
    """安装成功后重启自身，让工具注册走真正的 FastMCP 实现。"""
    argv = [sys.executable] + list(sys.argv)
    env = dict(os.environ)
    env[_DEPS_REEXEC_FLAG] = "1"
    LOG.info("重启进程以加载新安装的 fastmcp：%s", subprocess.list2cmdline(argv))
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        os.execve(sys.executable, argv, env)
    except OSError as exc:
        # 个别 Windows 环境不允许替换进程镜像，退化为子进程并透传退出码
        LOG.warning("进程内重启失败（%s），改用子进程继续启动", exc)
        return subprocess.call(argv, env=env)
    return 0


def _ensure_runtime(args: argparse.Namespace) -> Optional[int]:
    """确保当前环境有 fastmcp：缺失且需要启动服务时自动安装并重启。

    返回 None 表示继续执行；返回整数表示本次运行到此结束（作为退出码）。
    """
    static_mode = bool(args.verify or args.list_tools or args.list_transports)

    if args.install_deps:
        if _FASTMCP_AVAILABLE:
            LOG.info("fastmcp 已安装，无需重复安装")
            return 0
        return 0 if _install_dependencies() else 2

    if _FASTMCP_AVAILABLE:
        return None

    if static_mode:
        LOG.info("fastmcp 不可用（%s）；--verify / --list-tools / --list-transports 为静态检查，"
                 "不需要安装运行库", _FASTMCP_IMPORT_ERROR or "未安装")
        return None

    if not args.auto_install:
        LOG.error("未安装 fastmcp，且已关闭自动安装；请执行 "
                  "python -m pip install -r requirements.txt，或加 --install-deps")
        return 2

    if _FASTMCP_MISSING_MODULE not in (None, "fastmcp"):
        LOG.error("fastmcp 已存在但导入失败（%s），缺的是 %s；请先修复该依赖",
                  _FASTMCP_IMPORT_ERROR, _FASTMCP_MISSING_MODULE)
        return 2

    if os.environ.get(_DEPS_REEXEC_FLAG) == "1":
        LOG.error("自动安装并重启后仍无法导入 fastmcp（%s）；"
                  "请确认 pip 与 python 属于同一环境：%s",
                  _FASTMCP_IMPORT_ERROR, sys.executable)
        return 2

    if not _install_dependencies():
        return 2
    if not _fastmcp_importable():
        LOG.error("安装命令成功，但当前解释器仍找不到 fastmcp（可能装到了别的 Python）；"
                  "请用 %s -m pip install -r requirements.txt 手动确认", sys.executable)
        return 2
    return _redo_process()


def _normalize_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> argparse.Namespace:
    """统一归一化命令行与环境变量输入，避免默认值绕过类型/范围校验。"""
    try:
        args.transport = _transport_arg(args.transport)
        args.mcp_port = _port_arg(args.mcp_port)
        args.backend_port = _port_arg(args.backend_port)
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))

    host = (args.host or "").strip()
    if not host:
        parser.error("--host 不能为空")
    args.host = host

    try:
        timeout = float(args.timeout)
    except (TypeError, ValueError):
        parser.error(f"--timeout 必须是数值：{args.timeout!r}")
    if not math.isfinite(timeout) or timeout <= 0:
        parser.error("--timeout 必须大于 0")
    args.timeout = timeout
    return args


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="BinSentry MCP Server（FastMCP，全量 441 个 SDK 接口 + 500 条清单）",
        epilog="传输方式：stdio（客户端拉起）、sse、http（Streamable HTTP）、auto；"
               "用 --list-transports 查看当前环境可用端点。",
    )
    parser.add_argument("--transport", type=_transport_arg,
                        default=os.environ.get("MCP_TRANSPORT", "stdio"),
                        metavar="{stdio,sse,http,auto}",
                        help="MCP 传输方式，默认 stdio；http 即 Streamable HTTP，"
                             "也可写 streamable-http；auto 在终端里起 HTTP、"
                             "被客户端以管道拉起时走 stdio")
    parser.add_argument("--host", default=os.environ.get("MCP_HOST", "127.0.0.1"),
                        help="HTTP/SSE 监听地址（默认 127.0.0.1）")
    parser.add_argument("--mcp-port", type=_port_arg,
                        default=os.environ.get("MCP_PORT", "8000"),
                        help="HTTP/SSE 监听端口（默认 8000；0 表示由系统分配）")
    parser.add_argument("--mcp-path", default=None,
                        help="HTTP/SSE 端点路径；留空按传输方式取默认："
                             "SSE=/sse、HTTP=/mcp")
    parser.add_argument("--backend-address", default=os.environ.get("BINSENTRY_ADDRESS", "127.0.0.1"),
                        help="BinSentry 后端地址（默认 127.0.0.1）")
    parser.add_argument("--backend-port", type=_port_arg,
                        default=os.environ.get("BINSENTRY_PORT", "6891"),
                        help="BinSentry 后端端口（默认 6891）")
    parser.add_argument("--api-key", default=os.environ.get("BINSENTRY_API_KEY"),
                        help="BinSentry X-API-Key（可选，默认用 SDK 内置密钥）")
    parser.add_argument("--timeout", type=float, default=float(os.environ.get("BINSENTRY_TIMEOUT", "5")),
                        help="后端请求超时秒数（默认 5）")
    parser.add_argument("--verify", action="store_true", help="只做接口覆盖与文档完整性校验，缺失时退出码为 1")
    parser.add_argument("--list-tools", action="store_true", help="输出工具清单 JSON 后退出")
    parser.add_argument("--list-transports", action="store_true",
                        help="列出当前环境可用的传输方式、端点与客户端配置示例后退出")
    parser.add_argument("--auto-install", action=argparse.BooleanOptionalAction,
                        default=_env_bool("MCP_AUTO_INSTALL", True),
                        help="启动服务时若未安装 fastmcp 则自动 pip 安装（默认开启；"
                             "MCP_AUTO_INSTALL=0 或 --no-auto-install 可关闭）")
    parser.add_argument("--install-deps", action="store_true",
                        help="安装 requirements.txt 依赖后退出（用于离线预热；已安装则直接返回 0）")
    parser.add_argument("--strict", action="store_true",
                        help="启动时若存在未覆盖接口则直接退出（默认仅告警）")
    parser.add_argument("--verbose", action="store_true", help="输出调试日志")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = _normalize_args(parser, parser.parse_args(argv))

    _enable_ansi()
    log_format = "[%(asctime)s] %(levelname)-7s %(message)s"
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.DEBUG if args.verbose else logging.INFO,
        format=log_format,
        datefmt="%H:%M:%S",
    )
    for handler in logging.getLogger().handlers:
        handler.setFormatter(_ColorFormatter(log_format, datefmt="%H:%M:%S"))
    if not args.verbose:
        # fastmcp 自带的 “Starting MCP server …” 与启动面板重复，默认不重复打印
        for name in ("fastmcp", "mcp"):
            logging.getLogger(name).setLevel(logging.WARNING)

    # 依赖检查放在最前：缺失 fastmcp 时先安装，避免把工具注册到 fallback 实现上
    early_exit = _ensure_runtime(args)
    if early_exit is not None:
        return early_exit

    global _client
    _client = SDK.BinSentryClient(
        address=args.backend_address, port=args.backend_port, api_key=args.api_key
    )
    _client.config.timeout = args.timeout

    if args.verbose:
        LOG.debug("接口分布：\n%s", _report(detail=True))

    if args.list_tools:
        _dump_tools()
        return 0

    if args.list_transports:
        _print_transports(args.host, int(args.mcp_port), args.mcp_path)
        return 0

    if args.verify:
        if COVERAGE["missing"]:
            LOG.error("存在未注册且无通用入口的接口：%s", ", ".join(COVERAGE["missing"]))
            return 1
        # 接口可调用不等于可正确调用：参数无说明或返回结构缺失同样视为不完整
        if CATALOG and (COVERAGE["missing_param_docs"] or COVERAGE["missing_fields"]):
            if COVERAGE["missing_param_docs"]:
                LOG.error("参数说明不全（%d 个接口）：%s",
                          len(COVERAGE["missing_param_docs"]),
                          ", ".join(COVERAGE["missing_param_docs"][:20]))
            if COVERAGE["missing_fields"]:
                LOG.error("返回结构缺失（%d 个接口）：%s",
                          len(COVERAGE["missing_fields"]),
                          ", ".join(COVERAGE["missing_fields"][:20]))
            LOG.error("可运行 python enrich_interfaces.py 依据源码补齐接口信息")
            return 1
        LOG.info("校验通过：接口 %d/%d（具名 %d + 通用 %d） · 参数 %d/%d · 返回 %d/%d",
                 COVERAGE["interfaces"], COVERAGE["interfaces"],
                 COVERAGE["tools"], len(COVERAGE["generic_only"]),
                 COVERAGE["param_documented"], COVERAGE["param_total"],
                 COVERAGE["doc_fields"], COVERAGE["doc_total"])
        return 0

    if COVERAGE["missing"] and args.strict:
        LOG.error("严格模式下终止：%d 个接口未注册，%s",
                  len(COVERAGE["missing"]), ", ".join(COVERAGE["missing"][:20]))
        return 2

    if not _FASTMCP_AVAILABLE:
        LOG.error("未安装 fastmcp，无法启动 MCP 传输；请先执行 python -m pip install -r requirements.txt")
        return 2

    try:
        return _run_server(args)
    except RuntimeError as exc:
        LOG.error("%s", exc)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
