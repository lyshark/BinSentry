# -*- coding: utf-8 -*-
"""补全 binsentry_interfaces.json 的接口调用信息（参数语义 / 类型 / 必填 / 返回字段）
==================================================================================

数据来源（全部来自本仓库源码，避免凭空编造）：

1. ``MCP Server/__init__.py``        —— 后端 payload 键名、Python 参数类型与默认值
2. ``binsentry_commands.cpp``        —— 命令行派发链：每个接口支持的 ``--flag`` 及结果字段
3. ``binsentry_breakpoints.cpp``     —— 50 条断点属性命令的 ``g_bpAttrCmds`` 表与结果结构
4. ``HTML/ifaces.db.js``             —— 中文用途与请求示例（已有内容不覆盖）

处理原则：

* 只填空、只补充，不覆盖已经写好的人工说明；
* 参数说明只把「空」「（值）」「（示例：…）」这类占位替换为语义说明；
* 返回字段优先沿用已有内容，缺失时从 C++ 的 ``cJSON_Add*ToObject(result, ...)``
  递归解析（会跟进 ``AddXxxJson(result, ...)`` 一类的辅助函数）；
* ``outputs`` 为空时补成字段名列表。

用法：
    python enrich_interfaces.py            # 补全并写回 JSON
    python enrich_interfaces.py --check    # 只报告缺口，不写文件（有缺口退出码 1）
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import types
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
PROJ = HERE.parent
TARGET = HERE / "binsentry_interfaces.json"
COMMANDS_CPP = PROJ / "binsentry_commands.cpp"
BREAKPOINTS_CPP = PROJ / "binsentry_breakpoints.cpp"
WEB_DB = PROJ / "HTML" / "ifaces.db.js"

# ---------------------------------------------------------------------------
# 参数说明词典：键名 -> 语义。全部取自接口实际语义，覆盖 JSON 中的全部键名。
# ---------------------------------------------------------------------------
KEY_DESC: Dict[str, str] = {
    "address": "目标地址（十六进制，可带 0x）",
    "addr": "目标地址（十六进制，可带 0x）",
    "start": "起始地址（十六进制）",
    "end": "结束地址（十六进制，省略表示到所在区域末尾）",
    "base": "基址（十六进制）",
    "dst": "目标地址/目标缓冲区",
    "src": "源地址/源文件路径",
    "target": "目标地址（十六进制）",
    "entry": "入口点（RVA 或绝对地址）",
    "cip": "当前指令指针（CIP）值",
    "size": "长度/大小（字节）",
    "len": "长度（字节或元素个数，见接口用途）",
    "max": "最大返回条数（0 表示后端默认上限）",
    "count": "数量/次数",
    "index": "索引（从 0 开始）",
    "id": "标识/索引（断点、看门狗或订阅 ID）",
    "name": "名称/标识",
    "prefix": "名称前缀（批量匹配用）",
    "value": "值（按接口语义为数值、文本或开关）",
    "type": "类型名（数据类型或断点类型，取值见接口用途）",
    "ptype": "指针/数据类型",
    "bpx": "BPX 选项（命中后自动执行的断点设置，取值见接口用途）",
    "def": "类型定义文本（C 风格 struct/union 声明）",
    "struct": "结构体名",
    "field": "结构体字段名",
    "member": "联合体/结构体成员名",
    "aname": "参数名（AddArg/AppendArg 的别名字段）",
    "mname": "成员名（AddMember/AppendMember 的别名字段）",
    "arg": "参数名",
    "param": "参数名",
    "args": "调试参数命令行（原样传给被调试进程）",
    "cmdline": "命令行文本",
    "command": "命令文本（调试器命令或待执行命令）",
    "enable": "启用开关（1/0 或 true/false）",
    "disable": "禁用开关（1/0 或 true/false）",
    "flag": "标志位（内存断点访问类型 r/w/x，或布尔开关）",
    "option": "选项（选项名或位掩码，取值见接口用途）",
    "access": "内存访问类型（r/w/x 组合）",
    "remove": "是否移除/删除（1/0）",
    "clear": "是否清空既有记录（1/0）",
    "reset": "是否重置（1/0）",
    "all": "是否作用于全部对象（1/0）",
    "write": "写入内容（十六进制字节）",
    "code": "异常码/错误码（十六进制或十进制）",
    "condition": "条件表达式（非零时命中/生效）",
    "cond": "条件表达式（非零时命中/生效）",
    "expr": "表达式（BinSentry 表达式语法）",
    "text": "文本内容",
    "string": "字符串内容",
    "str": "字符串内容",
    "log": "日志文本",
    "format": "格式化字符串（printf 风格）",
    "pattern": "字节模式（十六进制，支持 ?? 通配）",
    "search": "搜索模式（十六进制，支持 ? 通配）",
    "replace": "替换模式（十六进制）",
    "mnemonic": "汇编助记符（如 jmp/call/mov）",
    "opcode": "操作码（十六进制字节）",
    "instr": "指令文本",
    "file": "文件路径",
    "path": "文件或目录路径",
    "script": "脚本文件路径",
    "url": "下载 URL",
    "dest": "目标路径或目标地址",
    "folder": "输出目录",
    "algo": "哈希算法（md5/sha1/crc32/murmur32/murmur128 等）",
    "module": "模块名（如 ntdll.dll，省略表示主模块）",
    "dll": "目标 DLL 名（API 断点所属模块）",
    "api": "API/函数名（API 断点目标）",
    "filter": "过滤条件（名称/关键字）",
    "priority": "优先级（数值越大越优先）",
    "pid": "进程 ID",
    "tid": "线程 ID（0 表示当前活动线程）",
    "thread": "线程 ID",
    "threadid": "线程 ID",
    "handle": "句柄值（十六进制）",
    "hwnd": "窗口句柄（十六进制）",
    "dr": "硬件断点寄存器编号（0-3）",
    "color": "颜色值（0xRRGGBB）",
    "hitcount": "命中次数（省略时仅查询，不清零）",
    "tail": "尾部保留字节数",
    "head": "头部保留字节数",
    "iterations": "迭代次数",
    "timeout": "超时（毫秒；部分接口为秒，见接口用途）",
    "useragent": "HTTP User-Agent",
    "debugger": "调试器标识/名称",
    "line": "行号（从 1 开始）",
    "depth": "递归/展开层数",
    "party": "所属方名称（'-' 表示清除）",
    "status": "状态过滤值",
    "mode": "模式（取值见接口用途）",
    "option_name": "选项名",
    "nop": "是否用 NOP 填充（1/0）",
    "fillnop": "是否用 NOP 填充（1/0）",
    "patch": "补丁内容或补丁文件路径",
    "ignore": "需要忽略的项（逗号分隔）",
    "commit": "提交内存页数（仅统计已提交区域）",
    "wait": "等待毫秒数",
    "ymm": "YMM 寄存器值（16 字节十六进制）",
    "zmm": "ZMM 寄存器值（32 字节十六进制）",
    "zmms": "ZMM 寄存器值（32 字节十六进制，逗号分隔）",
    "opmask": "opmask 寄存器值（8 位十六进制）",
    "opmasks": "opmask 寄存器值（8 位十六进制，逗号分隔）",
    "above": "只转储高于该地址的区域（1/0）",
    "max_bytes": "转储总字节上限（默认 1 GiB）",
    "flags": "标志位（按接口语义，见接口用途）",
    "full": "是否返回完整内容（1/0）",
    "var": "变量名",
    "aname_": "参数名",
    "section": "节区名",
    "region": "内存区域标识",
    "symbol": "符号名",
    "rva": "相对虚拟地址（RVA）",
    "offset": "文件偏移或地址偏移",
    "pattern_type": "模式类型",
}

# 需要按接口区分的参数说明（词典无法区分语义时使用）
PARAM_OVERRIDES: Dict[Tuple[str, str], str] = {
    ("SetDebug", "command"): "要执行的调试器命令（如 Logs、Run、StepInto）",
    ("SysCommand", "command"): "要执行的系统命令文本",
    ("SysCommand", "shell"): "命令解释器（cmd/powershell）",
    ("SysCommand", "cwd"): "命令工作目录",
    ("SysCommand", "timeout"): "命令超时（秒）",
    ("AddArg", "name"): "自定义类型名（struct/union 名称）",
    ("AddArg", "type"): "字段的 C 类型（如 int、DWORD、char*）",
    ("AddMember", "type"): "成员类型（支持嵌套已定义类型）",
    ("AddUnion", "type"): "联合体名或成员类型",
    ("AddUnion", "src"): "源结构类型名（按已有类型展开成员）",
    ("AddUnion", "value"): "枚举/常量值（可选）",
    ("AddUnion", "size"): "联合体总大小（字节，可选）",
    ("BpRefList", "type"): "断点类型过滤（software/hardware/memory/librarian/exception）",
    ("BpRefList", "priority"): "按优先级排序（1/0）",
    ("BpRefList", "text"): "按文本内容过滤",
    ("BpRefList", "module"): "只保留该模块内的引用",
    ("CheckWatchdog", "name"): "看门狗名称（按名称检查）",
    ("CheckWatchdog", "value"): "期望值（与当前值不一致时报告触发）",
    ("DeleteWatchDog", "expr"): "看门狗表达式（按表达式删除）",
    ("DeleteWatchDog", "value"): "看门狗期望值（辅助匹配）",
    ("FormatLog", "hitcount"): "是否附带断点命中次数（1/0）",
    ("GetRelocSize", "enable"): "是否启用重定位统计（1/0）",
    ("GetRelocSize", "value"): "重定位项过滤值（可选）",
    ("GetRelocSize", "base"): "重定位基准地址（可选）",
    ("GetRelocSize", "remove"): "是否同时移除重定位项（1/0）",
    ("MsgPush", "type"): "消息类型编号",
    ("MsgPush", "text"): "消息正文",
    ("MsgPush", "priority"): "消息优先级（数值越大越优先）",
    ("MsgPop", "type"): "只弹出该类型编号的消息",
    ("MsgClear", "party"): "只清理该来源方的消息",
    ("MsgClear", "module"): "只清理该模块相关的消息",
    ("SetTraceRecordType", "type"): "记录粒度（0=关闭，1=按位，2=字节+计数器）",
    ("SetDataMarking", "type"): "数据类型（byte/word/dword/qword/oword/float/double/ascii/unicode/code/junk 等）",
    ("SetAddressColor", "color"): "颜色值（0xRRGGBB）",
    ("GetTraceRecordType", "address"): "只查询该地址所在页的记录类型",
    ("GetTraceRecordType", "size"): "查询覆盖的长度（字节）",
    ("GetTraceRecordType", "file"): "输出到指定 JSON 文件",
    ("GetTraceRecordType", "line"): "输出文件中的起始行号（可选）",
    ("TraceSetStepFilter", "id"): "步骤过滤规则 ID",
    ("TraceSetStepFilter", "expr"): "步骤过滤表达式",
    ("TraceSetStepFilter", "clear"): "是否清空全部步骤过滤规则（1/0）",
    ("TraceSetCommand", "value"): "命中时执行的命令",
    ("TraceSetCommand", "filter"): "只对匹配该过滤条件的记录生效",
    ("TraceSetCommand", "clear"): "是否清空命令（1/0）",
    ("TraceSetLogFile", "value"): "日志文件名或路径",
    ("TraceSetLogFile", "filter"): "只记录匹配该过滤条件的记录",
    ("TraceSetLogFile", "clear"): "是否停止记录（1/0）",
    ("GetDataMarkings", "start"): "只返回该地址之后的标记",
    ("GetDataMarkings", "max"): "最大返回条数",
    ("DumpRegions", "above"): "只转储高于该地址的区域（1/0）",
    ("PatchFile", "patch"): "补丁文件路径或补丁字节",
    ("SetCommandLine", "args"): "新的命令行参数（不含程序路径）",
    ("SetCommandLine", "cmdline"): "完整命令行（含程序路径）",
    ("GetCommandLine", "cmdline"): "是否返回完整命令行文本（1/0）",
    ("GetCommandLine", "value"): "是否返回值（1/0，兼容别名）",
    ("switchthread", "value"): "要切换到的线程 ID（兼容写法）",
    ("switchthread", "cmdline"): "命令行文本（兼容写法）",
    ("bpgoto", "index"): "断点索引（与 address 二选一）",
    ("setfreezestack", "name"): "冻结栈帧的名称",
    ("setfreezestack", "module"): "栈帧所属模块",
    ("setfreezestack", "size"): "栈帧字节数",
    ("setfreezestack", "remove"): "是否取消冻结（1/0）",
    ("virtualmod", "name"): "虚拟模块名称",
    ("virtualmod", "size"): "虚拟模块大小（字节）",
    ("virtualmod", "remove"): "是否移除虚拟模块（1/0）",
    ("mnemonichelp", "value"): "助记符说明文本（兼容别名）",
    ("mnemonichelp", "name"): "助记符名称",
    ("mnemonichelp", "size"): "匹配字节数",
    ("savedata", "count"): "保存的字节数",
    ("argumentadd", "format"): "参数显示格式（可选）",
    ("argumentlist", "format"): "只显示该格式的参数",
    ("argumentlist", "value"): "只显示该值的参数",
    ("argumentclear", "format"): "只清除该格式的参数",
    ("functionadd", "name"): "函数名称",
    ("functionadd", "end"): "函数结束地址",
    ("functiondel", "name"): "要删除的函数名称",
    ("functionlist", "name"): "只列出该名称的函数",
    ("loopadd", "name"): "循环名称",
    ("loopdel", "name"): "要删除的循环名称",
    ("looplist", "name"): "只列出该名称的循环",
    ("varnew", "name"): "变量名（自动补 $ 前缀）",
    ("varset", "name"): "变量名",
    ("vardel", "name"): "要删除的变量名",
    ("varlist", "name"): "只列出该名称的变量",
    ("symdownload", "url"): "符号服务器 URL 或本地符号路径",
    ("symdownload", "dest"): "符号下载目标目录",
    ("symdownload", "name"): "只下载该模块的符号",
    ("symdownload", "script"): "符号下载脚本路径",
    ("setmaxfindresult", "count"): "最大结果数",
    ("setmaxfindresult", "command"): "只对该命令生效（留空表示全局）",
    ("SetAVX512Context", "zmms"): "ZMM0-ZMM31 内容（逗号分隔的 64 位十六进制块）",
    ("SetAVX512Context", "opmasks"): "k0-k7 opmask 内容（逗号分隔的 16 位十六进制）",
    ("plugload", "script"): "插件脚本路径",
    ("plugreload", "script"): "要重载的插件脚本路径",
    ("plugunload", "script"): "要卸载的插件脚本路径",
    ("copystr", "dst"): "目标地址",
    ("copystr", "max"): "最大复制字节数",
    ("copystr", "type"): "数据解释类型（ascii/unicode/utf8 等）",
    ("setstr", "dst"): "目标地址",
    ("setstr", "string"): "要写入的字符串",
    ("setstr", "type"): "字符串编码（ascii/unicode/utf8）",
    ("setstr", "max"): "最大写入字节数",
    ("getjit", "debugger"): "调试器标识",
    ("setjit", "debugger"): "调试器标识",
    ("getjitauto", "debugger"): "调试器标识",
    ("setjitauto", "debugger"): "调试器标识",
    ("exanal", "mnemonic"): "要解释的助记符",
    ("exanal", "name"): "要解释的助记符（兼容别名）",
    ("dprintf", "format"): "printf 风格格式串",
    ("dprintf", "value"): "格式串参数值",
    ("briefcheck", "dll"): "只检查该模块",
    ("modcallfind", "max"): "最大返回条数",
}

# 参数类型（SDK 未覆盖或需要更精确时）
PARAM_TYPES: Dict[str, str] = {
    "address": "string", "start": "string", "end": "string", "base": "string",
    "dst": "string", "src": "string", "entry": "string", "code": "string",
    "size": "number", "max": "number", "count": "number", "index": "number",
    "pid": "number", "tid": "number", "thread": "number", "threadid": "number",
    "dr": "number", "color": "string", "hitcount": "number", "depth": "number",
    "iterations": "number", "timeout": "number", "priority": "number",
    "line": "number", "max_bytes": "number", "wait": "number", "tail": "number",
    "head": "number", "enable": "bool", "remove": "bool", "clear": "bool",
    "reset": "bool", "all": "bool", "above": "bool", "fillnop": "bool",
    "nop": "bool", "full": "bool", "ignore": "string",
}

# 50 条断点属性命令之外、需要单独修返回结构的接口（源码里没有直接 cJSON 字段）
FIELD_OVERRIDES: Dict[str, List[Dict[str, str]]] = {}

BP_KIND_PARAMS = {
    "BPK_HARDWARE": [("address", "断点地址（十六进制）", "string", True)],
    "BPK_MEMORY": [("address", "断点地址（十六进制）", "string", True)],
    "BPK_LIBRARIAN": [
        ("dll", "目标 DLL 名（如 kernel32.dll）", "string", True),
        ("api", "API/导出函数名", "string", True),
    ],
    "BPK_EXCEPTION": [("code", "异常码（十六进制或十进制）", "string", True)],
    "BPK_SOFT": [("address", "断点地址（十六进制）", "string", True)],
}

BP_ATTR_PARAMS = {
    "BAK_NAME": [("value", "断点名称", "string", True)],
    "BAK_CONDITION": [("value", "条件表达式（非零时命中）", "string", True)],
    "BAK_LOG": [("value", "命中时输出的日志文本", "string", True)],
    "BAK_LOGCOND": [("value", "日志条件表达式（非零时输出日志）", "string", True)],
    "BAK_COMMAND": [("value", "命中时执行的调试器命令", "string", True)],
    "BAK_COMMANDCOND": [("value", "命令执行条件表达式（非零时执行命令）", "string", True)],
    "BAK_LOGFILE": [("value", "日志输出文件路径", "string", True)],
    "BAK_SILENT": [("enable", "是否静默（1/0，默认 1）", "bool", False)],
    "BAK_SINGLESHOT": [("enable", "是否单次命中后自动删除（1/0，默认 1）", "bool", False)],
    "BAK_FASTRESUME": [("enable", "是否快速恢复（1/0，默认 1）", "bool", False)],
    "BAK_HITCOUNT": [("count", "可选：给出时把命中计数改写为该值；省略时仅查询", "number", False)],
    "BAK_RESET_HITCOUNT": [],
}

_TYPE_MAP = {"Bool": "bool", "Number": "number", "String": "string", "Object": "object",
             "Array": "array", "Item": "array", "Null": "null", "Raw": "string"}


# ---------------------------------------------------------------------------
# C++ 解析
# ---------------------------------------------------------------------------
class CppIndex:
    def __init__(self) -> None:
        self.text = ""
        self.blocks: Dict[str, Dict[str, Any]] = {}
        self.funcs: Dict[str, Tuple[str, str]] = {}
        self._load()
        self._parse_blocks()
        self._parse_funcs()

    def _load(self) -> None:
        self.text = COMMANDS_CPP.read_text(encoding="utf-8", errors="replace")

    def _parse_blocks(self) -> None:
        head_re = re.compile(
            r'if\s*\((?P<cond>[^{;]*?strcmp\(\s*Opts\[0\]\s*,\s*"[^"]+"\s*\)[^{;]*?)\)\s*\{'
        )
        names_re = re.compile(r'strcmp\(\s*Opts\[0\]\s*,\s*"([^"]+)"\s*\)\s*==\s*0')
        for m in head_re.finditer(self.text):
            names = names_re.findall(m.group("cond"))
            if not names:
                continue
            body = self.text[m.end():self._block_end(m.end())]
            flags = sorted(set(re.findall(r'strcmp\(\s*Opts\[i\]\s*,\s*"(--[A-Za-z0-9_]+)"', body)))
            keys, nested = _scan_keys(body)
            calls = _scan_result_calls(body)
            for name in names:
                self.blocks.setdefault(name, {
                    "flags": flags, "keys": keys, "nested": nested, "calls": calls, "body": body,
                })

    def _block_end(self, start: int) -> int:
        text, n = self.text, len(self.text)
        depth, i = 1, start
        in_str = in_chr = esc = False
        while i < n and depth > 0:
            c = text[i]
            if in_str:
                if esc: esc = False
                elif c == "\\": esc = True
                elif c == '"': in_str = False
            elif in_chr:
                if esc: esc = False
                elif c == "\\": esc = True
                elif c == "'": in_chr = False
            else:
                if c == '"': in_str = True
                elif c == "'": in_chr = True
                elif c == "{": depth += 1
                elif c == "}": depth -= 1
            i += 1
        return i

    def _parse_funcs(self) -> None:
        """索引项目根目录所有 *.cpp / *.c 的函数体（跨文件跟进 AddXxxJson 一类辅助函数）。

        同时记录每个函数的第一个参数名：辅助函数把结果写进 ``cJSON* obj`` 而不是
        ``result``，必须按实际参数名扫描，才能拿到真实返回字段。
        """
        pattern = re.compile(
            r'\b(?:static\s+|inline\s+)?(?:void|bool|int|std::string|cJSON\*|ULONG_PTR)\s+'
            r'(?:\w+::)?(?P<name>\w+)\s*\((?P<args>[^;{}]*)\)\s*\{'
        )
        files = sorted(list(PROJ.glob("*.cpp")) + list(PROJ.glob("*.c")))
        for path in files:
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for m in pattern.finditer(source):
                name = m.group("name")
                end = self._block_end_in(source, m.end())
                body = source[m.end():end]
                result_var = _first_param_name(m.group("args"))
                # 同名函数优先保留内容更完整的一份（桥接函数只有一行转发）
                if name not in self.funcs or len(body) > len(self.funcs[name][0]):
                    self.funcs[name] = (body, result_var)

    @staticmethod
    def _block_end_in(source: str, start: int) -> int:
        depth, i, n = 1, start, len(source)
        in_str = in_chr = esc = False
        while i < n and depth > 0:
            c = source[i]
            if in_str:
                if esc: esc = False
                elif c == "\\": esc = True
                elif c == '"': in_str = False
            elif in_chr:
                if esc: esc = False
                elif c == "\\": esc = True
                elif c == "'": in_chr = False
            else:
                if c == '"': in_str = True
                elif c == "'": in_chr = True
                elif c == "{": depth += 1
                elif c == "}": depth -= 1
            i += 1
        return i

    def keys_of(self, iface: str, depth: int = 3) -> Tuple[Dict[str, str], List[str]]:
        """接口返回字段（含辅助函数递归）与数组元素字段。"""
        block = self.blocks.get(iface)
        if not block:
            return {}, []
        keys = dict(block["keys"])
        nested = list(block["nested"])
        pending = list(block["calls"])
        seen = set()
        level = 0
        while pending and level < depth:
            nxt: List[str] = []
            for fn in pending:
                if fn in seen or fn not in self.funcs:
                    continue
                seen.add(fn)
                body, var = self.funcs[fn]
                k2, n2 = _scan_keys(body, var)
                for k, v in k2.items():
                    keys.setdefault(k, v)
                nested.extend(n2)
                nxt.extend(_scan_result_calls(body, var))
            pending = nxt
            level += 1
        # 元素字段去重、剔除与顶层重复的键
        nested = sorted({x for x in nested if x not in keys})
        return keys, nested


def _first_param_name(args: str) -> str:
    """从 ``cJSON* obj, DWORD pid`` 取第一个参数名（辅助函数的结果容器）。"""
    if not args.strip() or args.strip() == "void":
        return "result"
    first = args.split(",")[0]
    m = re.search(r'([A-Za-z_]\w*)\s*(?:\[\s*\])?\s*$', first.strip())
    return m.group(1) if m else "result"


def _scan_keys(body: str, result_var: str = "result") -> Tuple[Dict[str, str], List[str]]:
    """扫描一个函数体里写入 ``result_var`` 的字段，以及其它对象的元素级字段。"""
    keys: Dict[str, str] = {}
    nested: List[str] = []
    rv = re.escape(result_var)
    for m in re.finditer(rf'cJSON_Add(\w+?)ToObject\(\s*{rv}\s*,\s*"([^"]+)"', body):
        keys.setdefault(m.group(2), _TYPE_MAP.get(m.group(1), "string"))
    for m in re.finditer(rf'AddHexStr\(\s*{rv}\s*,\s*"([^"]+)"', body):
        keys.setdefault(m.group(1), "string")
    for m in re.finditer(rf'cJSON_AddItemToObject\(\s*{rv}\s*,\s*"([^"]+)"', body):
        keys.setdefault(m.group(1), "array")
    # 元素级字段：非结果对象上添加的键
    for m in re.finditer(r'cJSON_Add(\w+?)ToObject\(\s*(\w+)\s*,\s*"([^"]+)"', body):
        var, key = m.group(2), m.group(3)
        if var != result_var and key not in ("state", "message"):
            nested.append(key)
    return keys, nested


def _scan_result_calls(body: str, result_var: str = "result") -> List[str]:
    """块里调用并把结果容器传入的辅助函数名（AddXxxJson(result, ...)）。"""
    names: List[str] = []
    pattern = re.escape(result_var)
    for m in re.finditer(r'(?:[A-Za-z_]\w*::)*(?P<name>[A-Za-z_]\w*)\s*\(', body):
        name = m.group("name")
        if name.startswith("cJSON") or name in ("if", "for", "while", "switch", "strcmp", "sizeof"):
            continue
        # 取调用参数，判断是否包含结果容器
        start = m.end()
        depth, i, n = 1, start, len(body)
        while i < n and depth > 0:
            if body[i] == "(": depth += 1
            elif body[i] == ")": depth -= 1
            i += 1
        args = body[start:i - 1]
        if re.search(rf'\b{pattern}\b', args):
            names.append(name)
    return sorted(set(names))


# ---------------------------------------------------------------------------
# SDK 签名信息
# ---------------------------------------------------------------------------
def sdk_param_info() -> Dict[str, Dict[str, Dict[str, Any]]]:
    """{接口: {payload 键: {type, required, py_name}}}"""
    try:
        import fastmcp  # noqa: F401
    except (ImportError, SyntaxError):
        stub = types.ModuleType("fastmcp")

        class _StubFastMCP:
            def __init__(self, *a, **k): pass

            def tool(self, *a, **k):
                if a and callable(a[0]): return a[0]
                return lambda fn: fn

            def run(self, *a, **k): pass

        stub.FastMCP = _StubFastMCP
        stub.Context = object
        sys.modules["fastmcp"] = stub

    import importlib.util
    import inspect
    spec = importlib.util.spec_from_file_location("mcp_server", HERE / "mcp_server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    out: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for cls, method, fn, _tool in module._collect_methods():
        iface = module._interface_of(cls, method)
        info = out.setdefault(iface, {})
        key_map = module._payload_key_map(fn)
        for name, p in inspect.signature(fn).parameters.items():
            if name == "self":
                continue
            ann = "string"
            if p.annotation in (int, float):
                ann = "number"
            elif p.annotation is bool:
                ann = "bool"
            elif p.annotation in (str, Any) or p.annotation is inspect.Parameter.empty:
                ann = "string"
            else:
                ann = "string|number"
            info[key_map.get(name, name)] = {
                "type": ann,
                "required": p.default is inspect.Parameter.empty,
                "py_name": name,
            }
    return out


# ---------------------------------------------------------------------------
# 断点属性命令
# ---------------------------------------------------------------------------
def load_bp_attr_table() -> Dict[str, Tuple[str, str]]:
    text = BREAKPOINTS_CPP.read_text(encoding="utf-8", errors="replace")
    out: Dict[str, Tuple[str, str]] = {}
    for name, kind, attr in re.findall(r'\{\s*"([^"]+)"\s*,\s*(BPK_\w+)\s*,\s*(BAK_\w+)\s*\}', text):
        out[name] = (kind, attr)
    return out


# ---------------------------------------------------------------------------
# 补全逻辑
# ---------------------------------------------------------------------------
_WEAK = re.compile(r'^[（(](?:值|示例|可选|默认|必填|兼容|见).*[）)]$')


def is_weak(desc: str) -> bool:
    s = (desc or "").strip()
    if not s:
        return True
    return bool(_WEAK.match(s))


def param_desc(iface: str, key: str, fallback_usage: str) -> str:
    override = PARAM_OVERRIDES.get((iface, key))
    if override:
        return override
    base = KEY_DESC.get(key)
    if base:
        return base
    # 从接口用途中找 "--key <x>" 说明
    m = re.search(rf'--{re.escape(key)}\s*<([^>]+)>', fallback_usage or "")
    if m:
        return f"{key}（命令行 --{key} <{m.group(1)}>）"
    return f"{key}（参数语义见接口用途）"


def normalize_fields(fields: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """统一字段类型写法并去重。

    历史数据里出现过 ``hex(string)`` / ``array[object]`` / ``array[string]``，
    这里统一成 ``string`` / ``array``，十六进制用 ``format=hex`` 标注，
    数组元素类型放 ``itemType``，方便 MCP 客户端按同一套类型渲染。
    """
    out: List[Dict[str, Any]] = []
    seen = set()
    for f in fields:
        name = (f.get("field") or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        typ = (f.get("type") or "string").strip()
        item = dict(f)  # 保留 items / format / itemType 等附加信息
        if typ == "hex(string)":
            typ = "string"
            item.setdefault("format", "hex")
        elif typ == "array[object]":
            typ = "array"
            item.setdefault("itemType", "object")
        elif typ == "array[string]":
            typ = "array"
            item.setdefault("itemType", "string")
        elif typ in ("int", "long", "uint", "dword", "qword"):
            typ = "number"
        if name.endswith("Hex") or name in ("addressHex", "valueHex", "baseAddress"):
            item.setdefault("format", "hex")
        item["field"], item["type"] = name, typ
        out.append(item)
    return out


def enrich(catalog: Dict[str, Dict[str, Any]], cpp: CppIndex,
           sdk: Dict[str, Dict[str, Dict[str, Any]]],
           bp_table: Dict[str, Tuple[str, str]],
           check_only: bool) -> Tuple[int, List[str]]:
    gaps: List[str] = []

    for iface, info in catalog.items():
        sdk_params = sdk.get(iface, {})
        usage = f"{info.get('usage', '')} {info.get('desc', '')}"

        # ---- 参数 ----
        params = list(info.get("params") or [])
        seen = set()
        for p in params:
            key = p.get("name", "")
            seen.add(key)
            if is_weak(p.get("desc", "")):
                p["desc"] = param_desc(iface, key, usage)
            meta = sdk_params.get(key)
            if meta:
                p.setdefault("type", meta["type"])
                p.setdefault("required", meta["required"])
            else:
                p.setdefault("type", PARAM_TYPES.get(key, "string"))
                p.setdefault("required", False)

        # 只登记源码里真实解析、且接口用途/词典能说明的参数别名；
        # 噪声大的共享处理块（flag 很多）不做自动补登记，避免把无关开关写成参数。
        block = cpp.blocks.get(iface, {})
        flag_names = [f[2:] for f in block.get("flags", [])]
        if 0 < len(flag_names) <= 10:
            usage_flags = set(re.findall(r'--([A-Za-z][A-Za-z0-9_]*)\s*<', usage))
            for key in flag_names:
                if key in seen or key in ("interface",):
                    continue
                if key not in usage_flags and key not in KEY_DESC:
                    continue
                seen.add(key)
                params.append({
                    "name": key,
                    "desc": param_desc(iface, key, usage),
                    "type": PARAM_TYPES.get(key, "string"),
                    "required": False,
                })

        info["params"] = params

        # ---- 返回字段 ----
        existing = info.get("fields") or []
        existing_names = {f.get("field") for f in existing}
        only_standard = existing_names and existing_names <= {"state", "message"}
        need_fields = not existing or only_standard
        if need_fields:
            keys, nested = cpp.keys_of(iface)
            extra = set(keys) - {"state", "message"}
            # 已有 state/message 且源码里也没有额外字段时，视为真实的最小返回，保持原样
            if need_fields and (extra or not existing):
                keys.setdefault("state", "bool")
                keys.setdefault("message", "string")
                fields: List[Dict[str, Any]] = []
                array_fields = [k for k, v in keys.items() if v == "array"]
                # 只有一个数组字段时，元素字段可可靠归属；多个数组各自身结构不同，不做错误归并
                attach_items = nested if len(array_fields) == 1 else []
                for name, typ in sorted(keys.items(),
                                        key=lambda kv: (kv[0] not in ("state", "message"), kv[0])):
                    item = {"field": name, "type": typ}
                    if typ == "array" and attach_items:
                        item["items"] = list(attach_items)
                    fields.append(item)
                info["fields"] = fields

        # ---- outputs ----
        if not info.get("outputs"):
            info["outputs"] = [f.get("field") for f in info.get("fields", []) if f.get("field")]

        # ---- 字段类型归一化（历史数据里有 hex(string)/array[object] 等写法） ----
        info["fields"] = normalize_fields(info.get("fields") or [])

        # ---- 校验 ----
        for p in info["params"]:
            if is_weak(p.get("desc", "")):
                gaps.append(f"{iface}.{p.get('name')}: 参数说明缺失")
        if not info.get("fields"):
            gaps.append(f"{iface}: 返回结构缺失")

    # ---- 断点属性命令（通用入口） ----
    for iface, (kind, attr) in bp_table.items():
        info = catalog.get(iface)
        if not info:
            gaps.append(f"{iface}: 清单缺失")
            continue
        p: List[Dict[str, Any]] = []
        for name, desc, typ, req in BP_KIND_PARAMS.get(kind, []):
            p.append({"name": name, "desc": desc, "type": typ, "required": req})
        for name, desc, typ, req in BP_ATTR_PARAMS.get(attr, []):
            p.append({"name": name, "desc": desc, "type": typ, "required": req})
        info["params"] = p

        f: List[Dict[str, Any]] = [
            {"field": "state", "type": "bool"},
            {"field": "attribute", "type": "string"},
        ]
        if attr in ("BAK_HITCOUNT", "BAK_RESET_HITCOUNT"):
            f.append({"field": "hitCount", "type": "number"})
        else:
            f.append({"field": "value", "type": "string"})
        if kind == "BPK_LIBRARIAN":
            f.extend([{"field": "dll", "type": "string"}, {"field": "api", "type": "string"}])
        elif kind == "BPK_EXCEPTION":
            f.append({"field": "code", "type": "string"})
        else:
            f.append({"field": "address", "type": "string"})
        f.append({"field": "message", "type": "string"})
        info["fields"] = f
        info["outputs"] = [x["field"] for x in f]

    return len(gaps), gaps


def coverage(catalog: Dict[str, Dict[str, Any]]) -> Dict[str, int]:
    total = len(catalog)
    p_total = p_doc = 0
    for info in catalog.values():
        for p in info.get("params", []):
            p_total += 1
            if not is_weak(p.get("desc", "")):
                p_doc += 1
    return {
        "interfaces": total,
        "params": p_total,
        "params_documented": p_doc,
        "interfaces_with_fields": sum(1 for v in catalog.values() if v.get("fields")),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="补全 binsentry_interfaces.json 的调用信息")
    parser.add_argument("--check", action="store_true", help="只报告缺口，不写文件")
    parser.add_argument("--verbose", action="store_true", help="打印全部缺口")
    args = parser.parse_args()

    catalog = json.loads(TARGET.read_text(encoding="utf-8"))
    cpp = CppIndex()
    sdk = sdk_param_info()
    bp_table = load_bp_attr_table()

    gap_count, gaps = enrich(catalog, cpp, sdk, bp_table, args.check)
    cov = coverage(catalog)

    print(f"[enrich] 接口 {cov['interfaces']} 条 | 参数 {cov['params']} 个 | "
          f"参数有说明 {cov['params_documented']}/{cov['params']} | "
          f"有返回结构 {cov['interfaces_with_fields']}/{cov['interfaces']}")
    print(f"[enrich] C++ 派发块 {len(cpp.blocks)} 个 | 断点属性命令 {len(bp_table)} 条 | "
          f"SDK 接口签名 {len(sdk)} 条")
    if gaps:
        print(f"[enrich] 缺口 {len(gaps)} 处")
        for g in (gaps if args.verbose else gaps[:20]):
            print("  -", g)
    else:
        print("[enrich] 无缺口：全部参数有语义说明，全部接口有返回结构")

    if args.check:
        print("[enrich] --check：未写入")
        return 0 if not gaps else 1

    TARGET.write_text(json.dumps(catalog, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"[enrich] 已写入 {TARGET.name}（{TARGET.stat().st_size / 1024:.0f} KB）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
