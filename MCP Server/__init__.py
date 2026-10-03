import json
import socket
from urllib.parse import urlparse
from typing import List, Dict, Union, Optional, Callable
from functools import wraps

def check_server_available(func: Callable) -> Callable:
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if not self.config.is_server_available():
            return json.dumps({
                "status": "error",
                "message": "Server unavailable"
            }, ensure_ascii=False)
        return func(self, *args, **kwargs)
    return wrapper

def validate_hex_address(address: Union[int, str]) -> Optional[str]:
    if isinstance(address, int):
        return hex(address)
    addr_str = str(address).strip()
    if not addr_str:
        return None
    if addr_str.startswith(('0x', '0X')):
        try:
            int(addr_str, 16)
            return addr_str
        except ValueError:
            return None
    try:
        int(addr_str, 10)
        return addr_str
    except ValueError:
        return None

DEFAULT_API_KEY = "45d3552b12b12cdf2c831344311cf81e"


class Config:
    def __init__(self, address: str = "127.0.0.1", port: int = 6891,
                 api_key: Optional[str] = None):
        self.address = address
        self.port = port
        self.server_addr = f"http://{address}:{port}"
        self.api_key = api_key or DEFAULT_API_KEY
        self.timeout = 5

    def set_server(self, address: str, port: int = 6891) -> None:
        self.address = address
        self.port = port
        self.server_addr = f"http://{address}:{port}"

    def set_api_key(self, api_key: str) -> None:
        self.api_key = api_key or DEFAULT_API_KEY

    def is_server_available(self, timeout: Optional[int] = None) -> bool:
        timeout = timeout or self.timeout
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((self.address, self.port))
                return result == 0
        except socket.error as e:
            print(f"WARNING: Server check failed: {str(e)}")
            return False

class BaseHttpClient:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        parsed_url = urlparse(self.config.server_addr)
        self.address = parsed_url.hostname
        self.port = parsed_url.port
        self.scheme = parsed_url.scheme
        self.path = parsed_url.path or '/'
        self.verify_ssl = True

    def set_server(self, address: str, port: int = 6891) -> None:
        self.config.set_server(address, port)
        self.address = address
        self.port = port

    def custom_post(self, payload: Optional[Dict] = None, timeout: Optional[int] = None) -> str:
        import http.client
        headers = {"Content-Type": "application/json",
                   "X-API-Key": getattr(self.config, "api_key", "") or DEFAULT_API_KEY}
        body = json.dumps(payload).encode("utf-8") if payload else None
        timeout = timeout or self.config.timeout
        try:
            if self.scheme == "https":
                import ssl
                context = ssl._create_unverified_context() if not self.verify_ssl else None
                conn = http.client.HTTPSConnection(self.address, self.port, timeout=timeout, context=context)
            else:
                conn = http.client.HTTPConnection(self.address, self.port, timeout=timeout)
            conn.request("POST", self.path, body=body, headers=headers)
            response = conn.getresponse()
            response_text = response.read().decode("utf-8", errors="ignore")
            conn.close()
            return response_text
        except socket.timeout:
            return json.dumps({"status": "error", "message": "Request timed out"}, ensure_ascii=False)
        except ConnectionRefusedError:
            return json.dumps({"status": "error", "message": "Connection refused by server"}, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"status": "error", "message": f"Request failed: {str(e)}"}, ensure_ascii=False)

class SystemApi(BaseHttpClient):
    @check_server_available
    def system_info(self) -> str:
        return self.custom_post({"interface": "SystemInfo", "params": {}})

    @check_server_available
    def process_list(self) -> str:
        return self.custom_post({"interface": "ProcessList", "params": {}})

    @check_server_available
    def enum_windows(self, pid: int) -> str:
        return self.custom_post({"interface": "EnumWindows", "params": {"pid": pid}})

    @check_server_available
    def is_process_elevated(self) -> str:
        return self.custom_post({"interface": "IsProcessElevated", "params": {}})

    @check_server_available
    def enum_error_codes(self) -> str:
        return self.custom_post({"interface": "EnumErrorCodes", "params": {}})

    @check_server_available
    def enum_exceptions(self) -> str:
        return self.custom_post({"interface": "EnumExceptions", "params": {}})

    @check_server_available
    def help(self) -> str:
        return self.custom_post({"interface": "Help", "params": {}})

    @check_server_available
    def get_jit(self) -> str:
        return self.custom_post({"interface": "GetJIT", "params": {}})

    @check_server_available
    def set_jit(self, path: str) -> str:
        return self.custom_post({"interface": "SetJIT", "params": {"path": path}})

    @check_server_available
    def get_command_line(self) -> str:
        return self.custom_post({"interface": "GetCommandLine", "params": {}})

    @check_server_available
    def set_command_line(self, args: str) -> str:
        return self.custom_post({"interface": "SetCommandLine", "params": {"args": args}})

    @check_server_available
    def tcp_connections(self) -> str:
        return self.custom_post({"interface": "TCPConnections", "params": {}})

    @check_server_available
    def process_info(self, pid: int = 0) -> str:
        return self.custom_post({"interface": "ProcessInfo", "params": {"pid": pid}})

    @check_server_available
    def syscall_name(self, index: int) -> str:
        return self.custom_post({"interface": "SyscallName", "params": {"index": index}})

    @check_server_available
    def syscall_index(self, name: str) -> str:
        return self.custom_post({"interface": "SyscallIndex", "params": {"name": name}})

    @check_server_available
    def syscall_table(self, count: int = 0) -> str:
        payload: Dict = {}
        if count:
            payload["count"] = count
        return self.custom_post({"interface": "SyscallTable", "params": payload})

    @check_server_available
    def sys_command(self, command: str, shell: str = "cmd", timeout: int = 30, cwd: str = "") -> str:
        payload: Dict = {"command": command, "shell": shell, "timeout": timeout}
        if cwd:
            payload["cwd"] = cwd
        return self.custom_post({"interface": "SysCommand", "params": payload})

class LogConfigApi(BaseHttpClient):
    @check_server_available
    def clear_log(self) -> str:
        return self.custom_post({"interface": "ClearLog", "params": {}})

    @check_server_available
    def logs(self) -> str:
        return self.custom_post({"interface": "Logs", "params": {}})

    @check_server_available
    def save_log(self, path: str) -> str:
        return self.custom_post({"interface": "SaveLog", "params": {"path": path}})

    @check_server_available
    def load_database(self, path: str) -> str:
        return self.custom_post({"interface": "LoadDatabase", "params": {"path": path}})

    @check_server_available
    def save_database(self, path: str) -> str:
        return self.custom_post({"interface": "SaveDatabase", "params": {"path": path}})

    @check_server_available
    def load_config(self, module: str) -> str:
        return self.custom_post({"interface": "LoadConfig", "params": {"module": module}})

class SymbolVarApi(BaseHttpClient):
    @check_server_available
    def set_var(self, name: str, value: str) -> str:
        return self.custom_post({"interface": "SetVar", "params": {"name": name, "value": value}})

    @check_server_available
    def del_var(self, name: str) -> str:
        return self.custom_post({"interface": "DelVar", "params": {"name": name}})

    @check_server_available
    def get_vars(self) -> str:
        return self.custom_post({"interface": "GetVars", "params": {}})

    @check_server_available
    def add_argument(self, start: Union[int, str], end: Union[int, str] = "", name: str = "") -> str:
        start_addr = validate_hex_address(start)
        payload: Dict = {"start": start_addr}
        if end:
            payload["end"] = validate_hex_address(end)
        if name:
            payload["name"] = name
        return self.custom_post({"interface": "AddArgument", "params": payload})

    @check_server_available
    def del_argument(self, start: Union[int, str]) -> str:
        s = validate_hex_address(start)
        return self.custom_post({"interface": "DelArgument", "params": {"start": s}})

    @check_server_available
    def get_arguments(self) -> str:
        return self.custom_post({"interface": "GetArguments", "params": {}})

    @check_server_available
    def get_comments(self) -> str:
        return self.custom_post({"interface": "GetComments", "params": {}})

    @check_server_available
    def get_labels(self) -> str:
        return self.custom_post({"interface": "GetLabels", "params": {}})

    @check_server_available
    def get_bookmarks(self) -> str:
        return self.custom_post({"interface": "GetBookMarks", "params": {}})

    @check_server_available
    def functions(self) -> str:
        return self.custom_post({"interface": "Functions", "params": {}})

    @check_server_available
    def set_label(self, address: Union[int, str], name: str) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "SetLabel", "params": {"address": addr, "name": name}})

    @check_server_available
    def del_label(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "DelLabel", "params": {"address": addr}})

    @check_server_available
    def set_comment(self, address: Union[int, str], text: str) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "SetComment", "params": {"address": addr, "text": text}})

    @check_server_available
    def del_comment(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "DelComment", "params": {"address": addr}})

    @check_server_available
    def set_watch(self, name: str, expr: str) -> str:
        return self.custom_post({"interface": "SetWatch", "params": {"name": name, "expr": expr}})

    @check_server_available
    def del_watch(self, watch_id: int = 0, name: str = "") -> str:
        payload: Dict = {}
        if watch_id:
            payload["id"] = watch_id
        if name:
            payload["name"] = name
        return self.custom_post({"interface": "DelWatch", "params": payload})

    @check_server_available
    def get_watches(self) -> str:
        return self.custom_post({"interface": "GetWatches", "params": {}})

    @check_server_available
    def set_bookmark(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "SetBookMark", "params": {"address": addr}})

    @check_server_available
    def del_bookmark(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "DelBookMark", "params": {"address": addr}})

    @check_server_available
    def add_function(self, start: Union[int, str], end: Union[int, str] = "", name: str = "") -> str:
        start_addr = validate_hex_address(start)
        payload: Dict = {"start": start_addr}
        if end:
            payload["end"] = validate_hex_address(end)
        if name:
            payload["name"] = name
        return self.custom_post({"interface": "AddFunction", "params": payload})

    @check_server_available
    def del_function(self, start: Union[int, str]) -> str:
        s = validate_hex_address(start)
        return self.custom_post({"interface": "DelFunction", "params": {"start": s}})

    @check_server_available
    def undecorate_symbol(self, name: str) -> str:
        return self.custom_post({"interface": "UndecorateSymbol", "params": {"name": name}})

    @check_server_available
    def add_type(self, def_: str) -> str:
        return self.custom_post({"interface": "AddType", "params": {"def": def_}})

    @check_server_available
    def del_type(self, name: str) -> str:
        return self.custom_post({"interface": "DelType", "params": {"name": name}})

    @check_server_available
    def get_types(self) -> str:
        return self.custom_post({"interface": "GetTypes", "params": {}})

    @check_server_available
    def get_type_info(self, name: str) -> str:
        return self.custom_post({"interface": "GetTypeInfo", "params": {"name": name}})

    @check_server_available
    def get_addr_info(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "GetAddrInfo", "params": {"address": addr}})

class BreakPointApi(BaseHttpClient):
    @check_server_available
    def show_breakpoint(self) -> str:
        return self.custom_post({"interface": "ShowBreakPoint", "params": {}})

    @check_server_available
    def show_hbreakpoint(self) -> str:
        return self.custom_post({"interface": "ShowHbreakPoint", "params": {}})

    @check_server_available
    def show_mem_breakpoint(self) -> str:
        return self.custom_post({"interface": "ShowMemBreakPoint", "params": {}})

    @check_server_available
    def show_api_breakpoint(self) -> str:
        return self.custom_post({"interface": "ShowApiBreakPoint", "params": {}})

    @check_server_available
    def set_bpx_options(self, option: str, enable: int) -> str:
        return self.custom_post({"interface": "SetBPXOptions", "params": {"option": option, "enable": enable}})

    @check_server_available
    def set_exception_bpx(self, code: str) -> str:
        return self.custom_post({"interface": "SetExceptionBPX", "params": {"code": code}})

    @check_server_available
    def del_exception_bpx(self, code: str) -> str:
        return self.custom_post({"interface": "DelExceptionBPX", "params": {"code": code}})

    @check_server_available
    def get_exception_bpx_list(self) -> str:
        return self.custom_post({"interface": "GetExceptionBPXList", "params": {}})

    @check_server_available
    def set_dll_breakpoint(self, dll: str) -> str:
        return self.custom_post({"interface": "SetDllBreakPoint", "params": {"dll": dll}})

    @check_server_available
    def del_dll_breakpoint(self, dll: str) -> str:
        return self.custom_post({"interface": "DelDllBreakPoint", "params": {"dll": dll}})

    @check_server_available
    def get_dll_breakpoints(self) -> str:
        return self.custom_post({"interface": "GetDllBreakPoints", "params": {}})

    @check_server_available
    def set_breakpoint(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "SetBreakPoint", "params": {"address": addr}})

    @check_server_available
    def del_breakpoint(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "DelBreakPoint", "params": {"address": addr}})

    @check_server_available
    def get_breakpoint_info(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "GetBreakpointInfo", "params": {"address": addr}})

    @check_server_available
    def get_breakpoint_type(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "GetBreakpointType", "params": {"address": addr}})

    @check_server_available
    def set_breakpoint_name(self, address: Union[int, str], name: str) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "SetBreakpointName", "params": {"address": addr, "name": name}})

    @check_server_available
    def set_breakpoint_singleshoot(self, address: Union[int, str], enable: int = 0) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "SetBreakpointSingleshoot", "params": {"address": addr, "enable": enable}})

    @check_server_available
    def set_breakpoint_fast_resume(self, address: Union[int, str], enable: int = 0) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "SetBreakpointFastResume", "params": {"address": addr, "enable": enable}})

    @check_server_available
    def set_breakpoint_silent(self, address: Union[int, str], enable: int = 0) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "SetBreakpointSilent", "params": {"address": addr, "enable": enable}})

    @check_server_available
    def set_breakpoint_log(self, address: Union[int, str], text: str) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "SetBreakpointLog", "params": {"address": addr, "text": text}})

    @check_server_available
    def set_breakpoint_log_file(self, address: Union[int, str], file: str) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "SetBreakpointLogFile", "params": {"address": addr, "file": file}})

    @check_server_available
    def set_breakpoint_hit_count(self, address: Union[int, str], count: int) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "SetBreakpointHitCount", "params": {"address": addr, "count": count}})

    @check_server_available
    def get_breakpoint_hit_count(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "GetBreakpointHitCount", "params": {"address": addr}})

    @check_server_available
    def reset_breakpoint_hit_count(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "ResetBreakpointHitCount", "params": {"address": addr}})

    @check_server_available
    def set_cond_breakpoint(self, address: Union[int, str], cond: str, thread: int = 0) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "SetCondBreakPoint", "params": {"address": addr, "cond": cond, "thread": thread}})

    @check_server_available
    def del_cond_breakpoint(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "DelCondBreakPoint", "params": {"address": addr}})

    @check_server_available
    def set_hbreakpoint(self, address: Union[int, str], len_: str = "1", flag: str = "e") -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "SetHbreakPoint", "params": {"address": addr, "len": len_, "flag": flag}})

    @check_server_available
    def del_hbreakpoint(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "DelHbreakPoint", "params": {"address": addr}})

    @check_server_available
    def set_mem_breakpoint(self, address: Union[int, str], flag: str = "e") -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "SetMemBreakPoint", "params": {"address": addr, "flag": flag}})

    @check_server_available
    def del_mem_breakpoint(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "DelMemBreakPoint", "params": {"address": addr}})

    @check_server_available
    def set_api_breakpoint(self, dll: str, api: str) -> str:
        return self.custom_post({"interface": "SetApiBreakPoint", "params": {"dll": dll, "api": api}})

    @check_server_available
    def del_api_breakpoint(self, dll: str, api: str) -> str:
        return self.custom_post({"interface": "DelApiBreakPoint", "params": {"dll": dll, "api": api}})

    @check_server_available
    def disable_breakpoint(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "DisableBreakpoint", "params": {"address": addr}})

    @check_server_available
    def enable_breakpoint(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "EnableBreakpoint", "params": {"address": addr}})

    @check_server_available
    def breakpoint_command(self, address: Union[int, str], command: str = "") -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "BreakpointCommand", "params": {"address": addr, "command": command}})

    @check_server_available
    def set_exception_ignore(self, code: str, ignore: int = 1) -> str:
        return self.custom_post({"interface": "SetExceptionIgnore", "params": {"code": code, "ignore": ignore}})

    @check_server_available
    def get_exception_settings(self) -> str:
        return self.custom_post({"interface": "GetExceptionSettings", "params": {}})

    @check_server_available
    def is_bpx_enabled(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "IsBPXEnabled", "params": {"address": addr}})

    @check_server_available
    def enable_bpx(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "EnableBPX", "params": {"address": addr}})

    @check_server_available
    def disable_bpx(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "DisableBPX", "params": {"address": addr}})

    @check_server_available
    def remove_all_breakpoints(self, option: int = 0) -> str:
        return self.custom_post({"interface": "RemoveAllBreakPoints", "params": {"option": option}})

    @check_server_available
    def safe_delete_bpx(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "SafeDeleteBPX", "params": {"address": addr}})

    @check_server_available
    def set_api_breakpoint_titan(self, dll: str, api: str, end: bool = False) -> str:
        payload: Dict = {"dll": dll, "api": api}
        if end:
            payload["end"] = True
        return self.custom_post({"interface": "SetAPIBreakPoint", "params": payload})

    @check_server_available
    def del_api_breakpoint_titan(self, dll: str, api: str, end: bool = False) -> str:
        payload: Dict = {"dll": dll, "api": api}
        if end:
            payload["end"] = True
        return self.custom_post({"interface": "DeleteAPIBreakPoint", "params": payload})

class DebugSessionApi(BaseHttpClient):
    @check_server_available
    def debug(self, path: str, args: str = "", cwd: str = "") -> str:
        return self.custom_post({"interface": "Debug", "params": {"path": path, "args": args, "cwd": cwd}})

    @check_server_available
    def debug_dll(self, path: str, args: str = "", cwd: str = "", entry: str = "") -> str:
        payload: Dict = {"path": path, "args": args, "cwd": cwd}
        if entry:
            payload["entry"] = entry
        return self.custom_post({"interface": "DebugDll", "params": payload})

    @check_server_available
    def set_debug(self, command: str = "Logs") -> str:
        return self.custom_post({"interface": "SetDebug", "params": command})

    @check_server_available
    def stop(self) -> str:
        return self.custom_post({"interface": "Stop", "params": {}})

    @check_server_available
    def detach(self) -> str:
        return self.custom_post({"interface": "Detach", "params": {}})

    @check_server_available
    def detach_debugger_ex(self) -> str:
        return self.custom_post({"interface": "DetachDebuggerEx", "params": {}})

    @check_server_available
    def restart(self) -> str:
        return self.custom_post({"interface": "Restart", "params": {}})

    @check_server_available
    def dump_process(self, path: str, base: Union[int, str], size: int) -> str:
        base_addr = validate_hex_address(base)
        return self.custom_post({"interface": "DumpProcess", "params": {"path": path, "base": base_addr, "size": size}})

    @check_server_available
    def minidump(self, path: str) -> str:
        return self.custom_post({"interface": "minidump", "params": {"path": path}})

    @check_server_available
    def status(self) -> str:
        return self.custom_post({"interface": "Status", "params": {}})

    @check_server_available
    def attach(self, pid: int) -> str:
        return self.custom_post({"interface": "Attach", "params": {"pid": pid}})

    @check_server_available
    def wait_stop(self, timeout: int = 60) -> str:
        return self.custom_post({"interface": "WaitStop", "params": {"timeout": timeout}})

    @check_server_available
    def get_debug_data(self) -> str:
        return self.custom_post({"interface": "GetDebugData", "params": {}})

    @check_server_available
    def is_file_being_debugged(self) -> str:
        return self.custom_post({"interface": "IsFileBeingDebugged", "params": {}})

    @check_server_available
    def set_engine_variable(self, name: str = "", engine_id: int = 0, enable: int = 1) -> str:
        payload: Dict = {"enable": enable}
        if name:
            payload["name"] = name
        if engine_id:
            payload["id"] = engine_id
        return self.custom_post({"interface": "SetEngineVariable", "params": payload})

    @check_server_available
    def engine_check_struct_alignment(self, struct: str = "TITAN_ENGINE_CONTEXT", size: int = 0) -> str:
        payload: Dict = {"struct": struct}
        if size:
            payload["size"] = size
        return self.custom_post({"interface": "EngineCheckStructAlignment", "params": payload})

    @check_server_available
    def attach_debugger(self, pid: int) -> str:
        return self.custom_post({"interface": "AttachDebugger", "params": {"pid": pid}})

    @check_server_available
    def detach_debugger(self) -> str:
        return self.custom_post({"interface": "DetachDebugger", "params": {}})

    @check_server_available
    def stop_debug(self) -> str:
        return self.custom_post({"interface": "StopDebug", "params": {}})

    @check_server_available
    def force_close(self) -> str:
        return self.custom_post({"interface": "ForceClose", "params": {}})

    @check_server_available
    def get_debugged_file_base_address(self) -> str:
        return self.custom_post({"interface": "GetDebuggedFileBaseAddress", "params": {}})

    @check_server_available
    def get_debugged_dll_base_address(self) -> str:
        return self.custom_post({"interface": "GetDebuggedDLLBaseAddress", "params": {}})

class RegisterThreadApi(BaseHttpClient):
    @check_server_available
    def register(self) -> str:
        return self.custom_post({"interface": "Register", "params": {}})

    @check_server_available
    def set_register(self, reg: str, value: str) -> str:
        return self.custom_post({"interface": "SetRegister", "params": {"reg": reg, "value": value}})

    @check_server_available
    def threads(self) -> str:
        return self.custom_post({"interface": "Threads", "params": {}})

    @check_server_available
    def thread_info(self, tid: int) -> str:
        return self.custom_post({"interface": "ThreadInfo", "params": {"tid": tid}})

    @check_server_available
    def get_active_thread(self) -> str:
        return self.custom_post({"interface": "GetActiveThread", "params": {}})

    @check_server_available
    def set_active_thread(self, tid: int) -> str:
        return self.custom_post({"interface": "SetActiveThread", "params": {"tid": tid}})

    @check_server_available
    def get_thread_last_error(self, tid: int) -> str:
        return self.custom_post({"interface": "GetThreadLastError", "params": {"tid": tid}})

    @check_server_available
    def get_thread_priority(self, tid: int) -> str:
        return self.custom_post({"interface": "GetThreadPriority", "params": {"tid": tid}})

    @check_server_available
    def set_thread_priority(self, tid: int, priority: str = "NORMAL") -> str:
        return self.custom_post({"interface": "SetThreadPriority", "params": {"tid": tid, "priority": priority}})

    @check_server_available
    def set_thread_name(self, tid: int, name: str) -> str:
        return self.custom_post({"interface": "SetThreadName", "params": {"tid": tid, "name": name}})

    @check_server_available
    def set_flag(self, flag: str, value: int) -> str:
        return self.custom_post({"interface": "SetFlag", "params": {"flag": flag, "value": value}})

    @check_server_available
    def create_remote_thread(self, start: Union[int, str] = "", hex_: str = "", param: Union[int, str] = "") -> str:
        payload: Dict = {}
        if start:
            payload["start"] = validate_hex_address(start)
        if hex_:
            payload["hex"] = hex_
        if param:
            payload["param"] = validate_hex_address(param)
        return self.custom_post({"interface": "CreateRemoteThread", "params": payload})

    @check_server_available
    def terminate_thread(self, tid: int) -> str:
        return self.custom_post({"interface": "TerminateThread", "params": {"tid": tid}})

    @check_server_available
    def get_full_context(self) -> str:
        return self.custom_post({"interface": "GetFullContext", "params": {}})

    @check_server_available
    def set_full_context(self, regs: Union[str, List[str]]) -> str:
        if isinstance(regs, (list, tuple)):
            return self.custom_post({"interface": "SetFullContext", "params": ["--reg " + r for r in regs]})
        return self.custom_post({"interface": "SetFullContext", "params": {"reg": regs}})

    @check_server_available
    def get_avx_context(self) -> str:
        return self.custom_post({"interface": "GetAVXContext", "params": {}})

    @check_server_available
    def set_avx_context(self, ymms: Union[str, List[str]]) -> str:
        if isinstance(ymms, (list, tuple)):
            return self.custom_post({"interface": "SetAVXContext", "params": ["--ymm " + y for y in ymms]})
        return self.custom_post({"interface": "SetAVXContext", "params": {"ymm": ymms}})

    @check_server_available
    def get_avx512_context(self) -> str:
        return self.custom_post({"interface": "GetAVX512Context", "params": {}})

    @check_server_available
    def set_avx512_context(self, zmms: Union[str, List[str]] = "", opmasks: Union[str, List[str]] = "") -> str:
        parts: List[str] = []
        if isinstance(zmms, (list, tuple)):
            parts += ["--zmm " + z for z in zmms]
        elif zmms:
            parts.append("--zmm " + zmms)
        if isinstance(opmasks, (list, tuple)):
            parts += ["--opmask " + o for o in opmasks]
        elif opmasks:
            parts.append("--opmask " + opmasks)
        if parts:
            return self.custom_post({"interface": "SetAVX512Context", "params": parts})
        return self.custom_post({"interface": "SetAVX512Context", "params": {}})

    @check_server_available
    def get_peb_location(self) -> str:
        return self.custom_post({"interface": "GetPEBLocation", "params": {}})

    @check_server_available
    def get_teb_location(self, tid: int = 0) -> str:
        return self.custom_post({"interface": "GetTEBLocation", "params": {"tid": tid}})

    @check_server_available
    def titan_open_process(self, pid: int, access: int = 0) -> str:
        payload: Dict = {"pid": pid}
        if access:
            payload["access"] = access
        return self.custom_post({"interface": "TitanOpenProcess", "params": payload})

    @check_server_available
    def titan_open_thread(self, tid: int, access: int = 0) -> str:
        payload: Dict = {"tid": tid}
        if access:
            payload["access"] = access
        return self.custom_post({"interface": "TitanOpenThread", "params": payload})

    @check_server_available
    def threader_get_thread_info(self, tid: int = 0) -> str:
        return self.custom_post({"interface": "ThreaderGetThreadInfo", "params": {"tid": tid}})

    @check_server_available
    def threader_is_thread_active(self, tid: int = 0) -> str:
        return self.custom_post({"interface": "ThreaderIsThreadActive", "params": {"tid": tid}})

    @check_server_available
    def threader_pause_process(self) -> str:
        return self.custom_post({"interface": "ThreaderPauseProcess", "params": {}})

    @check_server_available
    def threader_resume_process(self) -> str:
        return self.custom_post({"interface": "ThreaderResumeProcess", "params": {}})

    @check_server_available
    def threader_is_exception_in_main_thread(self) -> str:
        return self.custom_post({"interface": "ThreaderIsExceptionInMainThread", "params": {}})

    @check_server_available
    def get_peb_location64(self) -> str:
        return self.custom_post({"interface": "GetPEBLocation64", "params": {}})

    @check_server_available
    def get_teb_location64(self, tid: int = 0) -> str:
        return self.custom_post({"interface": "GetTEBLocation64", "params": {"tid": tid}})

    @check_server_available
    def get_mmx_registers(self) -> str:
        return self.custom_post({"interface": "GetMMXRegisters", "params": {}})

    @check_server_available
    def get_function_parameter(self, type_: str = "STDCALL", index: int = 1, ptype: int = 0) -> str:
        payload: Dict = {"type": type_, "index": index}
        if ptype:
            payload["ptype"] = ptype
        return self.custom_post({"interface": "GetFunctionParameter", "params": payload})

    @check_server_available
    def threader_is_thread_still_running(self, tid: int = 0) -> str:
        return self.custom_post({"interface": "ThreaderIsThreadStillRunning", "params": {"tid": tid}})

class ModulePeApi(BaseHttpClient):
    @check_server_available
    def modules(self) -> str:
        return self.custom_post({"interface": "Modules", "params": {}})

    @check_server_available
    def module_info(self, module: str) -> str:
        return self.custom_post({"interface": "ModuleInfo", "params": {"module": module}})

    @check_server_available
    def sections(self, module: str) -> str:
        return self.custom_post({"interface": "Sections", "params": {"module": module}})

    @check_server_available
    def pe_info(self, path: str) -> str:
        return self.custom_post({"interface": "PEInfo", "params": {"path": path}})

    @check_server_available
    def rich_header(self, module: str) -> str:
        return self.custom_post({"interface": "RichHeader", "params": {"module": module}})

    @check_server_available
    def tls_callbacks(self, module: str) -> str:
        return self.custom_post({"interface": "TLSCallbacks", "params": {"module": module}})

    @check_server_available
    def relocation_list(self, module: str) -> str:
        return self.custom_post({"interface": "RelocationList", "params": {"module": module}})

    @check_server_available
    def debug_directory(self, module: str) -> str:
        return self.custom_post({"interface": "DebugDirectory", "params": {"module": module}})

    @check_server_available
    def import_list(self, module: str) -> str:
        return self.custom_post({"interface": "ImportList", "params": {"module": module}})

    @check_server_available
    def export_list(self, module: str) -> str:
        return self.custom_post({"interface": "ExportList", "params": {"module": module}})

    @check_server_available
    def get_import_address(self, module: str, name: str) -> str:
        return self.custom_post({"interface": "GetImportAddress", "params": {"module": module, "name": name}})

    @check_server_available
    def get_export_address(self, module: str, name: str) -> str:
        return self.custom_post({"interface": "GetExportAddress", "params": {"module": module, "name": name}})

    @check_server_available
    def gpa(self, dll: str, api: str) -> str:
        return self.custom_post({"interface": "gpa", "params": {"dll": dll, "api": api}})

    @check_server_available
    def addr_to_module(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "AddrToModule", "params": {"address": addr}})

    @check_server_available
    def get_section_data(self, module: str, name: str) -> str:
        return self.custom_post({"interface": "GetSectionData", "params": {"module": module, "name": name}})

    @check_server_available
    def get_section_info(self, module: str, name: str) -> str:
        return self.custom_post({"interface": "GetSectionInfo", "params": {"module": module, "name": name}})

    @check_server_available
    def symbol(self, expr: str) -> str:
        return self.custom_post({"interface": "Symbol", "params": {"expr": expr}})

    @check_server_available
    def get_symbol_info(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "GetSymbolInfo", "params": {"address": addr}})

    @check_server_available
    def get_function_size(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "GetFunctionSize", "params": {"address": addr}})

    @check_server_available
    def heaps(self) -> str:
        return self.custom_post({"interface": "Heaps", "params": {}})

    @check_server_available
    def handles(self, max_num: int = 20) -> str:
        return self.custom_post({"interface": "Handles", "params": {"max": max_num}})

    @check_server_available
    def seh_list(self) -> str:
        return self.custom_post({"interface": "SEHList", "params": {}})

    @check_server_available
    def inject_dll(self, path: str) -> str:
        return self.custom_post({"interface": "InjectDll", "params": {"path": path}})

    @check_server_available
    def load_library(self, path: str) -> str:
        return self.custom_post({"interface": "LoadLibrary", "params": {"path": path}})

    @check_server_available
    def free_library(self, handle: int) -> str:
        return self.custom_post({"interface": "FreeLibrary", "params": {"handle": handle}})

    @check_server_available
    def analyse_module(self, module: str, start: Union[int, str] = "", size: int = 0, commit: int = 0) -> str:
        payload: Dict = {"module": module}
        if start:
            payload["start"] = validate_hex_address(start)
        if size:
            payload["size"] = size
        if commit:
            payload["commit"] = commit
        return self.custom_post({"interface": "AnalyseModule", "params": payload})

    @check_server_available
    def importer_get_nearest_api_address(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "ImporterGetNearestAPIAddress", "params": {"address": addr}})

    @check_server_available
    def remote_load_library(self, path: str, wait: int = 0) -> str:
        payload: Dict = {"path": path}
        if wait:
            payload["wait"] = wait
        return self.custom_post({"interface": "RemoteLoadLibrary", "params": payload})

    @check_server_available
    def remote_free_library(self, path: str, handle: int = 0, wait: int = 0) -> str:
        payload: Dict = {"path": path}
        if handle:
            payload["handle"] = handle
        if wait:
            payload["wait"] = wait
        return self.custom_post({"interface": "RemoteFreeLibrary", "params": payload})

    @check_server_available
    def static_file_load(self, path: str, write: bool = False) -> str:
        payload: Dict = {"path": path}
        if write:
            payload["write"] = True
        return self.custom_post({"interface": "StaticFileLoad", "params": payload})

    @check_server_available
    def static_file_unload(self, commit: bool = False) -> str:
        payload: Dict = {}
        if commit:
            payload["commit"] = True
        return self.custom_post({"interface": "StaticFileUnload", "params": payload})

    @check_server_available
    def importer_get_remote_dll_base(self, module: str) -> str:
        return self.custom_post({"interface": "ImporterGetRemoteDLLBase", "params": {"module": module}})

    @check_server_available
    def importer_is_forwarded_api(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "ImporterIsForwardedAPI", "params": {"address": addr}})

    @check_server_available
    def dump_module(self, module: Union[int, str], path: str) -> str:
        mod = validate_hex_address(module)
        return self.custom_post({"interface": "DumpModule", "params": {"module": mod, "path": path}})

    @check_server_available
    def is_file_dll(self, path: str) -> str:
        return self.custom_post({"interface": "IsFileDLL", "params": {"path": path}})

    @check_server_available
    def handler_close_remote_handle(self, handle: int) -> str:
        return self.custom_post({"interface": "HandlerCloseRemoteHandle", "params": {"handle": handle}})

    @check_server_available
    def realign_pe(self, path: str, mode: int = 0) -> str:
        payload: Dict = {"path": path}
        if mode:
            payload["mode"] = mode
        return self.custom_post({"interface": "RealignPE", "params": payload})

    @check_server_available
    def fix_header_checksum(self, path: str) -> str:
        return self.custom_post({"interface": "FixHeaderCheckSum", "params": {"path": path}})

    @check_server_available
    def load_pdb(self, path: str, base: Union[int, str] = "") -> str:
        payload: Dict = {"path": path}
        if base:
            payload["base"] = validate_hex_address(base)
        return self.custom_post({"interface": "LoadPDB", "params": payload})

    @check_server_available
    def unload_symbols(self) -> str:
        return self.custom_post({"interface": "UnloadSymbols", "params": {}})

    @check_server_available
    def enum_symbols(self, prefix: str = "", max_num: int = 500) -> str:
        payload: Dict = {}
        if prefix:
            payload["prefix"] = prefix
        if max_num:
            payload["max"] = max_num
        return self.custom_post({"interface": "EnumSymbols", "params": payload})

class MemoryApi(BaseHttpClient):
    @check_server_available
    def memory_info(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "MemoryInfo", "params": {"address": addr}})

    @check_server_available
    def regions(self) -> str:
        return self.custom_post({"interface": "Regions", "params": {}})

    @check_server_available
    def memory(self, address: Union[int, str], size: int = 16) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "Memory", "params": {"address": addr, "size": size}})

    @check_server_available
    def read_memory_value(self, address: Union[int, str], size: int = 4) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "ReadMemoryValue", "params": {"address": addr, "size": size}})

    @check_server_available
    def write_memory(self, address: Union[int, str], hex_: str) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "WriteMemory", "params": {"address": addr, "hex": hex_}})

    @check_server_available
    def get_page_rights(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "GetPageRights", "params": {"address": addr}})

    @check_server_available
    def set_page_rights(self, address: Union[int, str], protect: str) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "SetPageRights", "params": {"address": addr, "protect": protect}})

    @check_server_available
    def set_page_memory(self, address: Union[int, str], protect: str) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "SetPageMemory", "params": {"address": addr, "protect": protect}})

    @check_server_available
    def allocate_memory(self, size: int) -> str:
        return self.custom_post({"interface": "AllocateMemory", "params": {"size": size}})

    @check_server_available
    def free_memory(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "FreeMemory", "params": {"address": addr}})

    @check_server_available
    def set_memory(self, address: Union[int, str], hex_: str) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "SetMemory", "params": {"address": addr, "hex": hex_}})

    @check_server_available
    def fill_memory(self, address: Union[int, str], size: int, value: str) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "FillMemory", "params": {"address": addr, "size": size, "value": value}})

    @check_server_available
    def memcpy(self, src: Union[int, str], dst: Union[int, str], size: int) -> str:
        src_a = validate_hex_address(src)
        dst_a = validate_hex_address(dst)
        return self.custom_post({"interface": "Memcpy", "params": {"src": src_a, "dst": dst_a, "size": size}})

    @check_server_available
    def va_to_file_offset(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "VaToFileOffset", "params": {"address": addr}})

    @check_server_available
    def file_offset_to_va(self, offset: str) -> str:
        return self.custom_post({"interface": "FileOffsetToVa", "params": {"offset": offset}})

    @check_server_available
    def get_string(self, address: Union[int, str], max_num: int = 64, type_: str = "ascii") -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "GetString", "params": {"address": addr, "max": max_num, "type": type_}})

    @check_server_available
    def search_memory(self, pattern: str, start: Union[int, str], size: int) -> str:
        s = validate_hex_address(start)
        return self.custom_post({"interface": "SearchMemory", "params": {"pattern": pattern, "start": s, "size": size}})

    @check_server_available
    def search_all_memory(self, pattern: str, max_num: int = 5) -> str:
        return self.custom_post({"interface": "SearchAllMemory", "params": {"pattern": pattern, "max": max_num}})

    @check_server_available
    def search_strings(self, address: Union[int, str], size: int) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "SearchStrings", "params": {"address": addr, "size": size}})

    @check_server_available
    def match_pattern(self, address: Union[int, str], pattern: str, size: int) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "MatchPattern", "params": {"address": addr, "pattern": pattern, "size": size}})

    @check_server_available
    def hash_memory(self, address: Union[int, str], size: int, algo: str = "md5") -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "HashMemory", "params": {"address": addr, "size": size, "algo": algo}})

    @check_server_available
    def patch_memory(self, address: Union[int, str], hex_: str) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "PatchMemory", "params": {"address": addr, "hex": hex_}})

    @check_server_available
    def patches(self) -> str:
        return self.custom_post({"interface": "Patches", "params": {}})

    @check_server_available
    def revert_patch(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "RevertPatch", "params": {"address": addr}})

    @check_server_available
    def delete_patch(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "DeletePatch", "params": {"address": addr}})

    @check_server_available
    def is_valid_pointer(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "IsValidPointer", "params": {"address": addr}})

    @check_server_available
    def dump_memory(self, address: Union[int, str], size: int, path: str) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "DumpMemory", "params": {"address": addr, "size": size, "path": path}})

    @check_server_available
    def dump_regions(self, folder: str, above: bool = False) -> str:
        payload: Dict = {"folder": folder}
        if above:
            payload["above"] = True
        return self.custom_post({"interface": "DumpRegions", "params": payload})

    @check_server_available
    def watchdog_set(self, address: Union[int, str], size: int = 4, name: str = "") -> str:
        payload: Dict = {"address": validate_hex_address(address)}
        if size:
            payload["size"] = size
        if name:
            payload["name"] = name
        return self.custom_post({"interface": "WatchdogSet", "params": payload})

    @check_server_available
    def watchdog_check(self) -> str:
        return self.custom_post({"interface": "WatchdogCheck", "params": {}})

    @check_server_available
    def watchdog_clear(self, address: Union[int, str] = "") -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        return self.custom_post({"interface": "WatchdogClear", "params": payload})

    @check_server_available
    def encode_map(self, address: Union[int, str], size: int = 0) -> str:
        payload: Dict = {"address": validate_hex_address(address)}
        if size:
            payload["size"] = size
        return self.custom_post({"interface": "EncodeMap", "params": payload})

    @check_server_available
    def data_trace_set(self, address: Union[int, str], size: int = 0) -> str:
        payload: Dict = {"address": validate_hex_address(address)}
        if size:
            payload["size"] = size
        return self.custom_post({"interface": "DataTraceSet", "params": payload})

    @check_server_available
    def data_trace_clear(self, address: Union[int, str] = "") -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        return self.custom_post({"interface": "DataTraceClear", "params": payload})

    @check_server_available
    def get_data_trace(self) -> str:
        return self.custom_post({"interface": "GetDataTrace", "params": {}})

    @check_server_available
    def patch_file(self, path: str, patch: str) -> str:
        return self.custom_post({"interface": "PatchFile", "params": {"path": path, "patch": patch}})

class DisasmXrefApi(BaseHttpClient):
    @check_server_available
    def disassemble_at(self, address: Union[int, str], count: int = 5) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "DisassembleAt", "params": {"address": addr, "count": count}})

    @check_server_available
    def dissasembler(self, address: Union[int, str], count: int = 5) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "Dissasembler", "params": {"address": addr, "count": count}})

    @check_server_available
    def get_opcode_size(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "GetOpcodeSize", "params": {"address": addr}})

    @check_server_available
    def mnemonicbrief(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "mnemonicbrief", "params": {"address": addr}})

    @check_server_available
    def get_branch_target(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "GetBranchTarget", "params": {"address": addr}})

    @check_server_available
    def assemble(self, instr: str, cip: Union[int, str]) -> str:
        c = validate_hex_address(cip)
        return self.custom_post({"interface": "Assemble", "params": {"instr": instr, "cip": c}})

    @check_server_available
    def assemble_at(self, address: Union[int, str], instr: str) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "AssembleAt", "params": {"address": addr, "instr": instr}})

    @check_server_available
    def xrefs(self, address: Union[int, str], max_num: int = 5) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "xrefs", "params": {"address": addr, "max": max_num}})

    @check_server_available
    def find_ref(self, address: Union[int, str], max_num: int = 5) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "FindRef", "params": {"address": addr, "max": max_num}})

    @check_server_available
    def loop_analyse(self, address: Union[int, str], depth: int = 0) -> str:
        payload: Dict = {"address": validate_hex_address(address)}
        if depth:
            payload["depth"] = depth
        return self.custom_post({"interface": "LoopAnalyse", "params": payload})

    @check_server_available
    def static_disassemble(self, address: Union[int, str] = "") -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        return self.custom_post({"interface": "StaticDisassemble", "params": payload})

    @check_server_available
    def static_disassemble_ex(self, address: Union[int, str] = "") -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        return self.custom_post({"interface": "StaticDisassembleEx", "params": payload})

class StackTraceApi(BaseHttpClient):
    @check_server_available
    def call_stack(self, max_num: int = 16) -> str:
        return self.custom_post({"interface": "CallStack", "params": {"max": max_num}})

    @check_server_available
    def stack(self, count: int = 8) -> str:
        return self.custom_post({"interface": "Stack", "params": {"count": count}})

    @check_server_available
    def stack_push(self, value: str) -> str:
        return self.custom_post({"interface": "StackPush", "params": {"value": value}})

    @check_server_available
    def stack_pop(self) -> str:
        return self.custom_post({"interface": "StackPop", "params": {}})

    @check_server_available
    def stack_peek(self, offset: int = 0) -> str:
        return self.custom_post({"interface": "StackPeek", "params": {"offset": offset}})

    @check_server_available
    def start_trace_record(self) -> str:
        return self.custom_post({"interface": "StartTraceRecord", "params": {}})

    @check_server_available
    def get_trace_record(self, count: int = 5) -> str:
        return self.custom_post({"interface": "GetTraceRecord", "params": {"count": count}})

    @check_server_available
    def stop_trace_record(self) -> str:
        return self.custom_post({"interface": "StopTraceRecord", "params": {}})

    @check_server_available
    def jmp_history(self) -> str:
        return self.custom_post({"interface": "JmpHistory", "params": {}})

    @check_server_available
    def last_exception(self) -> str:
        return self.custom_post({"interface": "LastException", "params": {}})

    @check_server_available
    def eval_expr(self, expr: str) -> str:
        return self.custom_post({"interface": "Eval", "params": {"expr": expr}})

    @check_server_available
    def show_debugger(self) -> str:
        return self.custom_post({"interface": "ShowDebugger", "params": {}})

    @check_server_available
    def hide_debugger(self) -> str:
        return self.custom_post({"interface": "HideDebugger", "params": {}})

    @check_server_available
    def trace_set_log(self, condition: str, log: str = "") -> str:
        payload: Dict = {"condition": condition}
        if log:
            payload["log"] = log
        return self.custom_post({"interface": "TraceSetLog", "params": payload})

    @check_server_available
    def trace_set_condition(self, condition: str, log: str = "") -> str:
        payload: Dict = {"condition": condition}
        if log:
            payload["log"] = log
        return self.custom_post({"interface": "TraceSetCondition", "params": payload})

    @check_server_available
    def get_trace_log(self) -> str:
        return self.custom_post({"interface": "GetTraceLog", "params": {}})

    @check_server_available
    def trace_clear_log(self) -> str:
        return self.custom_post({"interface": "TraceClearLog", "params": {}})

    @check_server_available
    def history_start(self) -> str:
        return self.custom_post({"interface": "HistoryStart", "params": {}})

    @check_server_available
    def history_stop(self) -> str:
        return self.custom_post({"interface": "HistoryStop", "params": {}})

    @check_server_available
    def history_save(self) -> str:
        return self.custom_post({"interface": "HistorySave", "params": {}})

    @check_server_available
    def history_list(self) -> str:
        return self.custom_post({"interface": "HistoryList", "params": {}})

    @check_server_available
    def history_restore(self, index: int) -> str:
        return self.custom_post({"interface": "HistoryRestore", "params": {"index": index}})

    @check_server_available
    def history_clear(self) -> str:
        return self.custom_post({"interface": "HistoryClear", "params": {}})

class ExecutionControlApi(BaseHttpClient):
    @check_server_available
    def run(self) -> str:
        return self.custom_post({"interface": "Run", "params": {}})

    @check_server_available
    def pause(self) -> str:
        return self.custom_post({"interface": "Pause", "params": {}})

    @check_server_available
    def e_run(self) -> str:
        return self.custom_post({"interface": "ERun", "params": {}})

    @check_server_available
    def se_run(self) -> str:
        return self.custom_post({"interface": "SERun", "params": {}})

    @check_server_available
    def step_in(self) -> str:
        return self.custom_post({"interface": "StepIn", "params": {}})

    @check_server_available
    def step_over(self) -> str:
        return self.custom_post({"interface": "StepOver", "params": {}})

    @check_server_available
    def step_out(self) -> str:
        return self.custom_post({"interface": "StepOut", "params": {}})

    @check_server_available
    def e_step_into(self) -> str:
        return self.custom_post({"interface": "EStepInto", "params": {}})

    @check_server_available
    def e_step_over(self) -> str:
        return self.custom_post({"interface": "EStepOver", "params": {}})

    @check_server_available
    def e_step_out(self) -> str:
        return self.custom_post({"interface": "EStepOut", "params": {}})

    @check_server_available
    def step_user(self) -> str:
        return self.custom_post({"interface": "StepUser", "params": {}})

    @check_server_available
    def step_system(self) -> str:
        return self.custom_post({"interface": "StepSystem", "params": {}})

    @check_server_available
    def skip(self, count: int = 1) -> str:
        return self.custom_post({"interface": "Skip", "params": {"count": count}})

    @check_server_available
    def instr_undo(self) -> str:
        return self.custom_post({"interface": "InstrUndo", "params": {}})

    @check_server_available
    def execute_command(self, command: str) -> str:
        return self.custom_post({"interface": "ExecuteCommand", "params": command})

    @check_server_available
    def trace_into(self, count: int = 3) -> str:
        return self.custom_post({"interface": "TraceInto", "params": {"count": count}})

    @check_server_available
    def trace_over(self, count: int = 3) -> str:
        return self.custom_post({"interface": "TraceOver", "params": {"count": count}})

    @check_server_available
    def trace_line(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "TraceLine", "params": {"address": addr}})

    @check_server_available
    def run_to(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "RunTo", "params": {"address": addr}})

    @check_server_available
    def run_to_user_code(self) -> str:
        return self.custom_post({"interface": "RunToUserCode", "params": {}})

    @check_server_available
    def debug_continue(self, status: int = 0) -> str:
        return self.custom_post({"interface": "DebugContinue", "params": {"status": status}})

    @check_server_available
    def pause_all_threads(self) -> str:
        return self.custom_post({"interface": "PauseAllThreads", "params": {}})

    @check_server_available
    def resume_all_threads(self) -> str:
        return self.custom_post({"interface": "ResumeAllThreads", "params": {}})

    @check_server_available
    def thread_pause(self, tid: int) -> str:
        return self.custom_post({"interface": "ThreadPause", "params": {"tid": tid}})

    @check_server_available
    def thread_resume(self, tid: int) -> str:
        return self.custom_post({"interface": "ThreadResume", "params": {"tid": tid}})

    @check_server_available
    def animate_into(self, count: int = 3) -> str:
        return self.custom_post({"interface": "AnimateInto", "params": {"count": count}})

    @check_server_available
    def animate_over(self, count: int = 3) -> str:
        return self.custom_post({"interface": "AnimateOver", "params": {"count": count}})

    @check_server_available
    def animate_stop(self) -> str:
        return self.custom_post({"interface": "AnimateStop", "params": {}})

    @check_server_available
    def run_script(self, path: str = "", script: str = "") -> str:
        payload: Dict = {}
        if path:
            payload["path"] = path
        if script:
            payload["script"] = script
        return self.custom_post({"interface": "RunScript", "params": payload})

    @check_server_available
    def hooks_is_address_redirected(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "HooksIsAddressRedirected", "params": {"address": addr}})

    @check_server_available
    def hooks_get_hook_entry_details(self, address: Union[int, str]) -> str:
        addr = validate_hex_address(address)
        return self.custom_post({"interface": "HooksGetHookEntryDetails", "params": {"address": addr}})

    @check_server_available
    def is_jump_going_to_execute(self, address: Union[int, str] = "") -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        return self.custom_post({"interface": "IsJumpGoingToExecute", "params": payload})

    @check_server_available
    def set_next_dbg_continue_status(self, status: int = 1, code: int = 0) -> str:
        payload: Dict = {}
        if code:
            payload["code"] = code
        else:
            payload["status"] = status
        return self.custom_post({"interface": "SetNextDbgContinueStatus", "params": payload})

    @check_server_available
    def clear_exception_number(self) -> str:
        return self.custom_post({"interface": "ClearExceptionNumber", "params": {}})

    @check_server_available
    def current_exception_number(self) -> str:
        return self.custom_post({"interface": "CurrentExceptionNumber", "params": {}})

    @check_server_available
    def plugin_add_command(self, name: str, script: str) -> str:
        return self.custom_post({"interface": "PluginAddCommand", "params": {"name": name, "script": script}})

    @check_server_available
    def plugin_del_command(self, name: str) -> str:
        return self.custom_post({"interface": "PluginDelCommand", "params": {"name": name}})

    @check_server_available
    def plugin_list(self) -> str:
        return self.custom_post({"interface": "PluginList", "params": {}})

class AuthApi(BaseHttpClient):
    @check_server_available
    def get_api_key(self) -> str:
        return self.custom_post({"interface": "GetApiKey", "params": {}})

    @check_server_available
    def set_api_key(self, api_key: str) -> str:
        resp = self.custom_post({"interface": "SetApiKey", "params": {"key": api_key}})
        try:
            js = json.loads(resp)
            if js.get("status") == "success" and (js.get("result") or {}).get("state"):
                self.config.api_key = api_key
        except Exception:
            pass
        return resp


class ExtraApi(BaseHttpClient):
    @check_server_available
    def add_arg(self, name: str = "", type_: int = 0, aname: str = "", field: str = "", def_: str = "", member: str = "", arg: str = "") -> str:
        payload: Dict = {}
        if name:
            payload["name"] = name
        if type_:
            payload["type"] = type_
        if aname:
            payload["aname"] = aname
        if field:
            payload["field"] = field
        if def_:
            payload["def"] = def_
        if member:
            payload["member"] = member
        if arg:
            payload["arg"] = arg
        return self.custom_post({"interface": "AddArg", "params": payload})
    @check_server_available
    def add_member(self, name: str = "", type_: int = 0, mname: str = "", field: str = "", def_: str = "", member: str = "", arg: str = "") -> str:
        payload: Dict = {}
        if name:
            payload["name"] = name
        if type_:
            payload["type"] = type_
        if mname:
            payload["mname"] = mname
        if field:
            payload["field"] = field
        if def_:
            payload["def"] = def_
        if member:
            payload["member"] = member
        if arg:
            payload["arg"] = arg
        return self.custom_post({"interface": "AddMember", "params": payload})
    @check_server_available
    def add_union(self, name: str = "", type_: int = 0, mname: str = "", field: str = "", def_: str = "", member: str = "", arg: str = "", src: str = "", value: int = 0, size: int = 0) -> str:
        payload: Dict = {}
        if name:
            payload["name"] = name
        if type_:
            payload["type"] = type_
        if mname:
            payload["mname"] = mname
        if field:
            payload["field"] = field
        if def_:
            payload["def"] = def_
        if member:
            payload["member"] = member
        if arg:
            payload["arg"] = arg
        if src:
            payload["src"] = validate_hex_address(src)
        if value:
            payload["value"] = value
        if size:
            payload["size"] = size
        return self.custom_post({"interface": "AddUnion", "params": payload})
    @check_server_available
    def analyze_basic_blocks(self, address, size: int = 0, module: str = "") -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if size:
            payload["size"] = size
        if module:
            payload["module"] = module
        return self.custom_post({"interface": "AnalyzeBasicBlocks", "params": payload})
    @check_server_available
    def append_arg(self, name: str = "", type_: int = 0, aname: str = "", field: str = "", def_: str = "", member: str = "", arg: str = "") -> str:
        payload: Dict = {}
        if name:
            payload["name"] = name
        if type_:
            payload["type"] = type_
        if aname:
            payload["aname"] = aname
        if field:
            payload["field"] = field
        if def_:
            payload["def"] = def_
        if member:
            payload["member"] = member
        if arg:
            payload["arg"] = arg
        return self.custom_post({"interface": "AppendArg", "params": payload})
    @check_server_available
    def append_member(self, name: str = "", type_: int = 0, mname: str = "", field: str = "", def_: str = "", member: str = "", arg: str = "") -> str:
        payload: Dict = {}
        if name:
            payload["name"] = name
        if type_:
            payload["type"] = type_
        if mname:
            payload["mname"] = mname
        if field:
            payload["field"] = field
        if def_:
            payload["def"] = def_
        if member:
            payload["member"] = member
        if arg:
            payload["arg"] = arg
        return self.custom_post({"interface": "AppendMember", "params": payload})
    @check_server_available
    def bench(self, address: str = "", size: int = 0, iterations: int = 0) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if size:
            payload["size"] = size
        if iterations:
            payload["iterations"] = iterations
        return self.custom_post({"interface": "Bench", "params": payload})
    @check_server_available
    def bp_ref_dll(self, dll, api: str = "") -> str:
        payload: Dict = {}
        payload["dll"] = dll
        if api:
            payload["api"] = api
        return self.custom_post({"interface": "BpRefDll", "params": payload})
    @check_server_available
    def bp_ref_exception(self, code) -> str:
        payload: Dict = {}
        payload["code"] = code
        return self.custom_post({"interface": "BpRefException", "params": payload})
    @check_server_available
    def bp_ref_list(self, type_: int = 0, priority: int = 0, text: str = "", address: str = "", pid: int = 0, tid: int = 0, max: int = 0, module: str = "") -> str:
        payload: Dict = {}
        if type_:
            payload["type"] = type_
        if priority:
            payload["priority"] = priority
        if text:
            payload["text"] = text
        if address:
            payload["address"] = validate_hex_address(address)
        if pid:
            payload["pid"] = pid
        if tid:
            payload["tid"] = tid
        if max:
            payload["max"] = max
        if module:
            payload["module"] = module
        return self.custom_post({"interface": "BpRefList", "params": payload})
    @check_server_available
    def check_watchdog(self, id_: str = "", name: str = "", value: int = 0) -> str:
        payload: Dict = {}
        if id_:
            payload["id"] = id_
        if name:
            payload["name"] = name
        if value:
            payload["value"] = value
        return self.custom_post({"interface": "CheckWatchdog", "params": payload})
    @check_server_available
    def clear_address_colors(self, address: str = "", size: int = 0, type_: int = 0) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if size:
            payload["size"] = size
        if type_:
            payload["type"] = type_
        return self.custom_post({"interface": "ClearAddressColors", "params": payload})
    @check_server_available
    def clear_data_marking(self, address: str = "") -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        return self.custom_post({"interface": "ClearDataMarking", "params": payload})
    @check_server_available
    def clear_types(self, name: str = "", type_: int = 0, def_: str = "", file: str = "", path: str = "") -> str:
        payload: Dict = {}
        if name:
            payload["name"] = name
        if type_:
            payload["type"] = type_
        if def_:
            payload["def"] = def_
        if file:
            payload["file"] = file
        if path:
            payload["path"] = path
        return self.custom_post({"interface": "ClearTypes", "params": payload})
    @check_server_available
    def debug_flags(self, value) -> str:
        payload: Dict = {}
        payload["value"] = value
        return self.custom_post({"interface": "DebugFlags", "params": payload})
    @check_server_available
    def del_address_color(self, address) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        return self.custom_post({"interface": "DelAddressColor", "params": payload})
    @check_server_available
    def delete_exception_bpx(self, code: int = 0, name: str = "", value: int = 0) -> str:
        payload: Dict = {}
        if code:
            payload["code"] = code
        if name:
            payload["name"] = name
        if value:
            payload["value"] = value
        return self.custom_post({"interface": "DeleteExceptionBPX", "params": payload})
    @check_server_available
    def delete_watch_dog(self, address: str = "", id_: str = "", expr: str = "", value: int = 0) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if id_:
            payload["id"] = id_
        if expr:
            payload["expr"] = expr
        if value:
            payload["value"] = value
        return self.custom_post({"interface": "DeleteWatchDog", "params": payload})
    @check_server_available
    def device_path_to_path(self, path) -> str:
        payload: Dict = {}
        payload["path"] = path
        return self.custom_post({"interface": "DevicePathToPath", "params": payload})
    @check_server_available
    def disable_exception_bpx(self, code: int = 0, start: str = "", end: str = "", address: str = "", size: int = 0, flag: int = 0) -> str:
        payload: Dict = {}
        if code:
            payload["code"] = code
        if start:
            payload["start"] = validate_hex_address(start)
        if end:
            payload["end"] = validate_hex_address(end)
        if address:
            payload["address"] = validate_hex_address(address)
        if size:
            payload["size"] = size
        if flag:
            payload["flag"] = flag
        return self.custom_post({"interface": "DisableExceptionBPX", "params": payload})
    @check_server_available
    def disable_hardware_breakpoint(self, address: str = "", dr: int = 0) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if dr:
            payload["dr"] = dr
        return self.custom_post({"interface": "DisableHardwareBreakpoint", "params": payload})
    @check_server_available
    def disable_librarian_breakpoint(self, address: str = "", dll: str = "", api: str = "", code: int = 0) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if dll:
            payload["dll"] = dll
        if api:
            payload["api"] = api
        if code:
            payload["code"] = code
        return self.custom_post({"interface": "DisableLibrarianBreakpoint", "params": payload})
    @check_server_available
    def disable_log(self, file: str = "", path: str = "", name: str = "") -> str:
        payload: Dict = {}
        if file:
            payload["file"] = file
        if path:
            payload["path"] = path
        if name:
            payload["name"] = name
        return self.custom_post({"interface": "DisableLog", "params": payload})
    @check_server_available
    def disable_memory_breakpoint(self, address: str = "", dll: str = "", api: str = "") -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if dll:
            payload["dll"] = dll
        if api:
            payload["api"] = api
        return self.custom_post({"interface": "DisableMemoryBreakpoint", "params": payload})
    @check_server_available
    def disable_privilege(self, name: str = "", tid: int = 0, thread: str = "", threadid: str = "") -> str:
        payload: Dict = {}
        if name:
            payload["name"] = name
        if tid:
            payload["tid"] = tid
        if thread:
            payload["thread"] = thread
        if threadid:
            payload["threadid"] = threadid
        return self.custom_post({"interface": "DisablePrivilege", "params": payload})
    @check_server_available
    def disable_window(self, hwnd) -> str:
        payload: Dict = {}
        if hwnd:
            payload["hwnd"] = validate_hex_address(hwnd)
        return self.custom_post({"interface": "DisableWindow", "params": payload})
    @check_server_available
    def download_file(self, url, file, timeout: int = 0, useragent: str = "") -> str:
        payload: Dict = {}
        payload["url"] = url
        payload["file"] = file
        if timeout:
            payload["timeout"] = timeout
        if useragent:
            payload["useragent"] = useragent
        return self.custom_post({"interface": "DownloadFile", "params": payload})
    @check_server_available
    def enable_exception_bpx(self, code: int = 0, start: str = "", end: str = "", address: str = "", size: int = 0, flag: int = 0) -> str:
        payload: Dict = {}
        if code:
            payload["code"] = code
        if start:
            payload["start"] = validate_hex_address(start)
        if end:
            payload["end"] = validate_hex_address(end)
        if address:
            payload["address"] = validate_hex_address(address)
        if size:
            payload["size"] = size
        if flag:
            payload["flag"] = flag
        return self.custom_post({"interface": "EnableExceptionBPX", "params": payload})
    @check_server_available
    def enable_hardware_breakpoint(self, address: str = "", dr: int = 0) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if dr:
            payload["dr"] = dr
        return self.custom_post({"interface": "EnableHardwareBreakpoint", "params": payload})
    @check_server_available
    def enable_librarian_breakpoint(self, address: str = "", dll: str = "", api: str = "", code: int = 0) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if dll:
            payload["dll"] = dll
        if api:
            payload["api"] = api
        if code:
            payload["code"] = code
        return self.custom_post({"interface": "EnableLibrarianBreakpoint", "params": payload})
    @check_server_available
    def enable_log(self, file: str = "", path: str = "", name: str = "") -> str:
        payload: Dict = {}
        if file:
            payload["file"] = file
        if path:
            payload["path"] = path
        if name:
            payload["name"] = name
        return self.custom_post({"interface": "EnableLog", "params": payload})
    @check_server_available
    def enable_memory_breakpoint(self, address: str = "", dll: str = "", api: str = "") -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if dll:
            payload["dll"] = dll
        if api:
            payload["api"] = api
        return self.custom_post({"interface": "EnableMemoryBreakpoint", "params": payload})
    @check_server_available
    def enable_privilege(self, name: str = "", tid: int = 0, thread: str = "", threadid: str = "") -> str:
        payload: Dict = {}
        if name:
            payload["name"] = name
        if tid:
            payload["tid"] = tid
        if thread:
            payload["thread"] = thread
        if threadid:
            payload["threadid"] = threadid
        return self.custom_post({"interface": "EnablePrivilege", "params": payload})
    @check_server_available
    def enable_window(self, hwnd) -> str:
        payload: Dict = {}
        if hwnd:
            payload["hwnd"] = validate_hex_address(hwnd)
        return self.custom_post({"interface": "EnableWindow", "params": payload})
    @check_server_available
    def enum_types(self, name: str = "", type_: int = 0) -> str:
        payload: Dict = {}
        if name:
            payload["name"] = name
        if type_:
            payload["type"] = type_
        return self.custom_post({"interface": "EnumTypes", "params": payload})
    @check_server_available
    def eval_str(self, expr) -> str:
        payload: Dict = {}
        payload["expr"] = expr
        return self.custom_post({"interface": "EvalStr", "params": payload})
    @check_server_available
    def find_function_pointers(self, address, max: int = 0) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if max:
            payload["max"] = max
        return self.custom_post({"interface": "FindFunctionPointers", "params": payload})
    @check_server_available
    def find_mod_call(self, max: int = 0) -> str:
        payload: Dict = {}
        if max:
            payload["max"] = max
        return self.custom_post({"interface": "FindModCall", "params": payload})
    @check_server_available
    def find_ref_range(self, address, start, size, max: int = 0) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if start:
            payload["start"] = validate_hex_address(start)
        payload["size"] = size
        if max:
            payload["max"] = max
        return self.custom_post({"interface": "FindRefRange", "params": payload})
    @check_server_available
    def flush_log(self, type_: int = 0, all: int = 0, id_: str = "", max: int = 0, path: str = "", algo: int = 0, address: str = "", pattern: str = "", size: int = 0) -> str:
        payload: Dict = {}
        if type_:
            payload["type"] = type_
        if all:
            payload["all"] = all
        if id_:
            payload["id"] = id_
        if max:
            payload["max"] = max
        if path:
            payload["path"] = path
        if algo:
            payload["algo"] = algo
        if address:
            payload["address"] = validate_hex_address(address)
        if pattern:
            payload["pattern"] = pattern
        if size:
            payload["size"] = size
        return self.custom_post({"interface": "FlushLog", "params": payload})
    @check_server_available
    def format_log(self, text, address: str = "", hitcount: str = "", expr: str = "") -> str:
        payload: Dict = {}
        payload["text"] = text
        if address:
            payload["address"] = validate_hex_address(address)
        if hitcount:
            payload["hitcount"] = hitcount
        if expr:
            payload["expr"] = expr
        return self.custom_post({"interface": "FormatLog", "params": payload})
    @check_server_available
    def get_addr_from_line(self, file, line) -> str:
        payload: Dict = {}
        payload["file"] = file
        payload["line"] = line
        return self.custom_post({"interface": "GetAddrFromLine", "params": payload})
    @check_server_available
    def get_address_colors(self, address: str = "", size: int = 0, type_: int = 0) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if size:
            payload["size"] = size
        if type_:
            payload["type"] = type_
        return self.custom_post({"interface": "GetAddressColors", "params": payload})
    @check_server_available
    def get_data_marking(self, address) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        return self.custom_post({"interface": "GetDataMarking", "params": payload})
    @check_server_available
    def get_data_markings(self, address: str = "", start: str = "", size: int = 0, max: int = 0) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if start:
            payload["start"] = validate_hex_address(start)
        if size:
            payload["size"] = size
        if max:
            payload["max"] = max
        return self.custom_post({"interface": "GetDataMarkings", "params": payload})
    @check_server_available
    def get_events(self, max: int = 0) -> str:
        payload: Dict = {}
        if max:
            payload["max"] = max
        return self.custom_post({"interface": "GetEvents", "params": payload})
    @check_server_available
    def get_flag(self, flag: int = 0) -> str:
        payload: Dict = {}
        if flag:
            payload["flag"] = flag
        return self.custom_post({"interface": "GetFlag", "params": payload})
    @check_server_available
    def get_privilege_state(self, name: str = "", tid: int = 0, thread: str = "", threadid: str = "") -> str:
        payload: Dict = {}
        if name:
            payload["name"] = name
        if tid:
            payload["tid"] = tid
        if thread:
            payload["thread"] = thread
        if threadid:
            payload["threadid"] = threadid
        return self.custom_post({"interface": "GetPrivilegeState", "params": payload})
    @check_server_available
    def get_reloc_size(self, module: str = "", name: str = "", enable: int = 0, value: int = 0, base: str = "", address: str = "", size: int = 0, remove: str = "") -> str:
        payload: Dict = {}
        if module:
            payload["module"] = module
        if name:
            payload["name"] = name
        if enable:
            payload["enable"] = enable
        if value:
            payload["value"] = value
        if base:
            payload["base"] = validate_hex_address(base)
        if address:
            payload["address"] = validate_hex_address(address)
        if size:
            payload["size"] = size
        if remove:
            payload["remove"] = remove
        return self.custom_post({"interface": "GetRelocSize", "params": payload})
    @check_server_available
    def get_source_from_addr(self, address) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        return self.custom_post({"interface": "GetSourceFromAddr", "params": payload})
    @check_server_available
    def get_trace_record_bytes(self, address, size) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        payload["size"] = size
        return self.custom_post({"interface": "GetTraceRecordBytes", "params": payload})
    @check_server_available
    def get_trace_record_hit_count(self, address) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        return self.custom_post({"interface": "GetTraceRecordHitCount", "params": payload})
    @check_server_available
    def get_trace_record_type(self, address: str = "", size: int = 0, file: str = "", line: str = "") -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if size:
            payload["size"] = size
        if file:
            payload["file"] = file
        if line:
            payload["line"] = line
        return self.custom_post({"interface": "GetTraceRecordType", "params": payload})
    @check_server_available
    def get_type_data(self, name: str = "", address: str = "", depth: int = 0) -> str:
        payload: Dict = {}
        if name:
            payload["name"] = name
        if address:
            payload["address"] = validate_hex_address(address)
        if depth:
            payload["depth"] = depth
        return self.custom_post({"interface": "GetTypeData", "params": payload})
    @check_server_available
    def hash_file(self, path, algo: int = 0) -> str:
        payload: Dict = {}
        payload["path"] = path
        if algo:
            payload["algo"] = algo
        return self.custom_post({"interface": "HashFile", "params": payload})
    @check_server_available
    def label_runtime_functions(self, module) -> str:
        payload: Dict = {}
        payload["module"] = module
        return self.custom_post({"interface": "LabelRuntimeFunctions", "params": payload})
    @check_server_available
    def librarian_disable_breakpoint(self, address: str = "", dll: str = "", api: str = "") -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if dll:
            payload["dll"] = dll
        if api:
            payload["api"] = api
        return self.custom_post({"interface": "LibrarianDisableBreakpoint", "params": payload})
    @check_server_available
    def librarian_enable_breakpoint(self, address: str = "", dll: str = "", api: str = "") -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if dll:
            payload["dll"] = dll
        if api:
            payload["api"] = api
        return self.custom_post({"interface": "LibrarianEnableBreakpoint", "params": payload})
    @check_server_available
    def load_types(self, path: str = "", file: str = "", def_: str = "") -> str:
        payload: Dict = {}
        if path:
            payload["path"] = path
        if file:
            payload["file"] = file
        if def_:
            payload["def"] = def_
        return self.custom_post({"interface": "LoadTypes", "params": payload})
    @check_server_available
    def mod_get_party(self, module) -> str:
        payload: Dict = {}
        payload["module"] = module
        return self.custom_post({"interface": "ModGetParty", "params": payload})
    @check_server_available
    def mod_set_party(self, module, party) -> str:
        payload: Dict = {}
        payload["module"] = module
        payload["party"] = party
        return self.custom_post({"interface": "ModSetParty", "params": payload})
    @check_server_available
    def mod_symbol_status(self, module, pid: int = 0) -> str:
        payload: Dict = {}
        payload["module"] = module
        if pid:
            payload["pid"] = pid
        return self.custom_post({"interface": "ModSymbolStatus", "params": payload})
    @check_server_available
    def msg_clear(self, max: int = 0, module: str = "", party: str = "", pid: int = 0) -> str:
        payload: Dict = {}
        if max:
            payload["max"] = max
        if module:
            payload["module"] = module
        if party:
            payload["party"] = party
        if pid:
            payload["pid"] = pid
        return self.custom_post({"interface": "MsgClear", "params": payload})
    @check_server_available
    def msg_list(self, max: int = 0) -> str:
        payload: Dict = {}
        if max:
            payload["max"] = max
        return self.custom_post({"interface": "MsgList", "params": payload})
    @check_server_available
    def msg_peek(self, max: int = 0) -> str:
        payload: Dict = {}
        if max:
            payload["max"] = max
        return self.custom_post({"interface": "MsgPeek", "params": payload})
    @check_server_available
    def msg_pop(self, max: int = 0, type_: int = 0) -> str:
        payload: Dict = {}
        if max:
            payload["max"] = max
        if type_:
            payload["type"] = type_
        return self.custom_post({"interface": "MsgPop", "params": payload})
    @check_server_available
    def msg_push(self, type_, priority: int = 0, text: str = "", address: str = "", pid: int = 0, tid: int = 0) -> str:
        payload: Dict = {}
        payload["type"] = type_
        if priority:
            payload["priority"] = priority
        if text:
            payload["text"] = text
        if address:
            payload["address"] = validate_hex_address(address)
        if pid:
            payload["pid"] = pid
        if tid:
            payload["tid"] = tid
        return self.custom_post({"interface": "MsgPush", "params": payload})
    @check_server_available
    def parse_types(self, text: str = "", def_: str = "", file: str = "", path: str = "") -> str:
        payload: Dict = {}
        if text:
            payload["text"] = text
        if def_:
            payload["def"] = def_
        if file:
            payload["file"] = file
        if path:
            payload["path"] = path
        return self.custom_post({"interface": "ParseTypes", "params": payload})
    @check_server_available
    def pattern_search_replace(self, address, search, replace, size: int = 0) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        payload["search"] = search
        payload["replace"] = replace
        if size:
            payload["size"] = size
        return self.custom_post({"interface": "PatternSearchReplace", "params": payload})
    @check_server_available
    def pattern_write(self, address, pattern, size: int = 0) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        payload["pattern"] = pattern
        if size:
            payload["size"] = size
        return self.custom_post({"interface": "PatternWrite", "params": payload})
    @check_server_available
    def pe_arch(self, path) -> str:
        payload: Dict = {}
        payload["path"] = path
        return self.custom_post({"interface": "PeArch", "params": payload})
    @check_server_available
    def redirect_log(self, path: str = "", file: str = "", name: str = "") -> str:
        payload: Dict = {}
        if path:
            payload["path"] = path
        if file:
            payload["file"] = file
        if name:
            payload["name"] = name
        return self.custom_post({"interface": "RedirectLog", "params": payload})
    @check_server_available
    def set_address_color(self, address, size: int = 0, color: str = "") -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if size:
            payload["size"] = size
        if color:
            payload["color"] = color
        return self.custom_post({"interface": "SetAddressColor", "params": payload})
    @check_server_available
    def set_data_marking(self, address, type_, size: int = 0) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        payload["type"] = type_
        if size:
            payload["size"] = size
        return self.custom_post({"interface": "SetDataMarking", "params": payload})
    @check_server_available
    def set_memory_range_bpx(self, address: str = "", size: int = 0, start: str = "", end: str = "", flag: int = 0) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if size:
            payload["size"] = size
        if start:
            payload["start"] = validate_hex_address(start)
        if end:
            payload["end"] = validate_hex_address(end)
        if flag:
            payload["flag"] = flag
        return self.custom_post({"interface": "SetMemoryRangeBPX", "params": payload})
    @check_server_available
    def set_memory_range_breakpoint(self, address: str = "", size: int = 0, start: str = "", end: str = "", flag: int = 0) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if size:
            payload["size"] = size
        if start:
            payload["start"] = validate_hex_address(start)
        if end:
            payload["end"] = validate_hex_address(end)
        if flag:
            payload["flag"] = flag
        return self.custom_post({"interface": "SetMemoryRangeBreakpoint", "params": payload})
    @check_server_available
    def set_trace_record_type(self, type_) -> str:
        payload: Dict = {}
        payload["type"] = type_
        return self.custom_post({"interface": "SetTraceRecordType", "params": payload})
    @check_server_available
    def set_watch_name(self, id_: str = "", name: str = "", value: int = 0, type_: int = 0) -> str:
        payload: Dict = {}
        if id_:
            payload["id"] = id_
        if name:
            payload["name"] = name
        if value:
            payload["value"] = value
        if type_:
            payload["type"] = type_
        return self.custom_post({"interface": "SetWatchName", "params": payload})
    @check_server_available
    def set_watch_type(self, id_: str = "", type_: int = 0, value: int = 0, name: str = "") -> str:
        payload: Dict = {}
        if id_:
            payload["id"] = id_
        if type_:
            payload["type"] = type_
        if value:
            payload["value"] = value
        if name:
            payload["name"] = name
        return self.custom_post({"interface": "SetWatchType", "params": payload})
    @check_server_available
    def set_watchdog(self, address: str = "", id_: str = "", expr: str = "", value: int = 0) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if id_:
            payload["id"] = id_
        if expr:
            payload["expr"] = expr
        if value:
            payload["value"] = value
        return self.custom_post({"interface": "SetWatchdog", "params": payload})
    @check_server_available
    def sizeof_type(self, name: str = "", type_: int = 0) -> str:
        payload: Dict = {}
        if name:
            payload["name"] = name
        if type_:
            payload["type"] = type_
        return self.custom_post({"interface": "SizeofType", "params": payload})
    @check_server_available
    def stop_redirect_log(self, name: str = "") -> str:
        payload: Dict = {}
        if name:
            payload["name"] = name
        return self.custom_post({"interface": "StopRedirectLog", "params": payload})
    @check_server_available
    def subscribe_event(self, type_, all: int = 0) -> str:
        payload: Dict = {}
        payload["type"] = type_
        if all:
            payload["all"] = all
        return self.custom_post({"interface": "SubscribeEvent", "params": payload})
    @check_server_available
    def trace_set_command(self, command: str = "", value: int = 0, file: str = "", path: str = "", filter: str = "", clear: str = "") -> str:
        payload: Dict = {}
        if command:
            payload["command"] = command
        if value:
            payload["value"] = value
        if file:
            payload["file"] = file
        if path:
            payload["path"] = path
        if filter:
            payload["filter"] = filter
        if clear:
            payload["clear"] = clear
        return self.custom_post({"interface": "TraceSetCommand", "params": payload})
    @check_server_available
    def trace_set_log_file(self, path: str = "", file: str = "", filter: str = "", value: int = 0, clear: str = "") -> str:
        payload: Dict = {}
        if path:
            payload["path"] = path
        if file:
            payload["file"] = file
        if filter:
            payload["filter"] = filter
        if value:
            payload["value"] = value
        if clear:
            payload["clear"] = clear
        return self.custom_post({"interface": "TraceSetLogFile", "params": payload})
    @check_server_available
    def trace_set_step_filter(self, filter: str = "", value: int = 0, clear: str = "", id_: str = "", expr: str = "") -> str:
        payload: Dict = {}
        if filter:
            payload["filter"] = filter
        if value:
            payload["value"] = value
        if clear:
            payload["clear"] = clear
        if id_:
            payload["id"] = id_
        if expr:
            payload["expr"] = expr
        return self.custom_post({"interface": "TraceSetStepFilter", "params": payload})
    @check_server_available
    def unsubscribe_event(self, id_, all) -> str:
        payload: Dict = {}
        payload["id"] = id_
        payload["all"] = all
        return self.custom_post({"interface": "UnsubscribeEvent", "params": payload})
    @check_server_available
    def visit_type(self, name: str = "", type_: int = 0, def_: str = "", file: str = "", path: str = "") -> str:
        payload: Dict = {}
        if name:
            payload["name"] = name
        if type_:
            payload["type"] = type_
        if def_:
            payload["def"] = def_
        if file:
            payload["file"] = file
        if path:
            payload["path"] = path
        return self.custom_post({"interface": "VisitType", "params": payload})
    @check_server_available
    def argumentadd(self, start: str = "", end: str = "", name: str = "", format_: str = "") -> str:
        payload: Dict = {}
        if start:
            payload["start"] = validate_hex_address(start)
        if end:
            payload["end"] = validate_hex_address(end)
        if name:
            payload["name"] = name
        if format_:
            payload["format"] = format_
        return self.custom_post({"interface": "argumentadd", "params": payload})
    @check_server_available
    def argumentclear(self, format_: str = "", value: int = 0) -> str:
        payload: Dict = {}
        if format_:
            payload["format"] = format_
        if value:
            payload["value"] = value
        return self.custom_post({"interface": "argumentclear", "params": payload})
    @check_server_available
    def argumentdel(self, start: str = "", format_: str = "", value: int = 0) -> str:
        payload: Dict = {}
        if start:
            payload["start"] = validate_hex_address(start)
        if format_:
            payload["format"] = format_
        if value:
            payload["value"] = value
        return self.custom_post({"interface": "argumentdel", "params": payload})
    @check_server_available
    def argumentlist(self, format_: str = "", value: int = 0) -> str:
        payload: Dict = {}
        if format_:
            payload["format"] = format_
        if value:
            payload["value"] = value
        return self.custom_post({"interface": "argumentlist", "params": payload})
    @check_server_available
    def bookmarkclear(self) -> str:
        return self.custom_post({"interface": "bookmarkclear", "params": {}})
    @check_server_available
    def bpgoto(self, address: str = "", index: int = 0, code: int = 0, name: str = "", value: int = 0) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if index:
            payload["index"] = index
        if code:
            payload["code"] = code
        if name:
            payload["name"] = name
        if value:
            payload["value"] = value
        return self.custom_post({"interface": "bpgoto", "params": payload})
    @check_server_available
    def bplist(self, address: str = "") -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        return self.custom_post({"interface": "bplist", "params": payload})
    @check_server_available
    def briefcheck(self, address: str = "", dll: str = "") -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if dll:
            payload["dll"] = dll
        return self.custom_post({"interface": "briefcheck", "params": payload})
    @check_server_available
    def commentclear(self) -> str:
        return self.custom_post({"interface": "commentclear", "params": {}})
    @check_server_available
    def copystr(self, src: str = "", dst: str = "", dest: str = "", max: int = 0, type_: int = 0, address: str = "", size: int = 0, file: str = "") -> str:
        payload: Dict = {}
        if src:
            payload["src"] = validate_hex_address(src)
        if dst:
            payload["dst"] = validate_hex_address(dst)
        if dest:
            payload["dest"] = dest
        if max:
            payload["max"] = max
        if type_:
            payload["type"] = type_
        if address:
            payload["address"] = validate_hex_address(address)
        if size:
            payload["size"] = size
        if file:
            payload["file"] = file
        return self.custom_post({"interface": "copystr", "params": payload})
    @check_server_available
    def dbclear(self) -> str:
        return self.custom_post({"interface": "dbclear", "params": {}})
    @check_server_available
    def dprintf(self, text: str = "", format_: str = "", value: int = 0) -> str:
        payload: Dict = {}
        if text:
            payload["text"] = text
        if format_:
            payload["format"] = format_
        if value:
            payload["value"] = value
        return self.custom_post({"interface": "dprintf", "params": payload})
    @check_server_available
    def exanal(self, address: str = "", mnemonic: str = "", name: str = "") -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if mnemonic:
            payload["mnemonic"] = mnemonic
        if name:
            payload["name"] = name
        return self.custom_post({"interface": "exanal", "params": payload})
    @check_server_available
    def exhandlers(self, tid: int = 0) -> str:
        payload: Dict = {}
        if tid:
            payload["tid"] = tid
        return self.custom_post({"interface": "exhandlers", "params": payload})
    @check_server_available
    def exinfo(self, address: str = "") -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        return self.custom_post({"interface": "exinfo", "params": payload})
    @check_server_available
    def findasm(self, mnemonic: str = "", address: str = "", start: str = "", size: int = 0, opcode: str = "", max: int = 0, tid: int = 0) -> str:
        payload: Dict = {}
        if mnemonic:
            payload["mnemonic"] = mnemonic
        if address:
            payload["address"] = validate_hex_address(address)
        if start:
            payload["start"] = validate_hex_address(start)
        if size:
            payload["size"] = size
        if opcode:
            payload["opcode"] = opcode
        if max:
            payload["max"] = max
        if tid:
            payload["tid"] = tid
        return self.custom_post({"interface": "findasm", "params": payload})
    @check_server_available
    def functionadd(self, start: str = "", end: str = "", name: str = "") -> str:
        payload: Dict = {}
        if start:
            payload["start"] = validate_hex_address(start)
        if end:
            payload["end"] = validate_hex_address(end)
        if name:
            payload["name"] = name
        return self.custom_post({"interface": "functionadd", "params": payload})
    @check_server_available
    def functionclear(self, start: str = "", end: str = "", name: str = "") -> str:
        payload: Dict = {}
        if start:
            payload["start"] = validate_hex_address(start)
        if end:
            payload["end"] = validate_hex_address(end)
        if name:
            payload["name"] = name
        return self.custom_post({"interface": "functionclear", "params": payload})
    @check_server_available
    def functiondel(self, start: str = "", end: str = "", name: str = "") -> str:
        payload: Dict = {}
        if start:
            payload["start"] = validate_hex_address(start)
        if end:
            payload["end"] = validate_hex_address(end)
        if name:
            payload["name"] = name
        return self.custom_post({"interface": "functiondel", "params": payload})
    @check_server_available
    def functionlist(self, start: str = "", end: str = "", name: str = "") -> str:
        payload: Dict = {}
        if start:
            payload["start"] = validate_hex_address(start)
        if end:
            payload["end"] = validate_hex_address(end)
        if name:
            payload["name"] = name
        return self.custom_post({"interface": "functionlist", "params": payload})
    @check_server_available
    def getcommandline(self, value: int = 0, cmdline: str = "", address: str = "", string: str = "", type_: int = 0) -> str:
        payload: Dict = {}
        if value:
            payload["value"] = value
        if cmdline:
            payload["cmdline"] = cmdline
        if address:
            payload["address"] = validate_hex_address(address)
        if string:
            payload["string"] = string
        if type_:
            payload["type"] = type_
        return self.custom_post({"interface": "getcommandline", "params": payload})
    @check_server_available
    def getjit(self, value: int = 0, debugger: str = "", enable: int = 0) -> str:
        payload: Dict = {}
        if value:
            payload["value"] = value
        if debugger:
            payload["debugger"] = debugger
        if enable:
            payload["enable"] = enable
        return self.custom_post({"interface": "getjit", "params": payload})
    @check_server_available
    def getjitauto(self, value: int = 0, debugger: str = "", enable: int = 0) -> str:
        payload: Dict = {}
        if value:
            payload["value"] = value
        if debugger:
            payload["debugger"] = debugger
        if enable:
            payload["enable"] = enable
        return self.custom_post({"interface": "getjitauto", "params": payload})
    @check_server_available
    def labelclear(self) -> str:
        return self.custom_post({"interface": "labelclear", "params": {}})
    @check_server_available
    def loopadd(self, address: str = "", name: str = "", head: str = "", tail: str = "", start: str = "", end: str = "", module: str = "") -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if name:
            payload["name"] = name
        if head:
            payload["head"] = head
        if tail:
            payload["tail"] = tail
        if start:
            payload["start"] = validate_hex_address(start)
        if end:
            payload["end"] = validate_hex_address(end)
        if module:
            payload["module"] = module
        return self.custom_post({"interface": "loopadd", "params": payload})
    @check_server_available
    def loopclear(self, address: str = "", start: str = "", size: int = 0, mnemonic: str = "", opcode: str = "", max: int = 0, tid: int = 0) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if start:
            payload["start"] = validate_hex_address(start)
        if size:
            payload["size"] = size
        if mnemonic:
            payload["mnemonic"] = mnemonic
        if opcode:
            payload["opcode"] = opcode
        if max:
            payload["max"] = max
        if tid:
            payload["tid"] = tid
        return self.custom_post({"interface": "loopclear", "params": payload})
    @check_server_available
    def loopdel(self, address: str = "", head: str = "", start: str = "", size: int = 0, mnemonic: str = "", opcode: str = "", max: int = 0) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if head:
            payload["head"] = head
        if start:
            payload["start"] = validate_hex_address(start)
        if size:
            payload["size"] = size
        if mnemonic:
            payload["mnemonic"] = mnemonic
        if opcode:
            payload["opcode"] = opcode
        if max:
            payload["max"] = max
        return self.custom_post({"interface": "loopdel", "params": payload})
    @check_server_available
    def looplist(self, address: str = "", start: str = "", size: int = 0, mnemonic: str = "", opcode: str = "", max: int = 0, tid: int = 0) -> str:
        payload: Dict = {}
        if address:
            payload["address"] = validate_hex_address(address)
        if start:
            payload["start"] = validate_hex_address(start)
        if size:
            payload["size"] = size
        if mnemonic:
            payload["mnemonic"] = mnemonic
        if opcode:
            payload["opcode"] = opcode
        if max:
            payload["max"] = max
        if tid:
            payload["tid"] = tid
        return self.custom_post({"interface": "looplist", "params": payload})
    @check_server_available
    def mnemonichelp(self, mnemonic: str = "", name: str = "", module: str = "", enable: int = 0, value: int = 0, base: str = "", address: str = "", size: int = 0) -> str:
        payload: Dict = {}
        if mnemonic:
            payload["mnemonic"] = mnemonic
        if name:
            payload["name"] = name
        if module:
            payload["module"] = module
        if enable:
            payload["enable"] = enable
        if value:
            payload["value"] = value
        if base:
            payload["base"] = validate_hex_address(base)
        if address:
            payload["address"] = validate_hex_address(address)
        if size:
            payload["size"] = size
        return self.custom_post({"interface": "mnemonichelp", "params": payload})
    @check_server_available
    def plugload(self, name: str = "", script: str = "") -> str:
        payload: Dict = {}
        if name:
            payload["name"] = name
        if script:
            payload["script"] = script
        return self.custom_post({"interface": "plugload", "params": payload})
    @check_server_available
    def plugreload(self, name: str = "", script: str = "") -> str:
        payload: Dict = {}
        if name:
            payload["name"] = name
        if script:
            payload["script"] = script
        return self.custom_post({"interface": "plugreload", "params": payload})
    @check_server_available
    def plugunload(self, name: str = "", script: str = "") -> str:
        payload: Dict = {}
        if name:
            payload["name"] = name
        if script:
            payload["script"] = script
        return self.custom_post({"interface": "plugunload", "params": payload})
    @check_server_available
    def pop(self, value: int = 0, size: int = 0, src: str = "") -> str:
        payload: Dict = {}
        if value:
            payload["value"] = value
        if size:
            payload["size"] = size
        if src:
            payload["src"] = validate_hex_address(src)
        return self.custom_post({"interface": "pop", "params": payload})
    @check_server_available
    def push(self, value: int = 0, size: int = 0, src: str = "") -> str:
        payload: Dict = {}
        if value:
            payload["value"] = value
        if size:
            payload["size"] = size
        if src:
            payload["src"] = validate_hex_address(src)
        return self.custom_post({"interface": "push", "params": payload})
    @check_server_available
    def savedata(self, path: str = "", address: str = "", size: int = 0, file: str = "", count: int = 0) -> str:
        payload: Dict = {}
        if path:
            payload["path"] = path
        if address:
            payload["address"] = validate_hex_address(address)
        if size:
            payload["size"] = size
        if file:
            payload["file"] = file
        if count:
            payload["count"] = count
        return self.custom_post({"interface": "savedata", "params": payload})
    @check_server_available
    def setcommandline(self, args: str = "", value: int = 0, cmdline: str = "", address: str = "", string: str = "", type_: int = 0) -> str:
        payload: Dict = {}
        if args:
            payload["args"] = args
        if value:
            payload["value"] = value
        if cmdline:
            payload["cmdline"] = cmdline
        if address:
            payload["address"] = validate_hex_address(address)
        if string:
            payload["string"] = string
        if type_:
            payload["type"] = type_
        return self.custom_post({"interface": "setcommandline", "params": payload})
    @check_server_available
    def setfreezestack(self, value: int = 0, enable: int = 0, base: str = "", address: str = "", size: int = 0, name: str = "", module: str = "", remove: str = "") -> str:
        payload: Dict = {}
        if value:
            payload["value"] = value
        if enable:
            payload["enable"] = enable
        if base:
            payload["base"] = validate_hex_address(base)
        if address:
            payload["address"] = validate_hex_address(address)
        if size:
            payload["size"] = size
        if name:
            payload["name"] = name
        if module:
            payload["module"] = module
        if remove:
            payload["remove"] = remove
        return self.custom_post({"interface": "setfreezestack", "params": payload})
    @check_server_available
    def setjit(self, path: str = "", value: int = 0, debugger: str = "", enable: int = 0) -> str:
        payload: Dict = {}
        if path:
            payload["path"] = path
        if value:
            payload["value"] = value
        if debugger:
            payload["debugger"] = debugger
        if enable:
            payload["enable"] = enable
        return self.custom_post({"interface": "setjit", "params": payload})
    @check_server_available
    def setjitauto(self, value: int = 0, debugger: str = "", enable: int = 0) -> str:
        payload: Dict = {}
        if value:
            payload["value"] = value
        if debugger:
            payload["debugger"] = debugger
        if enable:
            payload["enable"] = enable
        return self.custom_post({"interface": "setjitauto", "params": payload})
    @check_server_available
    def setmaxfindresult(self, value: int = 0, count: int = 0, command: str = "", file: str = "", path: str = "") -> str:
        payload: Dict = {}
        if value:
            payload["value"] = value
        if count:
            payload["count"] = count
        if command:
            payload["command"] = command
        if file:
            payload["file"] = file
        if path:
            payload["path"] = path
        return self.custom_post({"interface": "setmaxfindresult", "params": payload})
    @check_server_available
    def setstr(self, name: str = "", value: int = 0, address: str = "", string: str = "", type_: int = 0, dest: str = "", src: str = "", max: int = 0) -> str:
        payload: Dict = {}
        if name:
            payload["name"] = name
        if value:
            payload["value"] = value
        if address:
            payload["address"] = validate_hex_address(address)
        if string:
            payload["string"] = string
        if type_:
            payload["type"] = type_
        if dest:
            payload["dest"] = dest
        if src:
            payload["src"] = validate_hex_address(src)
        if max:
            payload["max"] = max
        return self.custom_post({"interface": "setstr", "params": payload})
    @check_server_available
    def switchthread(self, tid: int = 0, thread: str = "", threadid: str = "", value: int = 0, cmdline: str = "") -> str:
        payload: Dict = {}
        if tid:
            payload["tid"] = tid
        if thread:
            payload["thread"] = thread
        if threadid:
            payload["threadid"] = threadid
        if value:
            payload["value"] = value
        if cmdline:
            payload["cmdline"] = cmdline
        return self.custom_post({"interface": "switchthread", "params": payload})
    @check_server_available
    def symdownload(self, url: str = "", file: str = "", dest: str = "", name: str = "", script: str = "") -> str:
        payload: Dict = {}
        if url:
            payload["url"] = url
        if file:
            payload["file"] = file
        if dest:
            payload["dest"] = dest
        if name:
            payload["name"] = name
        if script:
            payload["script"] = script
        return self.custom_post({"interface": "symdownload", "params": payload})
    @check_server_available
    def vardel(self, name: str = "", start: str = "", end: str = "") -> str:
        payload: Dict = {}
        if name:
            payload["name"] = name
        if start:
            payload["start"] = validate_hex_address(start)
        if end:
            payload["end"] = validate_hex_address(end)
        return self.custom_post({"interface": "vardel", "params": payload})
    @check_server_available
    def varlist(self, start: str = "", end: str = "", name: str = "") -> str:
        payload: Dict = {}
        if start:
            payload["start"] = validate_hex_address(start)
        if end:
            payload["end"] = validate_hex_address(end)
        if name:
            payload["name"] = name
        return self.custom_post({"interface": "varlist", "params": payload})
    @check_server_available
    def varnew(self, name: str = "", value: int = 0, start: str = "", end: str = "") -> str:
        payload: Dict = {}
        if name:
            payload["name"] = name
        if value:
            payload["value"] = value
        if start:
            payload["start"] = validate_hex_address(start)
        if end:
            payload["end"] = validate_hex_address(end)
        return self.custom_post({"interface": "varnew", "params": payload})
    @check_server_available
    def virtualmod(self, module: str = "", base: str = "", address: str = "", size: int = 0, name: str = "", remove: str = "") -> str:
        payload: Dict = {}
        if module:
            payload["module"] = module
        if base:
            payload["base"] = validate_hex_address(base)
        if address:
            payload["address"] = validate_hex_address(address)
        if size:
            payload["size"] = size
        if name:
            payload["name"] = name
        if remove:
            payload["remove"] = remove
        return self.custom_post({"interface": "virtualmod", "params": payload})


class BinSentryClient(
    SystemApi,
    LogConfigApi,
    SymbolVarApi,
    BreakPointApi,
    DebugSessionApi,
    RegisterThreadApi,
    ModulePeApi,
    MemoryApi,
    DisasmXrefApi,
    StackTraceApi,
    ExecutionControlApi,
    AuthApi,
    ExtraApi):
    def __init__(self, config: Optional[Config] = None, address: str = "", port: int = 6891,
                 api_key: Optional[str] = None):
        if config is None and address:
            config = Config(address=address, port=port, api_key=api_key)
        elif config is not None and api_key:
            config.set_api_key(api_key)
        super().__init__(config)

    def bind(self, address: str, port: int = 6891) -> "BinSentryClient":
        self.set_server(address, port)
        return self