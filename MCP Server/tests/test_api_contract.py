# -*- coding: utf-8 -*-
"""Stdlib-only contract tests for the MCP Server's new API parameters.

Run from the ``MCP Server`` directory:
    python -m unittest discover -s tests -v
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest import mock

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))


def _load_sdk() -> Any:
    spec = importlib.util.spec_from_file_location("binsentry_sdk_contract", HERE / "__init__.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load __init__.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SDK = _load_sdk()


class _FakeConfig:
    server_addr = "http://127.0.0.1:1"
    api_key = "test-key"
    timeout = 5
    lease = ""

    def is_server_available(self, timeout: Optional[int] = None) -> bool:
        return True


class _ClientHarness:
    def __init__(self, api_cls: Any) -> None:
        self.calls: List[Dict[str, Any]] = []
        self.client = api_cls(_FakeConfig())
        self.client.custom_post = self._capture

    def _capture(self, payload: Dict[str, Any], timeout: Optional[int] = None) -> str:
        self.calls.append(payload)
        return json.dumps({"status": "success", "result": {"state": True}})

    def one(self, method: str, *args: Any, **kwargs: Any) -> Any:
        result = getattr(self.client, method)(*args, **kwargs)
        return json.loads(result) if isinstance(result, str) else result


class TestTcpConnectionsContract(unittest.TestCase):
    def setUp(self) -> None:
        self.h = _ClientHarness(SDK.SystemApi)

    def test_default_omits_flags(self) -> None:
        self.h.one("tcp_connections")
        self.assertEqual(self.h.calls[-1], {"interface": "TCPConnections", "params": {}})

    def test_all_sets_only_all(self) -> None:
        self.h.one("tcp_connections", include_all=True)
        self.assertEqual(self.h.calls[-1]["params"], {"all": True})

    def test_established_only_sets_only_established(self) -> None:
        self.h.one("tcp_connections", established_only=True)
        self.assertEqual(self.h.calls[-1]["params"], {"establishedOnly": True})

    def test_conflicting_flags_are_rejected_before_request(self) -> None:
        result = self.h.one("tcp_connections", include_all=True, established_only=True)
        self.assertEqual(result["status"], "error")
        self.assertIn("choose one", result["message"])
        self.assertEqual(self.h.calls, [])


class TestGetExportAddressContract(unittest.TestCase):
    def setUp(self) -> None:
        self.h = _ClientHarness(SDK.ModulePeApi)

    def test_name(self) -> None:
        self.h.one("get_export_address", module="sample.dll", name="sample_add")
        self.assertEqual(
            self.h.calls[-1]["params"],
            {"module": "sample.dll", "name": "sample_add"},
        )

    def test_ordinal(self) -> None:
        self.h.one("get_export_address", module="sample.dll", ordinal=1)
        self.assertEqual(
            self.h.calls[-1]["params"],
            {"module": "sample.dll", "ordinal": 1},
        )

    def test_name_wins_when_both_supplied(self) -> None:
        self.h.one("get_export_address", module="sample.dll", name="sample_add", ordinal=1)
        self.assertEqual(
            self.h.calls[-1]["params"],
            {"module": "sample.dll", "name": "sample_add"},
        )

    def test_missing_selector_is_rejected_before_request(self) -> None:
        result = self.h.one("get_export_address", module="sample.dll")
        self.assertEqual(result["status"], "error")
        self.assertIn("Usage", result["message"])
        self.assertEqual(self.h.calls, [])

    def test_zero_ordinal_is_rejected_before_request(self) -> None:
        result = self.h.one("get_export_address", module="sample.dll", ordinal=0)
        self.assertEqual(result["status"], "error")
        self.assertIn("positive", result["message"])
        self.assertEqual(self.h.calls, [])


class TestDisassembleAtContract(unittest.TestCase):
    def setUp(self) -> None:
        self.h = _ClientHarness(SDK.DisasmXrefApi)

    def test_default_count_is_five(self) -> None:
        self.h.one("disassemble_at", address=0x401270)
        self.assertEqual(
            self.h.calls[-1]["params"],
            {"address": "0x401270", "count": 5},
        )

    def test_count(self) -> None:
        self.h.one("disassemble_at", address=0x401270, count=3)
        self.assertEqual(self.h.calls[-1]["params"], {"address": "0x401270", "count": 3})

    def test_size_omits_count(self) -> None:
        self.h.one("disassemble_at", address=0x401270, size=20)
        self.assertEqual(self.h.calls[-1]["params"], {"address": "0x401270", "size": 20})

    def test_conflicting_count_and_size_rejected(self) -> None:
        result = self.h.one("disassemble_at", address=0x401270, count=3, size=20)
        self.assertEqual(result["status"], "error")
        self.assertIn("choose one", result["message"])
        self.assertEqual(self.h.calls, [])

    def test_count_range(self) -> None:
        for bad in (0, 513):
            with self.subTest(count=bad):
                result = self.h.one("disassemble_at", address=0x401270, count=bad)
                self.assertEqual(result["status"], "error")
                self.assertIn("1-512", result["message"])
        self.assertEqual(self.h.calls, [])

    def test_size_range(self) -> None:
        for bad in (0, 4097):
            with self.subTest(size=bad):
                result = self.h.one("disassemble_at", address=0x401270, size=bad)
                self.assertEqual(result["status"], "error")
                self.assertIn("1-4096", result["message"])
        self.assertEqual(self.h.calls, [])

    def test_invalid_address_rejected(self) -> None:
        result = self.h.one("disassemble_at", address="not-an-address")
        self.assertEqual(result["status"], "error")
        self.assertIn("address", result["message"])
        self.assertEqual(self.h.calls, [])


class TestToolSchemaContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        import mcp_server
        cls.mcp = mcp_server
        cls.tools = {
            tool: (cls_, method, func)
            for cls_, method, func, tool in mcp_server._collect_methods()
        }

    def test_new_tool_signatures_exist(self) -> None:
        for name, params in (
            ("tcp_connections", ("include_all", "established_only")),
            ("get_export_address", ("name", "ordinal")),
            ("disassemble_at", ("count", "size")),
        ):
            with self.subTest(tool=name):
                self.assertIn(name, self.tools)
                signature = self.mcp.inspect.signature(self.tools[name][2])
                for param in params:
                    self.assertIn(param, signature.parameters)

    def test_payload_aliases_are_visible_to_docs(self) -> None:
        self.assertEqual(self.mcp.PAYLOAD_KEY_ALIASES["include_all"], "all")
        self.assertEqual(self.mcp.PAYLOAD_KEY_ALIASES["established_only"], "establishedOnly")
        key_map = self.mcp._payload_key_map(self.tools["tcp_connections"][2])
        self.assertEqual(key_map["include_all"], "all")
        self.assertEqual(key_map["established_only"], "establishedOnly")


class TestTransportConfig(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        import mcp_server
        cls.mcp = mcp_server

    def test_aliases(self) -> None:
        self.assertEqual(self.mcp._transport_arg("HTTP"), "http")
        self.assertEqual(self.mcp._transport_arg("streamable-http"), "http")
        self.assertEqual(self.mcp._transport_arg("streamable_http"), "http")
        self.assertEqual(self.mcp._transport_arg("stdio"), "stdio")
        self.assertEqual(self.mcp._transport_arg("sse"), "sse")
        self.assertEqual(self.mcp._transport_arg("auto"), "auto")

    def test_env_defaults_are_validated(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "MCP_TRANSPORT": "HTTP",
                "MCP_PORT": "0",
                "BINSENTRY_PORT": "6891",
                "BINSENTRY_TIMEOUT": "7.5",
                "MCP_HOST": " 127.0.0.1 ",
            },
            clear=False,
        ):
            parser = self.mcp._build_parser()
            args = self.mcp._normalize_args(parser, parser.parse_args([]))
        self.assertEqual(args.transport, "http")
        self.assertEqual(args.mcp_port, 0)
        self.assertEqual(args.backend_port, 6891)
        self.assertEqual(args.timeout, 7.5)
        self.assertEqual(args.host, "127.0.0.1")

    def test_invalid_env_transport_is_rejected(self) -> None:
        with mock.patch.dict(os.environ, {"MCP_TRANSPORT": "bogus"}, clear=False):
            parser = self.mcp._build_parser()
            with self.assertRaises(SystemExit):
                parser.parse_args([])

    def test_endpoint_path_precedence(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"MCP_PATH": "", "MCP_HTTP_PATH": "custom-http", "MCP_SSE_PATH": "/custom-sse"},
            clear=False,
        ):
            self.assertEqual(self.mcp._resolve_endpoint_path("http", None), "/custom-http")
            self.assertEqual(self.mcp._resolve_endpoint_path("sse", None), "/custom-sse")
            self.assertEqual(self.mcp._resolve_endpoint_path("http", "/cli"), "/cli")

    def test_sse_message_endpoint_is_root_messages(self) -> None:
        self.assertEqual(
            self.mcp._endpoint_base("http://127.0.0.1:8000/sse"),
            "http://127.0.0.1:8000",
        )
        self.assertEqual(
            self.mcp._endpoint_base("http://127.0.0.1:8000/custom/sse"),
            "http://127.0.0.1:8000",
        )


class TestAdminToolValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        import mcp_server
        cls.mcp = mcp_server

    def test_empty_address_rejected(self) -> None:
        result = self.mcp.binsentry_set_server("", 6891)
        self.assertEqual(result["status"], "error")
        self.assertIn("address", result["message"])

    def test_invalid_port_rejected(self) -> None:
        result = self.mcp.binsentry_set_server("127.0.0.1", 70000)
        self.assertEqual(result["status"], "error")
        self.assertIn("1-65535", result["message"])

    def test_invalid_timeout_rejected(self) -> None:
        self.assertIn("大于 0", self.mcp.binsentry_set_timeout(0)["message"])
        self.assertIn("大于 0", self.mcp.binsentry_set_timeout(float("nan"))["message"])


if __name__ == "__main__":
    unittest.main()
