# -*- coding: utf-8 -*-
"""Memory snapshot diff primitives for the BinSentry MCP server.

Kept dependency-free so the algorithm can be unit-tested without starting
FastMCP or a debugger session.
"""
from __future__ import annotations

from typing import Any, Dict, List


def _hex_bytes(data: bytes, limit: int) -> str:
    if limit <= 0:
        return ""
    shown = data[: min(4096, int(limit))]
    return " ".join(f"{b:02X}" for b in shown)


def _is_hex_truncated(length: int, limit: int) -> bool:
    """limit=0 表示调用方主动关闭十六进制摘要，不是“截断”。"""
    return limit > 0 and length > limit


def diff_buffers(
    old: bytes,
    new: bytes,
    max_ranges: int = 64,
    max_hex_bytes: int = 32,
) -> Dict[str, Any]:
    """Compare two byte buffers and coalesce consecutive differences.

    ``max_ranges`` limits how many ranges are returned; the total count is
    always reported so callers can show "showing N of M".
    """
    if max_ranges < 1:
        max_ranges = 1
    if max_ranges > 4096:
        max_ranges = 4096
    if max_hex_bytes < 0:
        max_hex_bytes = 0
    if max_hex_bytes > 4096:
        max_hex_bytes = 4096

    compared = min(len(old), len(new))
    ranges: List[Dict[str, Any]] = []
    total_ranges = 0
    diff_bytes = 0
    start = -1

    def flush(end: int) -> None:
        nonlocal total_ranges
        if start < 0:
            return
        total_ranges += 1
        if len(ranges) < max_ranges:
            old_slice = old[start:end]
            new_slice = new[start:end]
            ranges.append({
                "offset": start,
                "length": end - start,
                "oldHex": _hex_bytes(old_slice, max_hex_bytes),
                "newHex": _hex_bytes(new_slice, max_hex_bytes),
                "oldHexTruncated": _is_hex_truncated(len(old_slice), max_hex_bytes),
                "newHexTruncated": _is_hex_truncated(len(new_slice), max_hex_bytes),
            })

    for i in range(compared):
        if old[i] != new[i]:
            diff_bytes += 1
            if start < 0:
                start = i
        elif start >= 0:
            flush(i)
            start = -1
    if start >= 0:
        flush(compared)

    # A size mismatch is itself a structural difference: report the tail so
    # callers do not silently treat a shorter snapshot as equal.
    tail = max(len(old), len(new)) - compared
    if tail > 0:
        total_ranges += 1
        if len(ranges) < max_ranges:
            tail_start = compared
            ranges.append({
                "offset": tail_start,
                "length": tail,
                "oldHex": _hex_bytes(old[tail_start:], max_hex_bytes) if len(old) > compared else "",
                "newHex": _hex_bytes(new[tail_start:], max_hex_bytes) if len(new) > compared else "",
                "oldHexTruncated": _is_hex_truncated(max(0, len(old) - tail_start), max_hex_bytes),
                "newHexTruncated": _is_hex_truncated(max(0, len(new) - tail_start), max_hex_bytes),
            })

    common_diff = diff_bytes
    total_size = max(len(old), len(new))
    diff_bytes += tail
    return {
        "oldSize": len(old),
        "newSize": len(new),
        "comparedBytes": compared,
        "equalBytes": compared - common_diff,
        "diffBytes": diff_bytes,
        "diffRatio": (diff_bytes / total_size) if total_size else 0.0,
        "sizeMismatch": tail > 0,
        "sizeMismatchBytes": tail,
        "totalRanges": total_ranges,
        "truncated": total_ranges > len(ranges),
        "ranges": ranges,
    }
