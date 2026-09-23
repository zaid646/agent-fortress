"""Tool-call allowlisting for agentic targets.

Each tool the target agent may call is classified. Destructive or
scope-escaping tools are denied unless explicitly enabled in config; tools that
return sensitive data are flagged so the egress layer inspects their output.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from .detectors import re
from .models import CheckKind, Verdict


@dataclass
class ToolPolicy:
    allowed: list[str] = field(default_factory=list)
    denied: list[str] = field(default_factory=list)
    sensitive_output: list[str] = field(default_factory=list)

    @classmethod
    def secure_defaults(cls) -> "ToolPolicy":
        return cls(
            allowed=["list_files", "read_file", "web_search", "list_dir"],
            denied=["delete_files", "shell_exec", "drop_database"],
            sensitive_output=["query_customer_db", "read_secrets_file", "read_file"],
        )


class ToolGuard:
    def __init__(self, policy: ToolPolicy | None = None):
        self.policy = policy or ToolPolicy.secure_defaults()

    def check(self, tool_name: str, args: dict | None = None) -> Verdict:
        start = time.perf_counter()
        args = args or {}
        if tool_name in self.policy.denied:
            return Verdict.block(
                CheckKind.TOOL,
                check="destructive_tool",
                reason=f"tool '{tool_name}' is denied by policy",
                latency_ms=(time.perf_counter() - start) * 1000.0,
                details={"tool": tool_name},
            )
        # Path traversal in any arg value (covers read_file too)
        for k, v in args.items():
            if isinstance(v, str) and re.search(r"(\.\./){1,}|\.\.\\", v):
                return Verdict.block(
                    CheckKind.TOOL,
                    check="path_traversal",
                    reason=f"path traversal in argument '{k}'",
                    latency_ms=(time.perf_counter() - start) * 1000.0,
                    details={"tool": tool_name, "key": k},
                )
        if tool_name in self.policy.sensitive_output:
            return Verdict.block(
                CheckKind.TOOL,
                check="sensitive_tool",
                reason=f"tool '{tool_name}' returns sensitive data; requires egress verification",
                latency_ms=(time.perf_counter() - start) * 1000.0,
                details={"tool": tool_name},
            )
        return Verdict.allow(
            CheckKind.TOOL,
            check="tool_allow",
            reason=f"tool '{tool_name}' allowed",
            latency_ms=(time.perf_counter() - start) * 1000.0,
        )