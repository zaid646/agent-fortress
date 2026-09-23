from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class CheckKind(str, Enum):
    INGRESS = "ingress"
    EGRESS = "egress"
    TOOL = "tool"
    DEEP = "deep"


class Verdict(BaseModel):
    allowed: bool
    kind: CheckKind
    check: str = "pass"
    reason: str = "allowed"
    score: float = 1.0  # 1 = look fine, 0 = blocked
    latency_ms: float = 0.0
    details: dict = Field(default_factory=dict)

    @classmethod
    def allow(cls, kind: CheckKind, check: str = "pass", reason: str = "allowed", **kw):
        return cls(allowed=True, kind=kind, check=check, reason=reason, **kw)

    @classmethod
    def block(cls, kind: CheckKind, check: str, reason: str, score: float = 0.0, **kw):
        return cls(allowed=False, kind=kind, check=check, reason=reason, score=score, **kw)


class ProbeResponse(BaseModel):
    """Normalized response returned by every target /probe endpoint."""

    query: str
    response: str
    sources: list[str] = Field(default_factory=list)
    tool_calls: list[dict] = Field(default_factory=list)
    blocked: bool = False
    block_reason: str = ""
    target: str = ""
    latency_ms: float = 0.0

    def to_text(self) -> str:
        parts = [self.response]
        parts.extend(self.sources)
        for tc in self.tool_calls:
            parts.append(str(tc))
        return "\n".join(parts)

    @classmethod
    def blocked_response(cls, reason: str, target: str) -> "ProbeResponse":
        return cls(
            query="",
            response="",
            blocked=True,
            block_reason=reason,
            target=target,
        )