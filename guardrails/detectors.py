"""Lightweight, offline-first detectors used by the Fortress engine.

Cheap-path checks run on every request (<100us pure regex, <2ms with the
hashing embedding). They gate the LLM deep-check so the expensive model only
runs on genuinely suspicious traffic.
"""
from __future__ import annotations

import base64
import binascii
import re
import time
import zlib
from typing import Callable

from .models import CheckKind, Verdict

# ---------------------------------------------------------------------------
# Ingress: prompt-injection / override / jailbreak phrase rules
# ---------------------------------------------------------------------------
INGRESS_RULES: list[tuple[str, str, float]] = [
    ("instruction_override", r"ignore\s+(all\s+)?(previous|prior|earlier)\s+(instructions|prompts|messages)", 0.95),
    ("instruction_override", r"disregard\s+(all\s+)?(previous|prior)\s+", 0.95),
    ("instruction_override", r"forget\s+(everything|all)\s+(you\s+)?(know|learned)", 0.9),
    ("system_prompt", r"output\s+the\s+(full\s+)?system\s+prompt", 0.98),
    ("system_prompt", r"(reveal|show|print|repeat)\s+(your\s+)?system\s+prompt", 0.95),
    ("role_switch", r"you\s+are\s+now\s+(\w+\s+){0,2}(terminal|command\s+line|developer\s+mode|dan|sudo)", 0.9),
    ("role_switch", r"act\s+as\s+if\s+you\s+have\s+no\s+(rules|restrictions|limitations)", 0.88),
    ("cot_leak", r"chain[- ]of[- ]thought|reason\s+(step\s+by\s+step|out loud)|show\s+(me\s+)?your\s+(inner\s+)?reasoning", 0.85),
    ("cot_leak", r"internal\s+(instructions|chain|prompt|monologue)", 0.85),
    ("secret_phish", r"api\s+key|connection\s+string|database\s+.*password|credentials\s+file", 0.6),
    ("path_traversal", r"(\.\./){1,}|\.\.\\", 0.95),
]

# ---------------------------------------------------------------------------
# Egress: PII + secret leak rules (output of the agent)
# ---------------------------------------------------------------------------
EGRESS_RULES: list[tuple[str, str, float]] = [
    ("ssn", r"(?<!\d)(\d{3}-\d{2}-\d{4})(?!\d)", 1.0),
    ("credit_card", r"(?<!\d)(\d{4}[-\s]?){3}\d{3,4}(?!\d)", 0.95),
    ("email", r"[\w.+-]+@[\w-]+\.[\w.-]{2,}", 0.5),
    ("phone", r"(\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}", 0.5),
    ("openai_key", r"\bsk-[A-Za-z0-9]{20,}\b", 1.0),
    ("aws_key", r"\bAKIA[0-9A-Z]{16}\b", 1.0),
    ("github_token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", 1.0),
    ("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", 1.0),
    ("hex_secret", r"\bBINARY_SECRET_[a-z0-9]{4,}\b", 1.0),
    ("private_key", r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", 1.0),
]

# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

class IngresRuleEngine:
    """Matches input text against the ingress phrases."""

    def __init__(self, rules: list[tuple[str, str, float]] | None = None, enabled: bool = True):
        self.rules = rules or INGRESS_RULES
        self.enabled = enabled
        self._compiled = [(name, re.compile(pat, re.IGNORECASE), score) for name, pat, score in self.rules]

    def check(self, text: str) -> Verdict:
        start = time.perf_counter()
        hits: list[dict] = []
        worst = 0.0
        for name, rx, score in self._compiled:
            m = rx.search(text)
            if m:
                hits.append({"rule": name, "match": m.group(0)[:80]})
                worst = max(worst, score)
        if is_base64_string(text):
            hits.append({"rule": "encoded_base64", "match": text.strip()[:80]})
            worst = max(worst, 0.7)
        lat = (time.perf_counter() - start) * 1000.0
        if hits:
            return Verdict.block(
                CheckKind.INGRESS,
                check="ingress_rules",
                reason=f"matched {len(hits)} ingestion rule(s)",
                score=1.0 - worst,
                latency_ms=lat,
                details={"hits": hits, "max_score": worst},
            )
        return Verdict.allow(CheckKind.INGRESS, check="ingress_rules", latency_ms=lat)


class EgressRuleEngine:
    """Matches output text against PII / secret leak rules."""

    def __init__(self, rules: list[tuple[str, str, float]] | None = None, sensitive_terms: list[str] | None = None):
        self.rules = rules or EGRESS_RULES
        self.sensitive_terms = [t.lower() for t in (sensitive_terms or [])]
        self._compiled = [(name, re.compile(pat), score) for name, pat, score in self.rules]

    def check(self, text: str) -> Verdict:
        start = time.perf_counter()
        hits: list[dict] = []
        for name, rx, score in self._compiled:
            m = rx.search(text)
            if m:
                hits.append({"rule": name, "match": m.group(0)[:80]})
        for term in self.sensitive_terms:
            if term in text.lower():
                hits.append({"rule": "sensitive_term", "match": term})
        lat = (time.perf_counter() - start) * 1000.0
        if hits:
            return Verdict.block(
                CheckKind.EGRESS,
                check="egress_rules",
                reason=f"output leaked {len(hits)} sensitive item(s)",
                score=0.0,
                latency_ms=lat,
                details={"hits": hits},
            )
        return Verdict.allow(CheckKind.EGRESS, check="egress_rules", latency_ms=lat)


def is_base64_string(s: str) -> bool:
    s = s.strip()
    if len(s) < 24:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=\s]+", s):
        return False
    try:
        base64.b64decode(s, validate=True)
        return True
    except (binascii.Error, ValueError):
        return False


class HashedEmbedding:
    """Deterministic offline token-embedding for cheap similarity scoring.

    Pure-python hashing of n-grams into a fixed-dim vector space. Not a
    semantic embedding — used only to detect *near-duplicate* attack payloads
    against a bank of known-bad prototypes (many attacks are trivially escaped
    variants of a known payload).
    """

    def __init__(self, dim: int = 512, ngram: int = 3):
        self.dim = dim
        self.ngram = ngram

    def vectorize(self, text: str) -> list[float]:
        tokens = re.findall(r"[a-z0-9]+", text.lower())
        vec = [0.0] * self.dim
        joined = " ".join(tokens)
        key = joined if len(joined) >= self.ngram else joined + " " * (self.ngram - len(joined))
        return self._fold(key)

    def _fold(self, key: str) -> list[float]:
        vec = [0.0] * self.dim
        for i in range(0, max(1, len(key) - self.ngram + 1), max(1, len(key) // self.dim)):
            gram = key[i : i + self.ngram]
            h = zlib.crc32(gram.encode()) & 0xFFFFFFFF
            vec[h % self.dim] += 1.0
        norm = (sum(v * v for v in vec) ** 0.5) or 1.0
        return [v / norm for v in vec]

    def similarity(self, a: list[float], b: list[float]) -> float:
        return sum(x * y for x, y in zip(a, b))