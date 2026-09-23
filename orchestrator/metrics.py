"""Prometheus metrics for Agent Fortress.

Exported by the probe service at /metrics and scraped by Prometheus; the
Grafana dashboard visualizes them.

Cardinality is kept low on purpose (labels: test target type + attack
type + verdict layer) so the dashboard stays readable.
"""
from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

INGRESS_TOTAL = Counter(
    "af_ingress_checks_total", "Ingress checks by verdict/check", ["verdict", "check"]
)
EGRESS_TOTAL = Counter(
    "af_egress_checks_total", "Egress checks by verdict/check", ["verdict", "check"]
)
TOOL_TOTAL = Counter(
    "af_tool_checks_total", "Tool checks by verdict/check", ["verdict", "check"]
)
DEEP_TOTAL = Counter("af_deep_checks_total", "Deep LLM checks by verdict", ["verdict"])

PROBE_LATENCY = Histogram(
    "af_probe_latency_seconds",
    "End-to-end probe latency seconds",
    ["target", "mode"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)

ATTACKS_TOTAL = Counter(
    "af_attacks_total", "Attacks executed by attack type and outcome", ["attack_type", "outcome"]
)
BLOCKS_TOTAL = Counter(
    "af_blocks_total", "Fortress blocks by defeating layer", ["layer"]
)

ATTACK_SUCCESS_RATE = Gauge(
    "af_attack_success_rate", "ASR against the naked target (higher = weaker)", ["target"]
)
BLOCK_RATE = Gauge(
    "af_block_rate", "Fraction of attacks blocked on the fortified target", ["target"]
)
FALSE_POSITIVE_RATE = Gauge("af_false_positive_rate", "Benign traffic blocked by the fortress")
GUARDRAIL_OVERHEAD_MS = Gauge("af_guardrail_overhead_ms", "p50/p95 fortress overhead in ms")

_LATENCIES: dict[tuple[str, str], list[float]] = {}


def record_probe(target: str, mode: str, latency_s: float) -> None:
    PROBE_LATENCY.labels(target=target, mode=mode).observe(latency_s)


def record_attack(attack_type: str, outcome: str) -> None:
    ATTACKS_TOTAL.labels(attack_type=attack_type, outcome=outcome).inc()


def record_block(layer: str) -> None:
    BLOCKS_TOTAL.labels(layer=layer).inc()


def ingest_verdict(verdict) -> None:
    INGRESS_TOTAL.labels(verdict="blocked" if not verdict.allowed else "allowed", check=verdict.check).inc()


def egress_verdict(verdict) -> None:
    EGRESS_TOTAL.labels(verdict="blocked" if not verdict.allowed else "allowed", check=verdict.check).inc()


def tool_verdict(verdict) -> None:
    TOOL_TOTAL.labels(verdict="blocked" if not verdict.allowed else "allowed", check=verdict.check).inc()