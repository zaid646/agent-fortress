"""Probe service: exposes the RAG and agentic targets over HTTP in {naked,
fortified} modes, plus /metrics for Prometheus.

Run:  uv run uvicorn target.app:create_app --factory --host 127.0.0.1 --port 8000
"""
from __future__ import annotations

import os
import time

from fastapi import FastAPI
from fastapi.responses import Response
from pydantic import BaseModel

from agents.llm_client import LLMClient
from config.settings import CORPUS_DIR, TARGET_WORKSPACE
from guardrails.engine import Fortress
from orchestrator import metrics as M
from target.agentic import AgenticTarget
from target.corpus import load_documents
from target.rag import RagTarget


class ProbeIn(BaseModel):
    query: str
    session: str = "default"


class SuiteMetricsIn(BaseModel):
    attack_success_rate: dict[str, float] = {}
    block_rate: dict[str, float] = {}
    false_positive_rate: float = 0.0
    guardrail_overhead_ms: float = 0.0


def _instrumented(target_obj, target: str, mode: str):
    def _run(payload: ProbeIn) -> dict:
        started = time.perf_counter()
        resp = target_obj.query(payload.query, payload.session)
        latency_s = time.perf_counter() - started
        M.record_probe(target, mode, latency_s)
        if resp.blocked:
            reason = resp.block_reason
            if "BLOCKED_INGRESS" in reason:
                M.record_block("ingress")
            elif "BLOCKED_TOOL" in reason:
                M.record_block("tool")
            elif "BLOCKED_EGRESS" in reason:
                M.record_block("egress")
        return resp.model_dump()

    return _run


def create_app() -> FastAPI:
    app = FastAPI(title="Agent Fortress Probe Service", version="0.1.0")

    docs = load_documents(CORPUS_DIR)
    fortress = Fortress()  # deep checker auto-enables if AF_DEEP_* env set
    # Target-side LLM generation is OPT-IN and separate from the attacker LLM
    # (AF_LLM_BASE_URL). Without AF_TARGET_LLM_BASE_URL the targets stay in
    # deterministic offline mode so bench markers are reproducible.
    llm = LLMClient() if os.environ.get("AF_TARGET_LLM_BASE_URL") else None

    rag_naked = RagTarget(docs, fortress=None, llm=llm)
    rag_fort = RagTarget(docs, fortress=fortress, llm=llm)
    agentic_naked = AgenticTarget(TARGET_WORKSPACE, fortress=None, llm=llm)
    agentic_fort = AgenticTarget(TARGET_WORKSPACE, fortress=fortress, llm=llm)

    targets = {
        "rag/naked": _instrumented(rag_naked, "rag", "naked"),
        "rag/fortified": _instrumented(rag_fort, "rag", "fortified"),
        "agentic/naked": _instrumented(agentic_naked, "agentic", "naked"),
        "agentic/fortified": _instrumented(agentic_fort, "agentic", "fortified"),
    }

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "deep_enabled": fortress.deep.enabled}

    @app.post("/probe/{target}/{mode}")
    def probe(target: str, mode: str, payload: ProbeIn) -> dict:
        key = f"{target}/{mode}"
        if key not in targets:
            return {"error": f"unknown target/mode: {key}"}
        return targets[key](payload)

    @app.post("/metrics/suite")
    def suite_metrics(payload: SuiteMetricsIn) -> dict:
        for target, rate in (payload.attack_success_rate or {}).items():
            M.ATTACK_SUCCESS_RATE.labels(target=target).set(rate)
        for target, rate in (payload.block_rate or {}).items():
            M.BLOCK_RATE.labels(target=target).set(rate)
        M.FALSE_POSITIVE_RATE.set(payload.false_positive_rate)
        M.GUARDRAIL_OVERHEAD_MS.set(payload.guardrail_overhead_ms)
        return {"status": "ok"}

    @app.get("/metrics")
    def metrics() -> Response:
        from prometheus_client import generate_latest

        return Response(generate_latest(), media_type="text/plain")

    return app


app = create_app()