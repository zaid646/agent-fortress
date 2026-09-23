# Architecture

## Goals
1. Measure a real attack exposure (ASR) on RAG + agentic systems.
2. Show a production-plausible guardrail stack that neutralizes those attacks
   with bounded latency (<50 ms p95) and low false positives.
3. Reproduce all of it anywhere — offline and deterministic.

## Pipeline

```
catalog.yaml ─▶ load_catalog ─▶ AttackCatalog
                                    │
              AttackerAgent (LangGraph: pick→gen→run→judge→[gen|END])
                                    │  /probe/<target>/<mode>,
                                    │  multi-turn (drip) replay
                          ┌─────────▼──────────┐
                          │   FastAPI targets  │
                          │  rag.py agentic.py │
                          └─────────┬──────────┘
                                    │  fortress hooks
                          ┌─────────▼──────────┐
                          │  Fortress          │  ← THE PRODUCT
                          └─────────┬──────────┘
                                    │  verdicts
                    run_suite → SuiteResult ─▶ report.html / report.json
                                    │
                              Prometheus ─▶ Grafana ─▶ evidence/*.png
```

## The Fortress middleware

Layered, cost-ordered, provider-agnostic. Drop it in front of any
LangGraph/LangChain/FastAPI app: `check_input → run → check_tool* → check_output`.

```
┌─────────────────────────────────────────────────────────┐
│ INGRESS   check_input(query)                            │
│   1. regex rules                <100 µs                 │
│   2. attack-bank similarity     ~2 ms (hash embedding)  │
│   3. deep classifier (optional) only if flag_suspicious │
├─────────────────────────────────────────────────────────┤
│ TOOL      check_tool(name, args)      allowlist         │
│   denied: delete_files, shell_exec, drop_database       │
│   path-traversal in any arg → block                     │
│   sensitive_output tools → require egress verification  │
├─────────────────────────────────────────────────────────┤
│ EGRESS    check_output(text)                            │
│   PII rules + exact sensitive-term blocklist            │
└─────────────────────────────────────────────────────────┘
```

The deep classifier (e.g. ShieldGemma-9B served via vLLM) is **off the happy
path** — only traffic the cheap layers already flagged as suspicious is sent for
model review, which is how p50 stays under the budget. It is fail-closed: if it
is configured but unreachable, the fortress blocks rather than falls through.

## Why determinism matters

LLM-behavior is stochastic; benchmarks built on stochastic verdicts can't gate
CI. So every catalog test carries a **success marker** (a supplied watermark the
payload is designed to make the target emit), and every target is deterministic:

- RAG retrieval uses exact hashed-embedding similarity (no external vector DB).
- Target generators reply verbatim when their trigger conditions match and embed
  the expected marker; otherwise they answer blandly.
- `deterministic: false` tests (llm-crafted) are excluded unless an attacker LLM
  is configured, and their judged success still requires the watermark.

The same markers double as the fortress egress blocklist in `DEFAULT_SENSITIVE_TERMS`,
making "the fortress blocks exactly these attacks" an inspectable, testable claim.

## Semi-synthetic vulnerability model

Neither target is a toy string-matcher; both implement the *failure modes* real
apps ship with:

- **RAG**: retrieval from an in-memory corpus, per-session memory that
  "summarizes" across turns (drip), a base64 request-decode channel, a generator
  that parrots system prompt / chain-of-thought when asked, and summarizes
  *retrieved* content verbatim (the poisoned-doc vector).
- **Agentic**: a planner that maps user intent → tools, including
  `read_file` (no containment), `query_customer_db`, `read_secrets_file`,
  `delete_files`, `shell_exec`. Attack outcomes are gated on the predicted tool
  call actually executing and its output reaching the user.

The fortress is evaluated *across the board*, not just on the attacks it was
built for — benign probes exercise FP rate, and every verdict records which
layer fired so the defense story is auditable.

## Telemetry & evidence

- Prometheus counters/histograms: `agent_fortress_probe_total{target,mode,result}`,
  `probe_latency_seconds`, `attacks_total`, `blocks_total`, per-layer
  `block_layer_total`, plus `attack_success_rate`, `block_rate`,
  `false_positive_rate`, `guardrail_overhead_ms` gauges baked at suite end.
- Grafana dashboards are auto-provisioned (`dashboard/grafana/*`); screenshots
  are saved to `evidence/` (plain desktop or Playwright-driven) and committed.
- `report/report.json` is machine-readable; `report/report.html` is self-contained.

## Deployment notes

- **Local**: `docker compose up -d` (probe + Prometheus + Grafana).
- **GPU instance (Vast.ai, no Docker-in-Docker)**: `deploy/vast.sh` installs the
  GPU extras, runs uvicorn on the free internal port, and runs Prometheus +
  Grafana as community binaries. Forward ports with ssh -L and screenshot.
- **Env vars**: `AF_*` (catalog/corpus/workspace/report paths),
  `AF_LLM_BASE_URL/AF_LLM_API_KEY/AF_LLM_MODEL` (attacker model),
  `AF_DEEP_BASE_URL/AF_DEEP_API_KEY/AF_DEEP_MODEL` (guardrail classifier).