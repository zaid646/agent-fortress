# 🛡️ Agent Fortress

Automated red-teaming + production guardrail framework for **RAG** and **agentic**
LLM systems. Red-team the system, harden it with a composable firewall, and get
**evidence** (block rates, ASR, latency overhead) out of every run.

```
┌────────────┐   HTTP /probe  ┌───────────────────┐
│ Attacker   │ ─────────────▶ │  Vulnerable       │   naked   → baseline ASR
│ (LangGraph)│ ◀───────────── │  Target           │   fortified→ fortress defense
└─────┬──────┘   responses    │  (RAG | Agentic)  │
      │                       └─────────┬─────────┘
      │                                 │ fortress middleware
      │                       ┌─────────▼─────────┐
      └──────────────────────▶│  Prometheus       │  → Grafana dashboards
        bench suite           └───────────────────┘  → evidence screenshots
```

## Quickstart (offline, no API keys)

```bash
uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -e ".[dev]"
.venv/bin/python -m pytest                      # unit + e2e (TestClient)
.venv/bin/python -m scripts.run_suite           # full red-team bench + report
open report/report.html
```

The suite is fully deterministic — attackers, targets, and verdicts all run
locally with **zero tokens**. The two `llm-crafted` tests are skipped unless an
attacker LLM is configured (see below).

## Results

| metric | expected | measured (offline mock) | measured (GPU: Qwen attacker + ShieldGemma deep) |
|---|---|---|---|
| Attack success rate (naked) — RAG / agentic | baseline | 100% / 100% | 83.3% / 100% |
| Block rate (fortified) — RAG / agentic | >90% | 100% / 100% | 100% / 100% |
| False-positive rate | <5% | 0% | 8.3% |
| Guardrail overhead p95 | <50 ms | ~1 ms | 2.9 ms RAG / 287 ms agentic* |

*The agentic p95 includes LLM deep-check inference on watch-tier traffic
(ShieldGemma-2B, batched transformers on the same GPU — latency, not loss).

On the GPU run the two `llm-crafted` tests execute against the live Qwen
attacker; neither leaks a watermark on the fortified target (block rate stays
100%). The rag one is caught on the egress layer; the agentic one's payload
fails its own tool/egress checks (the attacker's own re-generation degraded).
The one false positive is a benign agentic query whose phrasing overlaps a
filesystem-escapade prototype, which the conservative classifier flags; a
benign-traffic corpus for the watch tier removes it.

## How it works

- **Attacker** ([`agents/attacker.py`](agents/attacker.py)) — a LangGraph state
  machine (`pick → gen → run → judge`) that works single- or multi-turn
  (context drip, LLM re-crafting). Payloads come from
  [`attacks/catalog.yaml`](attacks/catalog.yaml) (OWASP LLM Top-10 / MITRE ATLAS
  mapped), and each carries a **success marker** so outcomes are machine-checkable.
- **Targets** ([`target/rag.py`](target/rag.py), [`target/agentic.py`](target/agentic.py))
  — vulnerable-by-design apps the suite probes over HTTP (`POST /probe/rag/{naked,fortified}`,
  `POST /probe/agentic/{naked,fortified}`).
- **Fortress** ([`guardrails/engine.py`](guardrails/engine.py)) — the product.
  Provider-agnostic middleware you can drop in front of any agent:
  - **ingress** — regex rules → near-duplicate "known attack" bank (hash-embedding
    similarity, ~2 ms) → optional LLM deep-check (fail-closed, `AF_DEEP_*`);
  - **tool guard** — per-tool allowlist (deny `delete_files` / `shell_exec`,
    block path traversal, require egress verification for sensitive tools);
  - **egress** — DLP rules (SSN, cards, emails, keys) + exact sensitive-term
    blocklist for red-team watermarks.
- **Bench** ([`orchestrator/runner.py`](orchestrator/runner.py)) — drives each
  attack at the naked + fortified endpoints, computes ASR / block rate / FP rate
  / latency overhead, and publishes the numbers to Prometheus
  ([`orchestrator/metrics.py`](orchestrator/metrics.py)) for Grafana.

## Repo layout

```
attacks/     attack taxonomy & payload catalog
agents/      LangGraph attacker + LLM client
guardrails/  Fortress middleware (the product)
target/      RAG + agentic targets + FastAPI probe service
orchestrator suite runner, metrics, report renderer
tests/       pytest suite (offline, deterministic)
configuration settings, docs
deploy/      docker-compose (local) + vast.sh (GPU instance bootstrap)
dashboard/   Grafana provisioning
metrics/     Prometheus config
evidence/    Grafana screenshots (committed, see ARCHITECTURE)
```

## GPU phase (Vast.ai / RTX 4090)

With a rented GPU instance and an LLM endpoint you unlock:

1. **LLM-crafted attacks** — `AF_LLM_BASE_URL/AF_LLM_API_KEY/AF_LLM_MODEL`
   (attacker re-writes payloads against live targets; successes still gated on
   the watermark marker). Run suite with `--llm-phase`.
2. **Deep guardrail classifier** — serve [ShieldGemma](https://ai.google.dev/gemma/docs/shieldgemma)
   (either the gated `-it` variant through vLLM, or the open `shieldgemma-2b`
   base through the bundled [`scripts/serve_shieldgemma.py`](scripts/serve_shieldgemma.py)
   OpenAI-compatible transformers service — the base model fails closed on
   vLLM on some hosts). Set `AF_DEEP_BASE_URL/AF_DEEP_MODEL` and the fortress
   upgrades from heuristic-only to classifier-backed for suspicious traffic:
   benign traffic stays on the sub-ms path, only the ambiguous watch band hits
   the model.
3. **Load testing** — `locust` against the fortified endpoints
   (`.venv/bin/locust -f scripts/locustfile.py`) to measure latency overhead
   under concurrency.

`deploy/vast.sh` bootstraps all of the above on the instance (uvicorn on the
free internal port, Prometheus + Grafana as binaries — no Docker-in-Docker).

## Evidence

Every bench run produces `report/report.json` + a self-contained HTML report;
Grafana dashboards are screenshotted into `evidence/` and committed.

## License

Apache-2.0. Not affiliated with/endorsed by any company or model provider.