# Evidence index

Real-time monitoring screenshots, the final benchmark report, live traffic
demos, and Prometheus stats from the GPU run (RTX 4090, deep guard enabled).

## 01-grafana — live dashboard (localhost:3000)

| file | what it shows |
|---|---|
| `dashboard.png` | Grafana "Agent Fortress — Live Red-Team Bench": block rate 1.0/1.0, ASR 0.8333 rag / 1.0 agentic, FP rate 0.0833, guardrail overhead p95 145 ms, blocked-probes timeseries |
| `probe_metrics.txt` | full Prometheus scrape of the probe (`/metrics`) at evidence time |
| `prometheus_queries.json` | Prometheus API instant queries: `af_block_rate`, `af_attack_success_rate`, `af_false_positive_rate`, `af_guardrail_overhead_ms` |
| `live_probe.json` | `/health` (`deep_enabled:true`) + two benign live probes allowed on the fast path |

## 02-suite — benchmark results

| file | what it shows |
|---|---|
| `report.html.png` | rendered security report: 11 tests, per-test attack/block/latency detail |
| `../../report/report.json` | machine-readable results incl. summary (`asr_naked`, `block_rate`, `false_positive_rate`, `latency_overhead_ms`, `block_layer_distribution`) |
| `../../report/report.html` | same report, standalone HTML |
| `loadtest_stats.csv` | Locust load test: 1748 requests, 0% failures, mean 2.45 ms |

## 03-prometheus — real-time monitoring (localhost:9090)

| file | what it shows |
|---|---|
| `targets.png` | scrape targets page: `agent-fortress` job health |
| `graph_block_rate.png` | instant graph of `af_block_rate | af_attack_success_rate | af_false_positive_rate` |
| `graph_p95_latency.png` | `histogram_quantile(0.95, ...af_probe_latency_seconds_bucket)` — naked vs fortified p95 per target |

## 04-live — live traffic against the running fortress

| file | what it shows |
|---|---|
| `live_demos.txt` | real requests against the live probe: ingress block, egress block, **ShieldGemma deep-guard block**, benign allowed (~1 ms); ShieldGemma Safe/Unsafe verdicts with latencies; attacker vLLM model list; Prometheus instant queries; scrape health |

Headline numbers (from the final GPU suite, deep guard on):

- ASR naked: rag 83.3% / agentic 100% · fortified block rate: **100% / 100%**
- False-positive rate: 8.3% (1/12 benign, watch-tier classifier)
- Overhead p95: rag 2.9 ms · agentic 287 ms (includes ShieldGemma deep checks)
- Blocks by layer: ingress 7, egress 3, deep classifier 3 (agentic suite run)
- skipped tests: 0
