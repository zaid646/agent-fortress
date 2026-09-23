"""Render the suite result as a self-contained HTML report + JSON evidence."""
from __future__ import annotations

import json
import os

from jinja2 import Template

from .runner import SuiteResult

_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Agent Fortress — Security Report</title>
<style>
:root{--bg:#0f1115;--fg:#e6e9ef;--muted:#8b93a7;--ok:#2ea043;--bad:#f85149;--warn:#d29922}
*{box-sizing:border-box}body{background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:40px 8vw}
h1{font-size:26px}h2{font-size:19px;margin-top:36px}
.card{background:#161a22;border:1px solid #232a36;border-radius:10px;padding:18px 22px;margin:12px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px}
.metric{background:#161a22;border:1px solid #232a36;border-radius:10px;padding:16px}
.metric .v{font-size:26px;font-weight:700}.metric .k{color:var(--muted);font-size:12px;text-transform:uppercase}
table{width:100%;border-collapse:collapse;margin-top:10px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #232a36}
th{color:var(--muted);font-size:12px;text-transform:uppercase}
.badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:12px;font-weight:600}
.ok{background:#12261a;color:var(--ok)}.bad{background:#2a1416;color:var(--bad)}.warn{background:#2a2112;color:var(--warn)}.muted{background:#1c212b;color:var(--muted)}
blockquote{color:var(--muted);margin:4px 0 0;font-size:12px;white-space:pre-wrap}
</style></head><body>
<h1>🛡️ Agent Fortress — Security Report</h1>
<p class="muted">{{ suite.meta.get('description') }} · {{ suite.meta.get('num_tests') }} tests · generated {{ ts }}</p>
<div class="grid">
  <div class="metric"><div class="v">{{ (suite.asr_naked.get('rag',0)*100)|round(1) }}%</div><div class="k">ASR · RAG (naked)</div></div>
  <div class="metric"><div class="v">{{ (suite.asr_naked.get('agentic',0)*100)|round(1) }}%</div><div class="k">ASR · Agentic (naked)</div></div>
  <div class="metric"><div class="v">{{ (suite.block_rate.get('rag',0)*100)|round(1) }}%</div><div class="k">Block rate · RAG</div></div>
  <div class="metric"><div class="v">{{ (suite.block_rate.get('agentic',0)*100)|round(1) }}%</div><div class="k">Block rate · Agentic</div></div>
  <div class="metric"><div class="v">{{ (suite.false_positive_rate*100)|round(2) }}%</div><div class="k">False-positive rate</div></div>
  <div class="metric"><div class="v">{{ overhead }} ms</div><div class="k">p95 guardrail overhead</div></div>
</div>
<h2>Block layer distribution</h2>
<div class="card">
{% for layer,count in suite.block_layer_distribution.items() %}
  <div><b>{{ layer }}</b>: {{ count }}</div>
{% endfor %}
</div>
<h2>Per-test results</h2>
<table>
  <tr><th>id</th><th>type</th><th>target</th><th>sev</th><th>technique</th><th>naked leak</th><th>defense</th></tr>
{% for r in suite.results %}
  <tr>
    <td>{{ r.test_id }}</td><td>{{ r.attack_type }}</td><td>{{ r.target }}</td>
    <td><span class="badge {{ 'bad' if r.severity=='critical' else ('warn' if r.severity=='high' else 'muted') }}">{{ r.severity }}</span></td>
    <td>{{ r.technique }}</td>
    <td>{{ 'LEAKED' if r.leaked_marker else ('blocked' if r.naked_blocked else '—') }}</td>
    <td>{{ 'SKIPPED' if r.skipped else ('blocked@' + r.block_layer if r.candidate_blocked else 'LEAKED ⚠️') }}</td>
  </tr>
{% endfor %}
</table>
</body></html>
"""


def render_html_report(suite: SuiteResult, out_path: str, timestamp: str) -> str:
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    overhead = max((v["p95_overhead_ms"] for v in suite.latency_overhead_ms.values()), default=0.0)
    html = Template(_TEMPLATE).render(suite=suite, ts=timestamp, overhead=round(overhead, 2))
    with open(out_path, "w") as f:
        f.write(html)
    return out_path


def render_json_report(suite: SuiteResult, out_path: str) -> str:
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    payload = {"summary": suite.summary(), "meta": suite.meta, "results": [r.model_dump() for r in suite.results]}
    with open(out_path, "w") as f:
        json.dump(payload, f, indent=2)
    return out_path