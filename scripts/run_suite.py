"""End-to-end suite runner.

Starts the probe service, runs the full attack suite against naked + fortified
targets, and writes report/report.html + report/report.json.

Usage:
    python -m scripts.run_suite [--port 8000] [--report-dir report] [--llm-phase]
"""
from __future__ import annotations

import argparse
import datetime
import os
import subprocess
import sys
import time
import urllib.request

from agents.attacker import AttackerAgent
from agents.llm_client import LLMClient
from attacks import load_catalog
from config.settings import CATALOG_PATH, REPORT_DIR
from orchestrator import publish_suite_metrics, render_html_report, render_json_report, run_suite


def _wait_ready(port: int, tries: int = 30) -> None:
    for _ in range(tries):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as r:
                if r.status == 200:
                    return
        except Exception:  # noqa: BLE001
            time.sleep(0.5)
    raise RuntimeError("probe service did not become ready")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=int(os.environ.get("AF_PROBE_PORT", "8000")))
    ap.add_argument("--report-dir", default=REPORT_DIR)
    ap.add_argument("--llm-phase", action="store_true", help="attempt LLM-crafted tests (requires AF_LLM_BASE_URL)")
    ap.add_argument("--no-server", action="store_true", help="assume probe service already running")
    args = ap.parse_args()

    base = f"http://127.0.0.1:{args.port}"
    naked = {"rag": f"{base}/probe/rag/naked", "agentic": f"{base}/probe/agentic/naked"}
    fortified = {"rag": f"{base}/probe/rag/fortified", "agentic": f"{base}/probe/agentic/fortified"}

    server = None
    if not args.no_server:
        env = dict(os.environ)
        env["AF_PROBE_PORT"] = str(args.port)
        server = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "target.app:create_app", "--factory", "--host", "127.0.0.1", "--port", str(args.port)],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            env=env,
        )
        _wait_ready(args.port)

    try:
        catalog = load_catalog(CATALOG_PATH)
        llm = LLMClient()  # available only if AF_LLM_BASE_URL configured
        attacker = AttackerAgent(catalog, llm=llm)
        suite = run_suite(
            catalog,
            naked_urls=naked,
            fortified_urls=fortified,
            attacker=attacker,
            llm=llm,
            phases={} if args.llm_phase else {t.test_id: "deterministic" for t in catalog.tests},
        )
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        render_html_report(suite, os.path.join(args.report_dir, "report.html"), ts)
        render_json_report(suite, os.path.join(args.report_dir, "report.json"))
        try:
            publish_suite_metrics(suite, base)
        except Exception:  # noqa: BLE001
            print("warn: could not publish suite gauges to probe /metrics/suite", file=sys.stderr)
        import pprint

        pprint.pprint(suite.summary())
        return 0 if suite.block_rate.get("rag", 0) > 0.9 and suite.block_rate.get("agentic", 0) > 0.9 else 1
    finally:
        if server:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()


if __name__ == "__main__":
    sys.exit(main())