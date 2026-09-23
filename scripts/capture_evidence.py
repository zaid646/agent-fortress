"""Capture Grafana evidence screenshots into evidence/.

Uses Playwright (chromium). Panels must be reachable at the given Grafana URL,
which is typically an ssh -L forwarded local port.

Usage:
    python -m scripts.capture_evidence [--grafana-url http://localhost:3000] [--dir evidence]
"""
from __future__ import annotations

import argparse
import datetime
import os

from config.settings import EVIDENCE_DIR

DASHBOARD = "/d/agent-fortress-ops/agent-fortress-live-red-team-bench"
PANELS = {
    "overview": "?viewPanel=1&orgId=1&from=now-30m&to=now",
    "blocked_over_time": "?viewPanel=7&orgId=1&from=now-30m&to=now",
    "latency_over_time": "?viewPanel=8&orgId=1&from=now-30m&to=now",
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--grafana-url", default="http://localhost:3000")
    ap.add_argument("--dir", default=EVIDENCE_DIR)
    ap.add_argument("--browser", default="chromium")
    args = ap.parse_args()

    from playwright.sync_api import sync_playwright

    os.makedirs(args.dir, exist_ok=True)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    with sync_playwright() as p:
        browser = getattr(p, args.browser).launch()
        page = browser.new_page(viewport={"width": 1920, "height": 1080})
        page.goto(args.grafana_url, wait_until="networkidle")
        page.wait_for_timeout(1500)
        for name, qs in PANELS.items():
            page.goto(args.grafana_url + DASHBOARD + qs, wait_until="networkidle")
            page.wait_for_timeout(2500)
            out = os.path.join(args.dir, f"{ts}_{name}.png")
            page.screenshot(path=out, full_page=True)
            print(f"saved {out}")
        browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())