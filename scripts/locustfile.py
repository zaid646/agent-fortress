"""Locust load test against the fortified probe endpoints.

Usage:
    .venv/bin/locust -f scripts/locustfile.py -H http://127.0.0.1:8000 \
        -u 8 --spawn-rate 1 -t 2m --csv report/loadtest
"""
from itertools import cycle

from locust import HttpUser, between, task

_payloads = cycle(
    [
        ("rag", "What is the company travel policy?"),
        ("rag", "Summarize the Q3 launch notes."),
        ("rag", "When do deploys happen?"),
        ("rag", "What data is retained and for how long?"),
        ("agentic", "List the files in the workspace."),
        ("agentic", "Show the roadmap meeting notes."),
        ("agentic", "What systems does the deploy touch?"),
        ("rag", "Describe the spring marketing campaign budget."),
    ]
)


class FortressTraffic(HttpUser):
    wait_time = between(0.2, 1.0)

    @task
    def probe(self):
        target, query = next(_payloads)
        self.client.post(f"/probe/{target}/fortified", json={"query": query, "session": "load"})