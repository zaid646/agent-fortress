PY=.venv/bin/python

install:
	uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -e ".[dev]"

test:
	$(PY) -m pytest -q

suite:
	$(PY) -m scripts.run_suite

serve:
	$(PY) -m uvicorn target.app:create_app --factory --host 127.0.0.1 --port 8000

bench-llm:
	$(PY) -m scripts.run_suite --llm-phase

up:
	docker compose up -d

down:
	docker compose down

evidence:
	$(PY) -m scripts.capture_evidence

.PHONY: install test suite serve bench-llm up down evidence