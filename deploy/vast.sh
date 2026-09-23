#!/usr/bin/env bash
# Bootstrap Agent Fortress on a Vast.ai GPU instance (no Docker-in-Docker):
#   - install deps (incl. GPU extras for vLLM) into the active venv
#   - start uvicorn on the internal free port (default 10100)
#   - download prometheus + grafana binaries, provision dashboards, daemonize
# Run from the repo root that was rsynced to /workspace/agent-fortress.
set -euo pipefail

PORT=${AF_PROBE_PORT:-10100}
REPO=${PWD}
VENV="${VENV:-/venv/main}"

echo "==> Installing project (GPU extras) into ${VENV}"
"${VENV}/bin/pip" install -e ".[gpu,loadtest]" --quiet

echo "==> Probe service on :${PORT}"
AF_PROBE_PORT=${PORT} AF_TARGET_WS=/workspace/data/sandbox \
  nohup "${VENV}/bin/uvicorn" target.app:create_app --factory --host 0.0.0.0 --port "${PORT}" \
  >> /workspace/agent-fortress-probe.log 2>&1 &

echo "==> Prometheus"
PROM_VERSION=2.53.0
if ! command -v prometheus >/dev/null 2>&1; then
  wget -q "https://github.com/prometheus/prometheus/releases/download/v${PROM_VERSION}/prometheus-${PROM_VERSION}.linux-amd64.tar.gz" -O /tmp/prom.tgz
  mkdir -p /opt/prom && tar -xzf /tmp/prom.tgz -C /opt/prom --strip-components=1
fi
sed "s/localhost:8000/0.0.0.0:${PORT}/" metrics/prometheus/prometheus.yml > /workspace/prometheus.yml
nohup /opt/prom/prometheus --config.file=/workspace/prometheus.yml --storage.tsdb.path=/workspace/prom-data \
  >> /workspace/prometheus.log 2>&1 &

echo "==> Grafana"
GRAFANA_VERSION=11.1.0
if ! command -v grafana-server >/dev/null 2>&1; then
  wget -q "https://dl.grafana.com/oss/release/grafana-${GRAFANA_VERSION}.linux-amd64.tar.gz" -O /tmp/grafana.tgz
  mkdir -p /opt/grafana && tar -xzf /tmp/grafana.tgz -C /opt/grafana --strip-components=1
fi
mkdir -p /workspace/grafana-{data,conf}
cp -r dashboard/grafana /workspace/grafana-conf/ 2>/dev/null || true
cat > /workspace/grafana.ini <<EOF
[server]
http_port = 10100
[auth.anonymous]
enabled = true
[paths]
data = /workspace/grafana-data
provisioning = /workspace/grafana-conf
EOF
nohup /opt/grafana/bin/grafana-server -config /workspace/grafana.ini \
  >> /workspace/grafana.log 2>&1 &

echo "==> done. probe=:${PORT} prometheus=:9090 grafana=:10100/port-forward"
echo "    ssh -L 3000:localhost:10100 -L 9090:localhost:9090 ..."