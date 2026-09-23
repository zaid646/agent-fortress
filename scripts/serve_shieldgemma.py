"""Serve ShieldGemma (base classifier) over an OpenAI-compatible HTTP API.

ShieldGemma is a safety *classifier*: it answers in its pretraining format
(Safe / Unsafe + categories) given a "[Task Description] ... [User Prompt]"
turn — which DeepChecker already sends. vLLM can crash-loop this model on some
hosts, so a slim in-process transformers wrapper is more dependable for the
deep-guard workload (watch-tier traffic only).

Usage:
    /venv/main/bin/python -m scripts.serve_shieldgemma --port 10201

Endpoints (OpenAI-compatible subset used by the deep checker):
    GET  /v1/models
    POST /v1/chat/completions   -- replies with a bare verdict token
    GET  /health
"""
from __future__ import annotations

import argparse
import os
import threading

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

MODEL_ID = os.environ.get("SG_MODEL", "google/shieldgemma-2b")
SERVED_NAME = os.environ.get("SG_SERVED_NAME", "shieldgemma-2b")

_app: FastAPI | None = None
_tokenizer = None
_model = None
_lock = threading.Lock()


def _load() -> None:
    global _tokenizer, _model, _app
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    _tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    _model = AutoModelForCausalLM.from_pretrained(MODEL_ID, dtype=torch.bfloat16).to("cuda")
    _model.eval()


def _classify(text: str, max_new_tokens: int) -> str:
    import torch

    with _lock:
        inputs = _tokenizer(text, return_tensors="pt").to(_model.device)
        with torch.inference_mode():
            out = _model.generate(**inputs, max_new_tokens=max_new_tokens, do_sample=False)
        return _tokenizer.decode(out[0][inputs.input_ids.shape[1]:], skip_special_tokens=True).strip()


def create_app() -> FastAPI:
    global _app
    if _app is not None:
        return _app
    _load()

    app = FastAPI(title="ShieldGemma Classifier Service", version="0.1.0")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "model": SERVED_NAME}

    @app.get("/v1/models")
    def models() -> dict:
        return {"object": "list", "data": [{"id": SERVED_NAME, "object": "model", "owned_by": "google"}]}

    @app.post("/v1/chat/completions")
    async def chat_completions(req: Request) -> JSONResponse:
        body = await req.json()
        messages = body.get("messages") or []
        text = "\n".join(m.get("content", "") for m in messages if m.get("role") == "user")
        if not text:
            return JSONResponse({"choices": [{"message": {"role": "assistant", "content": ""}}]})
        max_tokens = int(body.get("max_tokens") or 24)
        verdict = _classify(text, max_tokens)
        return JSONResponse(
            {
                "id": "sg-" + verdict[:12],
                "object": "chat.completion",
                "model": SERVED_NAME,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": verdict}, "finish_reason": "stop"}],
            }
        )

    _app = app
    return app


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=10201)
    args = ap.parse_args()
    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())