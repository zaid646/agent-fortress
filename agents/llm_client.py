"""Provider-agnostic OpenAI-compatible chat client.

Points at any OpenAI-compatible /chat/completions endpoint via env:
    AF_LLM_BASE_URL   (e.g. https://opencode.ai/zen/v1 or a vLLM server)
    AF_LLM_API_KEY
    AF_LLM_MODEL

Works with vLLM on the RTX instance, OpenCode Zen, OpenAI, etc. When no base
URL is configured the client reports `available=False` and callers fall back to
deterministic (template) generation — the suite runs offline with no keys.
"""
from __future__ import annotations

import json
import os


class LLMClient:
    def __init__(self, base_url: str | None = None, api_key: str | None = None, model: str | None = None, timeout: float = 60.0):
        self.base_url = base_url or os.environ.get("AF_LLM_BASE_URL")
        self.api_key = api_key or os.environ.get("AF_LLM_API_KEY") or "not-needed"
        self.model = model or os.environ.get("AF_LLM_MODEL") or "big-pickle"
        self.timeout = timeout
        self._client = None
        if self.base_url:
            from openai import OpenAI

            self._client = OpenAI(base_url=self.base_url, api_key=self.api_key, timeout=timeout)

    @property
    def available(self) -> bool:
        return self._client is not None

    def complete(self, system: str, user: str, max_tokens: int = 512, temperature: float = 0.4) -> str:
        if not self.available:
            raise RuntimeError("LLMClient not configured (set AF_LLM_BASE_URL)")
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return (resp.choices[0].message.content or "").strip()

    def complete_json(self, system: str, user: str, max_tokens: int = 512) -> dict:
        text = self.complete(system, user, max_tokens=max_tokens, temperature=0.0)
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1:
            return {"raw": text}
        return json.loads(text[start : end + 1])