"""
vlair AI Providers — Ollama local LLM implementation.
"""

import os
from typing import Optional

from .base import AIProvider, AIResponse

_DEFAULT_ENDPOINT = "http://localhost:11434"
_DEFAULT_MODEL = "llama3"


class OllamaProvider(AIProvider):
    """
    AI provider backed by a local Ollama instance.

    Uses the Ollama REST API directly (no Python SDK required).
    The endpoint and model are configurable via environment variables:
      - OLLAMA_ENDPOINT  (default: http://localhost:11434)
      - OLLAMA_MODEL     (default: llama3)
    """

    def __init__(self, model: Optional[str] = None, endpoint: Optional[str] = None) -> None:
        self._endpoint = (endpoint or os.getenv("OLLAMA_ENDPOINT", _DEFAULT_ENDPOINT)).rstrip("/")
        self._model = model or os.getenv("OLLAMA_MODEL", _DEFAULT_MODEL)

    # ------------------------------------------------------------------
    # AIProvider interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "ollama"

    @property
    def model(self) -> str:
        return self._model

    def is_available(self) -> bool:
        """Return True if the Ollama endpoint responds to a GET /api/tags request."""
        try:
            import requests  # noqa: PLC0415

            resp = requests.get(f"{self._endpoint}/api/tags", timeout=3)
            return resp.status_code == 200
        except Exception:
            return False

    def analyze(self, system_prompt: str, user_message: str, max_tokens: int = 2000) -> AIResponse:
        """Call the Ollama /api/chat endpoint and return an AIResponse."""
        try:
            import requests  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError("The 'requests' package is required for OllamaProvider.") from exc

        payload = {
            "model": self._model,
            "stream": False,
            "options": {"num_predict": max_tokens},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
        }

        resp = requests.post(
            f"{self._endpoint}/api/chat",
            json=payload,
            timeout=120,
        )
        resp.raise_for_status()
        data = resp.json()

        content = ""
        if "message" in data and "content" in data["message"]:
            content = data["message"]["content"]

        # Ollama does not always report token counts; fall back to 0.
        tokens_used = data.get("eval_count", 0) + data.get("prompt_eval_count", 0)

        return AIResponse(
            content=content,
            tokens_used=tokens_used,
            model=self._model,
            cached=False,
            provider=self.name,
        )
