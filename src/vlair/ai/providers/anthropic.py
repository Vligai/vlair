"""
vlair AI Providers — Anthropic Claude implementation.
"""

import os
from typing import Optional

from .base import AIProvider, AIResponse

_DEFAULT_MODEL = "claude-sonnet-4-6"


class AnthropicProvider(AIProvider):
    """
    AI provider backed by Anthropic's Claude API.

    Requires the ANTHROPIC_API_KEY environment variable.
    The ``anthropic`` Python package is imported lazily so that the rest of
    vlair works even when the package is not installed.
    """

    def __init__(self, model: Optional[str] = None, temperature: float = 0.2) -> None:
        self._model = model or os.getenv("ANTHROPIC_MODEL", _DEFAULT_MODEL)
        self.temperature = temperature
        self._client = None  # lazy-initialised

    # ------------------------------------------------------------------
    # AIProvider interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "anthropic"

    @property
    def model(self) -> str:
        return self._model

    def is_available(self) -> bool:
        """Return True if ANTHROPIC_API_KEY is set."""
        return bool(os.getenv("ANTHROPIC_API_KEY"))

    def analyze(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: int = 2000,
        thinking: bool = False,
        thinking_budget_tokens: int = 8000,
    ) -> AIResponse:
        """Call Claude and return an AIResponse."""
        client = self._get_client()

        create_kwargs: dict = {
            "model": self._model,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_message}],
        }

        if thinking:
            # Extended thinking requires max_tokens > budget; no temperature param
            budget = min(thinking_budget_tokens, max(max_tokens - 1024, 1024))
            create_kwargs["max_tokens"] = max(max_tokens, budget + 1024)
            create_kwargs["thinking"] = {"type": "enabled", "budget_tokens": budget}
        else:
            create_kwargs["max_tokens"] = max_tokens
            create_kwargs["temperature"] = self.temperature

        response = client.messages.create(**create_kwargs)

        thinking_trace: Optional[str] = None
        text_content = ""
        for block in response.content:
            block_type = getattr(block, "type", None)
            if block_type == "thinking":
                thinking_trace = getattr(block, "thinking", None)
            elif block_type == "text":
                text_content = getattr(block, "text", "")

        if not text_content and response.content:
            text_content = getattr(response.content[0], "text", "")

        tokens_used = response.usage.input_tokens + response.usage.output_tokens

        return AIResponse(
            content=text_content,
            tokens_used=tokens_used,
            model=self._model,
            cached=False,
            provider=self.name,
            thinking_trace=thinking_trace,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_client(self):
        if self._client is None:
            try:
                import anthropic  # noqa: PLC0415

                self._client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
            except ImportError as exc:
                raise ImportError("The 'anthropic' package is required. Install it with: pip install anthropic") from exc
        return self._client
