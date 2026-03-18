"""
vlair AI Providers — Anthropic Claude implementation.

Uses BeskarClient when available for automatic prompt caching and token metrics.
Falls back to plain anthropic.Anthropic if beskar is not installed.
"""

import os
from typing import Optional

from .base import AIProvider, AIResponse

_DEFAULT_MODEL = "claude-sonnet-4-6"


class AnthropicProvider(AIProvider):
    """
    AI provider backed by Anthropic's Claude API.

    When ``beskar`` is installed, wraps the client in BeskarClient to enable:
    - Prompt caching (cache_control on system prompts ≥ 1024 tokens)
    - Per-call token metrics and estimated cost/savings tracking

    Requires the ANTHROPIC_API_KEY environment variable.
    The ``anthropic`` Python package is imported lazily so that the rest of
    vlair works even when the package is not installed.
    """

    def __init__(self, model: Optional[str] = None, temperature: float = 0.2) -> None:
        self._model = model or os.getenv("ANTHROPIC_MODEL", _DEFAULT_MODEL)
        self.temperature = temperature
        self._client = None  # lazy-initialised
        self._using_beskar = False

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

    def analyze(self, system_prompt: str, user_message: str, max_tokens: int = 2000) -> AIResponse:
        """Call Claude and return an AIResponse."""
        client = self._get_client()

        response = client.messages.create(
            model=self._model,
            max_tokens=max_tokens,
            temperature=self.temperature,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )

        content = response.content[0].text if response.content else ""
        usage = response.usage
        tokens_used = usage.input_tokens + usage.output_tokens
        cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0
        cache_creation = getattr(usage, "cache_creation_input_tokens", 0) or 0

        return AIResponse(
            content=content,
            tokens_used=tokens_used,
            model=self._model,
            cached=False,
            provider=self.name,
            cache_read_tokens=cache_read,
            cache_creation_tokens=cache_creation,
        )

    def get_metrics(self):
        """Return cumulative BeskarClient token metrics, or None if not using beskar."""
        if self._using_beskar and self._client is not None:
            return self._client.metrics.summary()
        return None

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_client(self):
        if self._client is not None:
            return self._client

        api_key = os.getenv("ANTHROPIC_API_KEY")

        try:
            from beskar import BeskarClient  # noqa: PLC0415
            from beskar.types import BeskarConfig, CacheConfig, MetricsConfig  # noqa: PLC0415

            self._client = BeskarClient(
                BeskarConfig(
                    api_key=api_key,
                    cache=CacheConfig(),
                    metrics=MetricsConfig(),
                )
            )
            self._using_beskar = True
        except ImportError:
            try:
                import anthropic  # noqa: PLC0415

                self._client = anthropic.Anthropic(api_key=api_key)
                self._using_beskar = False
            except ImportError as exc:
                raise ImportError(
                    "The 'anthropic' package is required. Install it with: pip install anthropic"
                ) from exc

        return self._client
