"""
vlair AI Providers — OpenAI GPT implementation.
"""

import os
from typing import Optional

from .base import AIProvider, AIResponse

_DEFAULT_MODEL = "gpt-4-turbo"


class OpenAIProvider(AIProvider):
    """
    AI provider backed by the OpenAI API (GPT-4 Turbo by default).

    Requires the OPENAI_API_KEY environment variable.
    The ``openai`` package is imported lazily and is optional — if it is not
    installed, ``is_available()`` returns False.
    """

    def __init__(self, model: Optional[str] = None, temperature: float = 0.2) -> None:
        self._model = model or os.getenv("OPENAI_MODEL", _DEFAULT_MODEL)
        self.temperature = temperature
        self._client = None  # lazy-initialised

    # ------------------------------------------------------------------
    # AIProvider interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "openai"

    @property
    def model(self) -> str:
        return self._model

    def is_available(self) -> bool:
        """Return True if OPENAI_API_KEY is set and the openai package is installed."""
        if not os.getenv("OPENAI_API_KEY"):
            return False
        try:
            import openai  # noqa: F401

            return True
        except ImportError:
            return False

    def analyze(self, system_prompt: str, user_message: str, max_tokens: int = 2000) -> AIResponse:
        """Call the OpenAI chat completions API and return an AIResponse."""
        client = self._get_client()

        response = client.chat.completions.create(
            model=self._model,
            max_tokens=max_tokens,
            temperature=self.temperature,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
        )

        content = response.choices[0].message.content if response.choices else ""
        tokens_used = response.usage.total_tokens if response.usage else 0

        return AIResponse(
            content=content,
            tokens_used=tokens_used,
            model=self._model,
            cached=False,
            provider=self.name,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_client(self):
        if self._client is None:
            try:
                import openai  # noqa: PLC0415

                self._client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
            except ImportError as exc:
                raise ImportError(
                    "The 'openai' package is required. Install it with: pip install openai"
                ) from exc
        return self._client
