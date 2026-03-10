"""
vlair AI Providers — Abstract base classes for AI provider implementations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AIResponse:
    """Unified response from any AI provider."""

    content: str
    confidence: float = 0.5
    tokens_used: int = 0
    model: str = ""
    cached: bool = False
    provider: str = ""


class AIProvider(ABC):
    """Abstract base class for AI provider implementations."""

    @abstractmethod
    def analyze(self, system_prompt: str, user_message: str, max_tokens: int = 2000) -> AIResponse:
        """
        Send a prompt to the AI provider and return a structured response.

        Args:
            system_prompt: The system-level instructions for the AI.
            user_message:  The user-turn message / data to analyze.
            max_tokens:    Maximum tokens in the response.

        Returns:
            AIResponse with content and usage metadata.
        """

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this provider is configured and reachable."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for this provider (e.g. 'anthropic', 'openai', 'ollama')."""

    @property
    @abstractmethod
    def model(self) -> str:
        """Model name / identifier currently in use."""
