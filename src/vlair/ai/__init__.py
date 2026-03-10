"""vlair AI analysis — Claude-powered threat intelligence summaries and Phase 6 AI features."""

from .summarizer import SummaryConfig, ThreatSummarizer
from .classifier import MalwareClassifier
from .correlator import IOCCorrelator
from .playbook_generator import PlaybookGenerator
from .cache import AIResponseCache
from .privacy import sanitize_tool_result, get_dry_run_summary
from .reporter import AIReporter
from .providers.base import AIProvider, AIResponse

__all__ = [
    "ThreatSummarizer",
    "SummaryConfig",
    "MalwareClassifier",
    "IOCCorrelator",
    "PlaybookGenerator",
    "AIResponseCache",
    "AIReporter",
    "AIProvider",
    "AIResponse",
    "sanitize_tool_result",
    "get_dry_run_summary",
]
