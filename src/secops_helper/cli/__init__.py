"""
SecOps Helper CLI - Command line interface

Entry points:
- main: Primary CLI (secops command)
- legacy_main: Legacy unified CLI (secops-helper command)
"""

from .main import main
from .legacy import main as legacy_main

__all__ = ["main", "legacy_main"]
