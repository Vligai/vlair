#!/usr/bin/env python3
"""
Playbook Registry - Central registry for investigation playbooks

Separated from engine.py to avoid circular imports.
"""

from typing import Dict, List, Optional, Type, TYPE_CHECKING

if TYPE_CHECKING:
    from .playbooks.base import BasePlaybook


class PlaybookRegistry:
    """Registry for available investigation playbooks"""

    _playbooks: Dict[str, Type["BasePlaybook"]] = {}

    @classmethod
    def register(cls, playbook_class: Type["BasePlaybook"]):
        """Register a playbook class."""
        # Create temporary instance to get name
        instance = playbook_class(verbose=False)
        cls._playbooks[instance.name] = playbook_class

    @classmethod
    def get(cls, name: str) -> Optional[Type["BasePlaybook"]]:
        """Get a playbook class by name."""
        return cls._playbooks.get(name)

    @classmethod
    def list_all(cls) -> List[Dict[str, str]]:
        """List all registered playbooks."""
        result = []
        for name, playbook_class in cls._playbooks.items():
            instance = playbook_class(verbose=False)
            result.append({
                "name": name,
                "description": instance.description,
                "type": instance.investigation_type,
                "steps": len(instance.steps),
            })
        return result
