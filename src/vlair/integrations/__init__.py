"""
vlair integrations — Slack and Microsoft Teams conversational security assistant bots.
"""

from .bot_context import BotContext
from .command_router import CommandRouter

__all__ = ["BotContext", "CommandRouter", "SlackBot", "TeamsBot"]


def __getattr__(name: str):
    if name == "SlackBot":
        from .slack import SlackBot

        return SlackBot
    if name == "TeamsBot":
        from .teams import TeamsBot

        return TeamsBot
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
