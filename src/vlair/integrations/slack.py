"""
vlair Slack Bot — Events API webhook server using Flask.

Required environment variables:
    VLAIR_SLACK_BOT_TOKEN       Slack bot OAuth token (xoxb-...)
    VLAIR_SLACK_SIGNING_SECRET  Slack signing secret (for request verification)

Optional:
    VLAIR_BOT_RATE_LIMIT        Requests per user per hour (default: 20)
    VLAIR_BOT_DB                Path to SQLite database (default: ~/.vlair/bot.db)
"""

import hashlib
import hmac
import json
import os
import threading
import time
from typing import Dict, Optional

try:
    import requests as _requests
except ImportError:  # pragma: no cover
    _requests = None  # type: ignore[assignment]

from .bot_context import BotContext
from .command_router import HELP_TEXT, CommandRouter


def _verify_slack_signature(
    signing_secret: str,
    body_bytes: bytes,
    timestamp: str,
    signature: str,
) -> bool:
    """
    Verify a Slack request signature using HMAC-SHA256.

    Returns False if the timestamp is more than 5 minutes old (replay protection).
    """
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False

    if abs(time.time() - ts) > 300:
        return False

    base_string = f"v0:{timestamp}:".encode() + body_bytes
    expected = (
        "v0="
        + hmac.new(
            signing_secret.encode(),
            base_string,
            hashlib.sha256,
        ).hexdigest()
    )

    return hmac.compare_digest(expected, signature)


class SlackBot:
    """Slack bot that handles app mentions and slash commands."""

    def __init__(
        self,
        bot_token: str,
        signing_secret: str,
        rate_limit_per_hour: int = 20,
        db_path: Optional[str] = None,
    ) -> None:
        if not bot_token:
            raise ValueError("bot_token is required")
        if not signing_secret:
            raise ValueError("signing_secret is required")

        self.bot_token = bot_token
        self.signing_secret = signing_secret
        self.rate_limit_per_hour = rate_limit_per_hour
        self.context = BotContext(db_path=db_path)
        self.router = CommandRouter()

    # ------------------------------------------------------------------
    # Slack API helpers
    # ------------------------------------------------------------------

    def _post_message(self, channel: str, text: str, thread_ts: Optional[str] = None) -> Dict:
        """POST a message to a Slack channel via chat.postMessage."""
        if _requests is None:
            return {"ok": False, "error": "requests library not installed"}

        payload: Dict = {"channel": channel, "text": text}
        if thread_ts:
            payload["thread_ts"] = thread_ts

        try:
            resp = _requests.post(
                "https://slack.com/api/chat.postMessage",
                headers={
                    "Authorization": f"Bearer {self.bot_token}",
                    "Content-Type": "application/json; charset=utf-8",
                },
                json=payload,
                timeout=15,
            )
            return resp.json()
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def handle_app_mention(self, event: Dict) -> None:
        """
        Process an app_mention event.

        - Check rate limit
        - Store the user message in context
        - Route the command
        - Post the response back in-thread
        """
        channel = event.get("channel", "")
        thread_ts = event.get("thread_ts") or event.get("ts", "")
        user_id = event.get("user", "")
        text = event.get("text", "")

        # Rate limiting
        if not self.context.check_rate_limit(user_id, self.rate_limit_per_hour):
            self._post_message(
                channel,
                f"<@{user_id}> You have reached the rate limit ({self.rate_limit_per_hour} requests/hour).",
                thread_ts=thread_ts,
            )
            return

        # Store user message
        self.context.add_message(
            platform="slack",
            channel_id=channel,
            thread_ts=thread_ts,
            user_id=user_id,
            role="user",
            content=text,
        )

        # Retrieve thread context for AI-aware commands
        thread_context = self.context.get_thread_context(channel, thread_ts, limit=10)

        # Route
        command, args = self.router.parse_command(text)
        result = self.router.route(command, args, thread_context=thread_context)
        response_text = result.get("text", "An error occurred.")

        # Store assistant response
        self.context.add_message(
            platform="slack",
            channel_id=channel,
            thread_ts=thread_ts,
            user_id="bot",
            role="assistant",
            content=response_text,
        )

        self._post_message(channel, response_text, thread_ts=thread_ts)

    def handle_slash_command(self, payload: Dict) -> Dict:
        """
        Handle a /vlair slash command.

        Returns an immediate ephemeral response dict (Slack expects JSON within 3 s).
        """
        text = payload.get("text", "").strip()
        user_id = payload.get("user_id", "")

        if not text or text in ("help", "--help", "-h"):
            return {
                "response_type": "ephemeral",
                "text": HELP_TEXT,
            }

        command, args = self.router.parse_command(text)
        result = self.router.route(command, args)
        response_text = result.get("text", "An error occurred.")

        return {
            "response_type": "ephemeral",
            "text": response_text,
        }

    def dispatch_event_async(self, event: Dict) -> None:
        """Dispatch handle_app_mention in a background thread."""
        thread = threading.Thread(target=self.handle_app_mention, args=(event,), daemon=True)
        thread.start()


# ------------------------------------------------------------------
# Flask application factory
# ------------------------------------------------------------------


def create_slack_app(bot: SlackBot):
    """Create and return a Flask app wired to the given SlackBot."""
    try:
        from flask import Flask, Response, jsonify, request
    except ImportError as exc:
        raise ImportError("Flask is required. Install with: pip install flask") from exc

    app = Flask(__name__)

    def _verify(req) -> bool:
        return _verify_slack_signature(
            bot.signing_secret,
            req.get_data(),
            req.headers.get("X-Slack-Request-Timestamp", ""),
            req.headers.get("X-Slack-Signature", ""),
        )

    @app.route("/slack/events", methods=["POST"])
    def slack_events():
        if not _verify(request):
            return Response("Invalid signature", status=403)

        try:
            data = request.get_json(force=True) or {}
        except Exception:
            return Response("Bad request", status=400)

        # URL verification challenge (Slack sends this when you configure the endpoint)
        if data.get("type") == "url_verification":
            return jsonify({"challenge": data.get("challenge", "")})

        event_wrapper = data.get("event", {})
        event_type = event_wrapper.get("type", "")

        if event_type == "app_mention":
            bot.dispatch_event_async(event_wrapper)

        return Response("OK", status=200)

    @app.route("/slack/commands", methods=["POST"])
    def slack_commands():
        if not _verify(request):
            return Response("Invalid signature", status=403)

        payload = request.form.to_dict()
        response = bot.handle_slash_command(payload)
        return jsonify(response)

    @app.route("/slack/actions", methods=["POST"])
    def slack_actions():
        if not _verify(request):
            return Response("Invalid signature", status=403)

        try:
            raw = request.form.get("payload", "{}")
            data = json.loads(raw)
        except Exception:
            return Response("Bad request", status=400)

        action_id = ""
        for action in data.get("actions", []):
            action_id = action.get("action_id", "")
            break

        # Placeholder — interactive buttons can be extended here
        return jsonify({"text": f"Action `{action_id}` received. Feature coming soon."})

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "bot": "slack"})

    return app


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------


def run_slack_bot(port: int = 3000, debug: bool = False) -> None:
    """Read environment variables, create the bot and Flask app, and run the server."""
    bot_token = os.environ.get("VLAIR_SLACK_BOT_TOKEN", "")
    signing_secret = os.environ.get("VLAIR_SLACK_SIGNING_SECRET", "")

    if not bot_token:
        raise ValueError(
            "VLAIR_SLACK_BOT_TOKEN environment variable is not set. "
            "Create a Slack app at https://api.slack.com/apps and copy the Bot User OAuth Token."
        )
    if not signing_secret:
        raise ValueError(
            "VLAIR_SLACK_SIGNING_SECRET environment variable is not set. "
            "Find it under Basic Information → App Credentials in your Slack app settings."
        )

    rate_limit = int(os.environ.get("VLAIR_BOT_RATE_LIMIT", "20"))
    db_path = os.environ.get("VLAIR_BOT_DB")

    bot = SlackBot(bot_token, signing_secret, rate_limit_per_hour=rate_limit, db_path=db_path)
    app = create_slack_app(bot)

    print(f"Starting vlair Slack bot on port {port}")
    print("Configure your Slack app to send events to: POST /slack/events")
    print("Configure slash commands to: POST /slack/commands")
    app.run(host="0.0.0.0", port=port, debug=debug)
