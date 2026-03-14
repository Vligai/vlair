"""
vlair Teams Bot — Microsoft Bot Framework webhook server using Flask.

Required environment variables:
    VLAIR_TEAMS_APP_ID          Azure Bot app ID
    VLAIR_TEAMS_APP_PASSWORD    Azure Bot app password (client secret)

Optional:
    VLAIR_BOT_RATE_LIMIT        Requests per user per hour (default: 20)
    VLAIR_BOT_DB                Path to SQLite database (default: ~/.vlair/bot.db)
"""

import base64
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
from .command_router import CommandRouter


# Microsoft login endpoint for Bot Framework token acquisition
_MS_TOKEN_URL = "https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token"
_BOT_FRAMEWORK_SEND_URL = "{service_url}v3/conversations/{conversation_id}/activities"


def _verify_teams_signature(
    app_password: str,
    body_bytes: bytes,
    auth_header: str,
) -> bool:
    """
    Verify a Teams Bot Framework request signature.

    The Bot Framework signs requests with HMAC-SHA256 over the body bytes,
    then base64-encodes the digest and places it in the Authorization header
    as "HMAC <base64digest>".
    """
    if not auth_header or not auth_header.startswith("HMAC "):
        return False

    try:
        provided_sig = auth_header[5:]  # strip "HMAC "
        expected_bytes = hmac.new(
            app_password.encode(),
            body_bytes,
            hashlib.sha256,
        ).digest()
        expected_sig = base64.b64encode(expected_bytes).decode()
        return hmac.compare_digest(expected_sig, provided_sig)
    except Exception:
        return False


def _build_adaptive_card(
    title: str,
    body_text: str,
    verdict: Optional[str] = None,
) -> Dict:
    """
    Build a minimal Adaptive Card v1.4 for Teams.

    Parameters
    ----------
    title:     Card heading text.
    body_text: Main content (plain text).
    verdict:   Optional verdict badge (e.g. "Malicious", "Clean").
    """
    body_blocks = [
        {"type": "TextBlock", "size": "Large", "weight": "Bolder", "text": title, "wrap": True},
        {"type": "TextBlock", "text": body_text, "wrap": True},
    ]

    if verdict:
        colour_map = {
            "malicious": "Attention",
            "suspicious": "Warning",
            "clean": "Good",
        }
        colour = colour_map.get(verdict.lower(), "Default")
        body_blocks.append(
            {
                "type": "TextBlock",
                "text": f"Verdict: **{verdict}**",
                "color": colour,
                "weight": "Bolder",
            }
        )

    return {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.4",
        "body": body_blocks,
    }


class TeamsBot:
    """Microsoft Teams bot handler using the Bot Framework REST API."""

    def __init__(
        self,
        app_id: str,
        app_password: str,
        rate_limit_per_hour: int = 20,
        db_path: Optional[str] = None,
    ) -> None:
        if not app_id:
            raise ValueError("app_id is required")
        if not app_password:
            raise ValueError("app_password is required")

        self.app_id = app_id
        self.app_password = app_password
        self.rate_limit_per_hour = rate_limit_per_hour
        self.context = BotContext(db_path=db_path)
        self.router = CommandRouter()

        self._token: Optional[str] = None
        self._token_expiry: float = 0.0

    # ------------------------------------------------------------------
    # Bot Framework token
    # ------------------------------------------------------------------

    def _get_teams_token(self) -> Optional[str]:
        """Acquire (or return cached) Bot Framework OAuth token."""
        if self._token and time.time() < self._token_expiry - 60:
            return self._token

        if _requests is None:
            return None

        try:
            resp = _requests.post(
                _MS_TOKEN_URL,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.app_id,
                    "client_secret": self.app_password,
                    "scope": "https://api.botframework.com/.default",
                },
                timeout=15,
            )
            data = resp.json()
            self._token = data.get("access_token")
            expires_in = int(data.get("expires_in", 3600))
            self._token_expiry = time.time() + expires_in
            return self._token
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Reply helpers
    # ------------------------------------------------------------------

    def _send_reply(self, activity: Dict, text: str, card: Optional[Dict] = None) -> None:
        """Send a reply activity to the originating conversation."""
        token = self._get_teams_token()
        if not token or _requests is None:
            return

        service_url = activity.get("serviceUrl", "").rstrip("/") + "/"
        conversation_id = activity.get("conversation", {}).get("id", "")
        activity_id = activity.get("id", "")

        if not service_url or not conversation_id:
            return

        reply: Dict = {
            "type": "message",
            "from": {"id": self.app_id},
            "conversation": {"id": conversation_id},
            "replyToId": activity_id,
        }

        if card:
            reply["attachments"] = [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": card,
                }
            ]
        else:
            reply["text"] = text

        try:
            url = f"{service_url}v3/conversations/{conversation_id}/activities/{activity_id}"
            _requests.post(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                json=reply,
                timeout=15,
            )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Message handling
    # ------------------------------------------------------------------

    def handle_message(self, activity: Dict) -> None:
        """
        Process an incoming Teams message activity.

        - Rate-limit the user
        - Store context
        - Route command
        - Send reply in background thread
        """
        text = activity.get("text", "").strip()
        user_id = activity.get("from", {}).get("id", "unknown")
        channel_id = activity.get("conversation", {}).get("id", "")
        thread_ts = activity.get("replyToId") or activity.get("id", "")

        def _reply():
            if not self.context.check_rate_limit(user_id, self.rate_limit_per_hour):
                self._send_reply(
                    activity,
                    f"You have reached the rate limit ({self.rate_limit_per_hour} requests/hour).",
                )
                return

            self.context.add_message(
                platform="teams",
                channel_id=channel_id,
                thread_ts=thread_ts,
                user_id=user_id,
                role="user",
                content=text,
            )

            thread_context = self.context.get_thread_context(channel_id, thread_ts, limit=10)
            command, args = self.router.parse_command(text)
            result = self.router.route(command, args, thread_context=thread_context)
            response_text = result.get("text", "An error occurred.")
            raw = result.get("raw_result")

            self.context.add_message(
                platform="teams",
                channel_id=channel_id,
                thread_ts=thread_ts,
                user_id="bot",
                role="assistant",
                content=response_text,
            )

            # Build Adaptive Card for analyze results
            if raw and command == "analyze":
                verdict = raw.get("verdict")
                card = _build_adaptive_card(
                    title=f"Analysis: {args.split()[0] if args else 'Unknown'}",
                    body_text=response_text,
                    verdict=verdict,
                )
                self._send_reply(activity, response_text, card=card)
            else:
                self._send_reply(activity, response_text)

        thread = threading.Thread(target=_reply, daemon=True)
        thread.start()


# ------------------------------------------------------------------
# Flask application factory
# ------------------------------------------------------------------


def create_teams_app(bot: TeamsBot):
    """Create and return a Flask app wired to the given TeamsBot."""
    try:
        from flask import Flask, Response, jsonify, request
    except ImportError as exc:
        raise ImportError("Flask is required. Install with: pip install flask") from exc

    app = Flask(__name__)

    @app.route("/teams/messages", methods=["POST"])
    def teams_messages():
        body_bytes = request.get_data()
        auth_header = request.headers.get("Authorization", "")

        if not _verify_teams_signature(bot.app_password, body_bytes, auth_header):
            return Response("Invalid signature", status=403)

        try:
            activity = json.loads(body_bytes) if body_bytes else {}
        except Exception:
            return Response("Bad request", status=400)

        activity_type = activity.get("type", "")
        if activity_type == "message":
            bot.handle_message(activity)

        return Response("", status=202)

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "bot": "teams"})

    return app


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------


def run_teams_bot(port: int = 3978, debug: bool = False) -> None:
    """Read environment variables, create the bot and Flask app, and run the server."""
    app_id = os.environ.get("VLAIR_TEAMS_APP_ID", "")
    app_password = os.environ.get("VLAIR_TEAMS_APP_PASSWORD", "")

    if not app_id:
        raise ValueError(
            "VLAIR_TEAMS_APP_ID environment variable is not set. "
            "Register a bot at https://dev.botframework.com/ to get your App ID."
        )
    if not app_password:
        raise ValueError(
            "VLAIR_TEAMS_APP_PASSWORD environment variable is not set. "
            "This is the client secret from your Azure Bot registration."
        )

    rate_limit = int(os.environ.get("VLAIR_BOT_RATE_LIMIT", "20"))
    db_path = os.environ.get("VLAIR_BOT_DB")

    bot = TeamsBot(app_id, app_password, rate_limit_per_hour=rate_limit, db_path=db_path)
    app = create_teams_app(bot)

    print(f"Starting vlair Teams bot on port {port}")
    print("Configure your Azure Bot messaging endpoint to: POST /teams/messages")
    app.run(host="0.0.0.0", port=port, debug=debug)
