"""
Tests for Phase 6.5 — Slack/Teams conversational security assistant bots.

Covers:
- BotContext: add_message, get_thread_context, check_rate_limit
- CommandRouter: parse_command, help, status, unknown command,
                 analyze (mocked Analyzer), explain (mocked provider)
- SlackBot: _verify_slack_signature, handle_slash_command
- TeamsBot: _verify_teams_signature, _build_adaptive_card
- Flask routes: /slack/events url_verification, /health for both bots
"""

import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_db(tmp_path):
    """Return a temporary SQLite database path."""
    return str(tmp_path / "test_bot.db")


@pytest.fixture()
def bot_context(tmp_db):
    from vlair.integrations.bot_context import BotContext

    return BotContext(db_path=tmp_db)


@pytest.fixture()
def router():
    from vlair.integrations.command_router import CommandRouter

    return CommandRouter()


@pytest.fixture()
def slack_bot(tmp_db):
    from vlair.integrations.slack import SlackBot

    return SlackBot(
        bot_token="xoxb-test-token",
        signing_secret="test_signing_secret",
        rate_limit_per_hour=20,
        db_path=tmp_db,
    )


@pytest.fixture()
def slack_app(slack_bot):
    pytest.importorskip("flask")
    from vlair.integrations.slack import create_slack_app

    app = create_slack_app(slack_bot)
    app.config["TESTING"] = True
    return app


@pytest.fixture()
def teams_bot(tmp_db):
    from vlair.integrations.teams import TeamsBot

    return TeamsBot(
        app_id="test-app-id",
        app_password="test-app-password",
        rate_limit_per_hour=20,
        db_path=tmp_db,
    )


@pytest.fixture()
def teams_app(teams_bot):
    pytest.importorskip("flask")
    from vlair.integrations.teams import create_teams_app

    app = create_teams_app(teams_bot)
    app.config["TESTING"] = True
    return app


# ===========================================================================
# BotContext tests
# ===========================================================================


class TestBotContext:
    def test_add_and_retrieve_messages(self, bot_context):
        bot_context.add_message("slack", "C123", "ts001", "U456", "user", "Hello bot")
        bot_context.add_message("slack", "C123", "ts001", "bot", "assistant", "Hello user")

        messages = bot_context.get_thread_context("C123", "ts001")
        assert len(messages) == 2
        assert messages[0]["role"] == "user"
        assert messages[0]["content"] == "Hello bot"
        assert messages[1]["role"] == "assistant"

    def test_get_thread_context_empty(self, bot_context):
        messages = bot_context.get_thread_context("CNONE", "ts999")
        assert messages == []

    def test_get_thread_context_limit(self, bot_context):
        for i in range(15):
            bot_context.add_message("slack", "C123", "ts001", "U1", "user", f"msg {i}")
        messages = bot_context.get_thread_context("C123", "ts001", limit=10)
        assert len(messages) == 10

    def test_get_thread_context_order(self, bot_context):
        """Messages should be returned oldest-first."""
        for i in range(5):
            bot_context.add_message("slack", "C1", "ts1", "U1", "user", f"message {i}")
        messages = bot_context.get_thread_context("C1", "ts1")
        contents = [m["content"] for m in messages]
        assert contents == [f"message {i}" for i in range(5)]

    def test_check_rate_limit_allows_within_limit(self, bot_context):
        for _ in range(5):
            assert bot_context.check_rate_limit("user1", limit_per_hour=10) is True

    def test_check_rate_limit_blocks_when_exceeded(self, bot_context):
        for _ in range(20):
            bot_context.check_rate_limit("user2", limit_per_hour=20)
        # 21st request should be blocked
        result = bot_context.check_rate_limit("user2", limit_per_hour=20)
        assert result is False

    def test_check_rate_limit_different_users_independent(self, bot_context):
        for _ in range(20):
            bot_context.check_rate_limit("userA", limit_per_hour=20)
        # userB should still be allowed
        assert bot_context.check_rate_limit("userB", limit_per_hour=20) is True

    def test_cleanup_old_messages(self, bot_context):
        """Cleanup should delete messages older than the given number of days."""
        # Directly insert an old message using SQLite
        import sqlite3

        old_ts = time.time() - (8 * 86400)  # 8 days ago
        with sqlite3.connect(str(bot_context.db_path)) as conn:
            conn.execute(
                "INSERT INTO messages (platform, channel_id, thread_ts, user_id, role, content, created_at) "
                "VALUES ('slack', 'C1', 'ts1', 'U1', 'user', 'old message', ?)",
                (old_ts,),
            )

        bot_context.add_message("slack", "C1", "ts1", "U1", "user", "new message")
        deleted = bot_context.cleanup_old_messages(days=7)
        assert deleted == 1

        remaining = bot_context.get_thread_context("C1", "ts1")
        assert len(remaining) == 1
        assert remaining[0]["content"] == "new message"


# ===========================================================================
# CommandRouter tests
# ===========================================================================


class TestCommandRouterParseCommand:
    def test_parse_simple_command(self, router):
        cmd, args = router.parse_command("help")
        assert cmd == "help"
        assert args == ""

    def test_parse_with_mention(self, router):
        cmd, args = router.parse_command("<@U12345> analyze malicious.com")
        assert cmd == "analyze"
        assert args == "malicious.com"

    def test_parse_at_vlair_prefix(self, router):
        cmd, args = router.parse_command("@vlair explain lateral movement")
        assert cmd == "explain"
        assert args == "lateral movement"

    def test_parse_empty_text(self, router):
        cmd, args = router.parse_command("")
        assert cmd == "help"
        assert args == ""

    def test_parse_mention_only(self, router):
        cmd, args = router.parse_command("<@U12345>")
        assert cmd == "help"
        assert args == ""

    def test_parse_uppercase_command_normalized(self, router):
        cmd, args = router.parse_command("HELP")
        assert cmd == "help"


class TestCommandRouterRouting:
    def test_help_command(self, router):
        result = router.route("help", "")
        assert result["error"] is False
        assert "vlair Security Assistant" in result["text"]
        assert result["raw_result"] is None

    def test_unknown_command(self, router):
        result = router.route("frobnicate", "args")
        assert result["error"] is True
        assert "Unknown command" in result["text"]

    def test_status_command_no_keys(self, router):
        env_patch = {
            "VT_API_KEY": "",
            "ABUSEIPDB_KEY": "",
            "ANTHROPIC_API_KEY": "",
            "OPENAI_API_KEY": "",
        }
        with patch.dict(os.environ, env_patch, clear=False):
            result = router.route("status", "")
        assert result["error"] is False
        assert "vlair Status" in result["text"]

    def test_status_command_with_keys(self, router):
        env_patch = {
            "VT_API_KEY": "vt-key-123",
            "ANTHROPIC_API_KEY": "sk-ant-123",
        }
        with patch.dict(os.environ, env_patch):
            result = router.route("status", "")
        assert "configured" in result["text"]

    def test_investigate_no_args(self, router):
        result = router.route("investigate", "")
        assert result["error"] is True

    def test_investigate_with_iocs(self, router):
        mock_extractor = MagicMock()
        mock_extractor.return_value.extract_from_text.return_value = {
            "ips": ["1.2.3.4"],
            "domains": ["evil.com"],
            "urls": [],
            "emails": [],
            "hashes": [],
            "cves": [],
        }
        with patch("vlair.integrations.command_router.IOCExtractor", mock_extractor, create=True):
            # Import the module fresh so patch takes effect
            from vlair.integrations import command_router as cr

            with patch.object(cr, "_first_available_provider", return_value=None):
                with patch("vlair.tools.ioc_extractor.IOCExtractor", mock_extractor, create=True):
                    result = router.route("investigate", "Check IP 1.2.3.4 and domain evil.com")
        # Accept either a real IOC extraction result or a mocked one
        assert (
            result["error"] is False or "IOC" in result["text"] or "ioc" in result["text"].lower()
        )

    def test_analyze_no_args(self, router):
        result = router.route("analyze", "")
        assert result["error"] is True
        assert "target" in result["text"].lower() or "provide" in result["text"].lower()

    def test_analyze_with_mocked_analyzer(self, router):
        mock_analyzer_cls = MagicMock()
        mock_analyzer_instance = MagicMock()
        mock_analyzer_instance.analyze.return_value = {
            "verdict": "Malicious",
            "risk_score": 90,
            "type": "domain",
            "findings": ["High-risk domain", "Flagged by VirusTotal"],
            "tool_results": {},
        }
        mock_analyzer_cls.return_value = mock_analyzer_instance

        with patch.dict(
            "sys.modules", {"vlair.core.analyzer": MagicMock(Analyzer=mock_analyzer_cls)}
        ):
            with patch(
                "vlair.integrations.command_router._first_available_provider", return_value=None
            ):
                result = router.route("analyze", "evil.com")

        assert result["error"] is False
        assert "Malicious" in result["text"]
        assert "90" in result["text"]

    def test_explain_no_args(self, router):
        result = router.route("explain", "")
        assert result["error"] is True

    def test_explain_no_provider(self, router):
        with patch(
            "vlair.integrations.command_router._first_available_provider", return_value=None
        ):
            result = router.route("explain", "lateral movement")
        assert result["error"] is False
        assert "No AI provider" in result["text"]

    def test_explain_with_mock_provider(self, router):
        mock_provider = MagicMock()
        mock_response = MagicMock()
        mock_response.content = "Lateral movement is how attackers move through a network."
        mock_provider.analyze.return_value = mock_response

        with patch(
            "vlair.integrations.command_router._first_available_provider",
            return_value=mock_provider,
        ):
            result = router.route("explain", "lateral movement")

        assert result["error"] is False
        assert "Lateral movement" in result["text"]

    def test_ask_no_args(self, router):
        result = router.route("ask", "")
        assert result["error"] is True

    def test_ask_with_thread_context(self, router):
        mock_provider = MagicMock()
        mock_response = MagicMock()
        mock_response.content = "Based on the thread, the IP is likely a C2 server."
        mock_provider.analyze.return_value = mock_response

        context = [
            {"role": "user", "content": "analyze 8.8.8.8"},
            {"role": "assistant", "content": "Risk score: 10, verdict: Clean"},
        ]

        with patch(
            "vlair.integrations.command_router._first_available_provider",
            return_value=mock_provider,
        ):
            result = router.route("ask", "Is this IP dangerous?", thread_context=context)

        assert result["error"] is False
        # The provider should have been called with context
        call_args = mock_provider.analyze.call_args
        assert "Thread context" in call_args[0][1] or "ASSISTANT" in call_args[0][1]

    def test_summary_no_context(self, router):
        result = router.route("summary", "", thread_context=None)
        assert result["error"] is False
        assert "No thread context" in result["text"]

    def test_summary_fallback_without_provider(self, router):
        context = [
            {"role": "user", "content": "analyze evil.com"},
            {"role": "assistant", "content": "Verdict: Malicious, risk score 95"},
        ]
        with patch(
            "vlair.integrations.command_router._first_available_provider", return_value=None
        ):
            result = router.route("summary", "", thread_context=context)
        assert result["error"] is False
        assert "Summary" in result["text"] or "finding" in result["text"].lower()

    def test_workflow_known_name(self, router):
        result = router.route("workflow", "phishing-email")
        assert result["error"] is False
        assert "Phishing" in result["text"]

    def test_workflow_unknown_name(self, router):
        result = router.route("workflow", "unknown-workflow")
        assert result["error"] is False
        assert "phishing-email" in result["text"]

    def test_workflow_no_args(self, router):
        result = router.route("workflow", "")
        assert result["error"] is False


# ===========================================================================
# Slack signature verification
# ===========================================================================


class TestSlackSignature:
    def _make_signature(self, secret: str, timestamp: str, body: bytes) -> str:
        base = f"v0:{timestamp}:".encode() + body
        digest = hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
        return f"v0={digest}"

    def test_valid_signature(self):
        from vlair.integrations.slack import _verify_slack_signature

        secret = "my_signing_secret"
        ts = str(int(time.time()))
        body = b'{"type": "event_callback"}'
        sig = self._make_signature(secret, ts, body)

        assert _verify_slack_signature(secret, body, ts, sig) is True

    def test_invalid_signature(self):
        from vlair.integrations.slack import _verify_slack_signature

        ts = str(int(time.time()))
        body = b'{"type": "event_callback"}'
        assert _verify_slack_signature("secret", body, ts, "v0=badsignature") is False

    def test_expired_timestamp(self):
        from vlair.integrations.slack import _verify_slack_signature

        secret = "my_signing_secret"
        ts = str(int(time.time()) - 400)  # 400 seconds ago — beyond 5-min window
        body = b'{"type": "event_callback"}'
        sig = self._make_signature(secret, ts, body)

        assert _verify_slack_signature(secret, body, ts, sig) is False

    def test_invalid_timestamp_format(self):
        from vlair.integrations.slack import _verify_slack_signature

        assert _verify_slack_signature("secret", b"body", "not-a-number", "v0=sig") is False


# ===========================================================================
# SlackBot.handle_slash_command
# ===========================================================================


class TestSlackBotSlashCommand:
    def test_slash_help(self, slack_bot):
        payload = {"text": "help", "user_id": "U001"}
        result = slack_bot.handle_slash_command(payload)
        assert result["response_type"] == "ephemeral"
        assert "vlair Security Assistant" in result["text"]

    def test_slash_empty_text_returns_help(self, slack_bot):
        payload = {"text": "", "user_id": "U001"}
        result = slack_bot.handle_slash_command(payload)
        assert "vlair Security Assistant" in result["text"]

    def test_slash_status(self, slack_bot):
        with patch.dict(os.environ, {"VT_API_KEY": "", "ANTHROPIC_API_KEY": ""}):
            payload = {"text": "status", "user_id": "U001"}
            result = slack_bot.handle_slash_command(payload)
        assert result["response_type"] == "ephemeral"
        assert "vlair Status" in result["text"]

    def test_slash_unknown_command(self, slack_bot):
        payload = {"text": "frobnicate", "user_id": "U001"}
        result = slack_bot.handle_slash_command(payload)
        assert result["response_type"] == "ephemeral"
        assert "Unknown command" in result["text"]


# ===========================================================================
# SlackBot constructor validation
# ===========================================================================


class TestSlackBotValidation:
    def test_missing_bot_token_raises(self, tmp_db):
        from vlair.integrations.slack import SlackBot

        with pytest.raises(ValueError, match="bot_token"):
            SlackBot("", "secret", db_path=tmp_db)

    def test_missing_signing_secret_raises(self, tmp_db):
        from vlair.integrations.slack import SlackBot

        with pytest.raises(ValueError, match="signing_secret"):
            SlackBot("xoxb-token", "", db_path=tmp_db)


# ===========================================================================
# Teams signature verification
# ===========================================================================


class TestTeamsSignature:
    def _make_teams_sig(self, password: str, body: bytes) -> str:
        import base64

        digest = hmac.new(password.encode(), body, hashlib.sha256).digest()
        return "HMAC " + base64.b64encode(digest).decode()

    def test_valid_signature(self):
        from vlair.integrations.teams import _verify_teams_signature

        password = "test-app-password"
        body = b'{"type": "message", "text": "hello"}'
        auth = self._make_teams_sig(password, body)

        assert _verify_teams_signature(password, body, auth) is True

    def test_invalid_signature(self):
        from vlair.integrations.teams import _verify_teams_signature

        body = b'{"type": "message"}'
        assert _verify_teams_signature("password", body, "HMAC invalidsig==") is False

    def test_missing_hmac_prefix(self):
        from vlair.integrations.teams import _verify_teams_signature

        body = b"body"
        assert _verify_teams_signature("password", body, "Bearer some-jwt") is False

    def test_empty_auth_header(self):
        from vlair.integrations.teams import _verify_teams_signature

        assert _verify_teams_signature("password", b"body", "") is False


# ===========================================================================
# _build_adaptive_card
# ===========================================================================


class TestBuildAdaptiveCard:
    def test_basic_card(self):
        from vlair.integrations.teams import _build_adaptive_card

        card = _build_adaptive_card("Test Title", "Some body text")
        assert card["type"] == "AdaptiveCard"
        assert card["version"] == "1.4"
        texts = [b.get("text", "") for b in card["body"]]
        assert "Test Title" in texts
        assert "Some body text" in texts

    def test_card_with_malicious_verdict(self):
        from vlair.integrations.teams import _build_adaptive_card

        card = _build_adaptive_card("Analysis", "Details here", verdict="Malicious")
        verdict_block = [b for b in card["body"] if "Verdict" in b.get("text", "")]
        assert len(verdict_block) == 1
        assert verdict_block[0]["color"] == "Attention"

    def test_card_with_clean_verdict(self):
        from vlair.integrations.teams import _build_adaptive_card

        card = _build_adaptive_card("Analysis", "Details", verdict="Clean")
        verdict_block = [b for b in card["body"] if "Verdict" in b.get("text", "")]
        assert verdict_block[0]["color"] == "Good"

    def test_card_with_suspicious_verdict(self):
        from vlair.integrations.teams import _build_adaptive_card

        card = _build_adaptive_card("Analysis", "Details", verdict="Suspicious")
        verdict_block = [b for b in card["body"] if "Verdict" in b.get("text", "")]
        assert verdict_block[0]["color"] == "Warning"

    def test_card_without_verdict(self):
        from vlair.integrations.teams import _build_adaptive_card

        card = _build_adaptive_card("Title", "Body")
        verdict_blocks = [b for b in card["body"] if "Verdict" in b.get("text", "")]
        assert len(verdict_blocks) == 0


# ===========================================================================
# Flask routes
# ===========================================================================


class TestSlackFlaskRoutes:
    def _make_slack_sig(self, secret: str, ts: str, body: bytes) -> str:
        base = f"v0:{ts}:".encode() + body
        digest = hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
        return f"v0={digest}"

    def test_health_endpoint(self, slack_app):
        with slack_app.test_client() as client:
            resp = client.get("/health")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "ok"
        assert data["bot"] == "slack"

    def test_url_verification_challenge(self, slack_app, slack_bot):
        body = json.dumps(
            {
                "type": "url_verification",
                "challenge": "3eZbrw1aBm2rZgRNFdxV2595E9CY3gmdALWMmHkvFXO7tYXAYM8P",
            }
        ).encode()
        ts = str(int(time.time()))
        sig = self._make_slack_sig(slack_bot.signing_secret, ts, body)

        with slack_app.test_client() as client:
            resp = client.post(
                "/slack/events",
                data=body,
                content_type="application/json",
                headers={
                    "X-Slack-Request-Timestamp": ts,
                    "X-Slack-Signature": sig,
                },
            )

        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["challenge"] == "3eZbrw1aBm2rZgRNFdxV2595E9CY3gmdALWMmHkvFXO7tYXAYM8P"

    def test_events_invalid_signature_rejected(self, slack_app):
        body = b'{"type": "event_callback"}'
        ts = str(int(time.time()))

        with slack_app.test_client() as client:
            resp = client.post(
                "/slack/events",
                data=body,
                content_type="application/json",
                headers={
                    "X-Slack-Request-Timestamp": ts,
                    "X-Slack-Signature": "v0=badsig",
                },
            )
        assert resp.status_code == 403


class TestTeamsFlaskRoutes:
    def test_health_endpoint(self, teams_app):
        with teams_app.test_client() as client:
            resp = client.get("/health")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "ok"
        assert data["bot"] == "teams"

    def test_messages_invalid_signature_rejected(self, teams_app):
        body = b'{"type": "message", "text": "hello"}'
        with teams_app.test_client() as client:
            resp = client.post(
                "/teams/messages",
                data=body,
                content_type="application/json",
                headers={"Authorization": "HMAC invalidsig=="},
            )
        assert resp.status_code == 403

    def test_messages_valid_signature_accepted(self, teams_app, teams_bot):
        import base64

        body = json.dumps(
            {
                "type": "message",
                "text": "help",
                "from": {"id": "U001"},
                "conversation": {"id": "C001"},
                "id": "activity-001",
                "serviceUrl": "https://smba.trafficmanager.net/",
            }
        ).encode()

        digest = hmac.new(teams_bot.app_password.encode(), body, hashlib.sha256).digest()
        auth = "HMAC " + base64.b64encode(digest).decode()

        with teams_app.test_client() as client:
            resp = client.post(
                "/teams/messages",
                data=body,
                content_type="application/json",
                headers={"Authorization": auth},
            )
        # 202 Accepted — response is sent asynchronously
        assert resp.status_code == 202


# ===========================================================================
# TeamsBot constructor validation
# ===========================================================================


class TestTeamsBotValidation:
    def test_missing_app_id_raises(self, tmp_db):
        from vlair.integrations.teams import TeamsBot

        with pytest.raises(ValueError, match="app_id"):
            TeamsBot("", "password", db_path=tmp_db)

    def test_missing_app_password_raises(self, tmp_db):
        from vlair.integrations.teams import TeamsBot

        with pytest.raises(ValueError, match="app_password"):
            TeamsBot("app-id", "", db_path=tmp_db)
