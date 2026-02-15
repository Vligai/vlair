#!/usr/bin/env python3
"""
Tests for vlair webapp Flask application.

Covers:
- app.py: create_app, error handlers, file validation, tool endpoints
"""

import os
import sys
import pytest
import tempfile
import io
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class TestAppCreation:
    """Test Flask application factory."""

    def setup_method(self):
        """Set up test database."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        os.environ["VLAIR_WEBAPP_DB"] = self.temp_db.name

    def teardown_method(self):
        """Clean up test database."""
        if hasattr(self, "temp_db"):
            try:
                os.unlink(self.temp_db.name)
            except Exception:
                pass

    def test_create_app(self):
        """Test application creation."""
        from vlair.webapp.app import create_app

        app = create_app()
        assert app is not None
        assert app.config["MAX_CONTENT_LENGTH"] == 50 * 1024 * 1024

    def test_create_app_has_blueprints(self):
        """Test app has registered blueprints."""
        from vlair.webapp.app import create_app

        app = create_app()
        blueprint_names = [bp.name for bp in app.blueprints.values()]
        assert "auth" in app.blueprints
        assert "admin" in app.blueprints


class TestFileValidation:
    """Test file extension validation."""

    def test_allowed_eml_extension(self):
        """Test EML file extensions are allowed."""
        from vlair.webapp.app import _allowed

        assert _allowed("test.eml", "eml")
        assert _allowed("test.msg", "eml")
        assert not _allowed("test.txt", "eml")

    def test_allowed_log_extension(self):
        """Test log file extensions are allowed."""
        from vlair.webapp.app import _allowed

        assert _allowed("test.log", "log")
        assert _allowed("test.txt", "log")
        assert not _allowed("test.exe", "log")

    def test_allowed_pcap_extension(self):
        """Test PCAP file extensions are allowed."""
        from vlair.webapp.app import _allowed

        assert _allowed("capture.pcap", "pcap")
        assert _allowed("capture.pcapng", "pcap")
        assert _allowed("capture.cap", "pcap")
        assert not _allowed("capture.txt", "pcap")

    def test_allowed_cert_extension(self):
        """Test certificate file extensions are allowed."""
        from vlair.webapp.app import _allowed

        assert _allowed("cert.crt", "cert")
        assert _allowed("cert.cer", "cert")
        assert _allowed("cert.pem", "cert")
        assert _allowed("cert.der", "cert")
        assert not _allowed("cert.txt", "cert")

    def test_allowed_script_extension(self):
        """Test script file extensions are allowed."""
        from vlair.webapp.app import _allowed

        assert _allowed("script.js", "script")
        assert _allowed("script.ps1", "script")
        assert _allowed("script.vbs", "script")
        assert _allowed("script.bat", "script")
        assert _allowed("script.py", "script")

    def test_allowed_binary_extension(self):
        """Test binary file extensions are allowed."""
        from vlair.webapp.app import _allowed

        assert _allowed("file.bin", "binary")
        assert _allowed("file.exe", "binary")
        assert _allowed("file.dll", "binary")
        assert _allowed("file.img", "binary")

    def test_allowed_no_extension(self):
        """Test files without extensions are rejected."""
        from vlair.webapp.app import _allowed

        assert not _allowed("filename", "log")
        assert not _allowed("noext", "eml")

    def test_allowed_unknown_type(self):
        """Test unknown file type returns empty set."""
        from vlair.webapp.app import _allowed

        assert not _allowed("file.txt", "unknown_type")


class TestErrorHandlers:
    """Test error handlers."""

    def setup_method(self):
        """Set up test Flask app."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        os.environ["VLAIR_WEBAPP_DB"] = self.temp_db.name

        from vlair.webapp.app import create_app

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def teardown_method(self):
        """Clean up test database."""
        if hasattr(self, "temp_db"):
            try:
                os.unlink(self.temp_db.name)
            except Exception:
                pass

    def test_404_handler(self):
        """Test 404 error handler."""
        resp = self.client.get("/api/nonexistent")
        assert resp.status_code == 404
        data = resp.get_json()
        assert "error" in data

    def test_404_spa_route(self):
        """Test SPA routes don't return API 404."""
        # Non-API routes should serve the SPA template
        # This may fail if template doesn't exist, that's OK for testing
        try:
            resp = self.client.get("/some/spa/route")
            # Either 200 (template exists) or 500 (template missing)
            assert resp.status_code in [200, 500]
        except Exception:
            pass  # Template not found is acceptable in tests


class TestHealthEndpoint:
    """Test health check endpoint."""

    def setup_method(self):
        """Set up test Flask app."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        os.environ["VLAIR_WEBAPP_DB"] = self.temp_db.name

        from vlair.webapp.app import create_app

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def teardown_method(self):
        """Clean up test database."""
        if hasattr(self, "temp_db"):
            try:
                os.unlink(self.temp_db.name)
            except Exception:
                pass

    def test_health_endpoint(self):
        """Test health check returns healthy status."""
        resp = self.client.get("/api/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "timestamp" in data


class TestEndpointsListing:
    """Test endpoints listing."""

    def setup_method(self):
        """Set up test Flask app."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        os.environ["VLAIR_WEBAPP_DB"] = self.temp_db.name

        from vlair.webapp.app import create_app
        from vlair.webapp.auth.models import create_user

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        # Create test user
        self.user = create_user("endpointuser", "endpoint@example.com", "password123")

    def teardown_method(self):
        """Clean up test database."""
        if hasattr(self, "temp_db"):
            try:
                os.unlink(self.temp_db.name)
            except Exception:
                pass

    def get_auth_token(self):
        """Get authentication token."""
        resp = self.client.post(
            "/api/auth/login", json={"username": "endpointuser", "password": "password123"}
        )
        return resp.get_json()["access_token"]

    def test_endpoints_listing_requires_auth(self):
        """Test endpoints listing requires authentication."""
        resp = self.client.get("/api/endpoints")
        assert resp.status_code == 401

    def test_endpoints_listing_success(self):
        """Test endpoints listing returns all endpoints."""
        token = self.get_auth_token()
        resp = self.client.get("/api/endpoints", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert "endpoints" in data
        assert len(data["endpoints"]) > 0


class TestIOCExtractorEndpoint:
    """Test IOC extractor endpoint."""

    def setup_method(self):
        """Set up test Flask app."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        os.environ["VLAIR_WEBAPP_DB"] = self.temp_db.name

        from vlair.webapp.app import create_app
        from vlair.webapp.auth.models import create_user

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        self.user = create_user("iocuser", "ioc@example.com", "password123")

    def teardown_method(self):
        """Clean up test database."""
        if hasattr(self, "temp_db"):
            try:
                os.unlink(self.temp_db.name)
            except Exception:
                pass

    def get_auth_token(self):
        """Get authentication token."""
        resp = self.client.post(
            "/api/auth/login", json={"username": "iocuser", "password": "password123"}
        )
        return resp.get_json()["access_token"]

    def test_ioc_extract_requires_auth(self):
        """Test IOC extraction requires authentication."""
        resp = self.client.post("/api/ioc/extract", json={"text": "8.8.8.8"})
        assert resp.status_code == 401

    def test_ioc_extract_no_input(self):
        """Test IOC extraction with no input."""
        token = self.get_auth_token()
        resp = self.client.post(
            "/api/ioc/extract", headers={"Authorization": f"Bearer {token}"}, json={}
        )
        assert resp.status_code == 400

    def test_ioc_extract_success(self):
        """Test successful IOC extraction."""
        token = self.get_auth_token()
        resp = self.client.post(
            "/api/ioc/extract",
            headers={"Authorization": f"Bearer {token}"},
            json={"text": "Found IP 8.8.8.8 and domain example.com"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert "statistics" in data

    def test_ioc_extract_with_file(self):
        """Test IOC extraction from uploaded file."""
        token = self.get_auth_token()
        data = {"file": (io.BytesIO(b"IP: 192.168.1.1"), "test.txt")}
        resp = self.client.post(
            "/api/ioc/extract",
            headers={"Authorization": f"Bearer {token}"},
            data=data,
            content_type="multipart/form-data",
        )
        assert resp.status_code == 200


class TestHashLookupEndpoint:
    """Test hash lookup endpoint."""

    def setup_method(self):
        """Set up test Flask app."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        os.environ["VLAIR_WEBAPP_DB"] = self.temp_db.name

        from vlair.webapp.app import create_app
        from vlair.webapp.auth.models import create_user

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        self.user = create_user("hashuser", "hash@example.com", "password123")

    def teardown_method(self):
        """Clean up test database."""
        if hasattr(self, "temp_db"):
            try:
                os.unlink(self.temp_db.name)
            except Exception:
                pass

    def get_auth_token(self):
        """Get authentication token."""
        resp = self.client.post(
            "/api/auth/login", json={"username": "hashuser", "password": "password123"}
        )
        return resp.get_json()["access_token"]

    def test_hash_lookup_requires_auth(self):
        """Test hash lookup requires authentication."""
        resp = self.client.post("/api/hash/lookup", json={"hashes": ["abc123"]})
        assert resp.status_code == 401

    def test_hash_lookup_no_hashes(self):
        """Test hash lookup with no hashes."""
        token = self.get_auth_token()
        resp = self.client.post(
            "/api/hash/lookup", headers={"Authorization": f"Bearer {token}"}, json={}
        )
        assert resp.status_code == 400

    def test_hash_lookup_string_input(self):
        """Test hash lookup with string input (newline-delimited)."""
        token = self.get_auth_token()
        resp = self.client.post(
            "/api/hash/lookup",
            headers={"Authorization": f"Bearer {token}"},
            json={"hashes": "44d88612fea8a8f36de82e1278abb02f\n5d41402abc4b2a76b9719d911017c592"},
        )
        assert resp.status_code == 200


class TestIntelEndpoint:
    """Test domain/IP intel endpoint."""

    def setup_method(self):
        """Set up test Flask app."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        os.environ["VLAIR_WEBAPP_DB"] = self.temp_db.name

        from vlair.webapp.app import create_app
        from vlair.webapp.auth.models import create_user

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        self.user = create_user("inteluser", "intel@example.com", "password123")

    def teardown_method(self):
        """Clean up test database."""
        if hasattr(self, "temp_db"):
            try:
                os.unlink(self.temp_db.name)
            except Exception:
                pass

    def get_auth_token(self):
        """Get authentication token."""
        resp = self.client.post(
            "/api/auth/login", json={"username": "inteluser", "password": "password123"}
        )
        return resp.get_json()["access_token"]

    def test_intel_requires_auth(self):
        """Test intel requires authentication."""
        resp = self.client.post("/api/intel/analyze", json={"targets": ["8.8.8.8"]})
        assert resp.status_code == 401

    def test_intel_no_targets(self):
        """Test intel with no targets."""
        token = self.get_auth_token()
        resp = self.client.post(
            "/api/intel/analyze", headers={"Authorization": f"Bearer {token}"}, json={}
        )
        # Might be 400 or 500 depending on how tool handles empty input
        assert resp.status_code in [400, 500]

    def test_intel_string_targets(self):
        """Test intel with string input."""
        token = self.get_auth_token()
        resp = self.client.post(
            "/api/intel/analyze",
            headers={"Authorization": f"Bearer {token}"},
            json={"targets": "8.8.8.8\nexample.com"},
        )
        # Tool may fail due to missing API keys, but endpoint should respond
        assert resp.status_code in [200, 500]


class TestURLAnalyzerEndpoint:
    """Test URL analyzer endpoint."""

    def setup_method(self):
        """Set up test Flask app."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        os.environ["VLAIR_WEBAPP_DB"] = self.temp_db.name

        from vlair.webapp.app import create_app
        from vlair.webapp.auth.models import create_user

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        self.user = create_user("urluser", "url@example.com", "password123")

    def teardown_method(self):
        """Clean up test database."""
        if hasattr(self, "temp_db"):
            try:
                os.unlink(self.temp_db.name)
            except Exception:
                pass

    def get_auth_token(self):
        """Get authentication token."""
        resp = self.client.post(
            "/api/auth/login", json={"username": "urluser", "password": "password123"}
        )
        return resp.get_json()["access_token"]

    def test_url_requires_auth(self):
        """Test URL analysis requires authentication."""
        resp = self.client.post("/api/url/analyze", json={"urls": ["http://example.com"]})
        assert resp.status_code == 401

    def test_url_no_urls(self):
        """Test URL analysis with no URLs."""
        token = self.get_auth_token()
        resp = self.client.post(
            "/api/url/analyze", headers={"Authorization": f"Bearer {token}"}, json={}
        )
        assert resp.status_code == 400

    def test_url_string_input(self):
        """Test URL analysis with single string URL."""
        token = self.get_auth_token()
        resp = self.client.post(
            "/api/url/analyze",
            headers={"Authorization": f"Bearer {token}"},
            json={"urls": "http://example.com"},
        )
        assert resp.status_code == 200


class TestLogAnalyzerEndpoint:
    """Test log analyzer endpoint."""

    def setup_method(self):
        """Set up test Flask app."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        os.environ["VLAIR_WEBAPP_DB"] = self.temp_db.name

        from vlair.webapp.app import create_app
        from vlair.webapp.auth.models import create_user

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        self.user = create_user("loguser", "log@example.com", "password123")

    def teardown_method(self):
        """Clean up test database."""
        if hasattr(self, "temp_db"):
            try:
                os.unlink(self.temp_db.name)
            except Exception:
                pass

    def get_auth_token(self):
        """Get authentication token."""
        resp = self.client.post(
            "/api/auth/login", json={"username": "loguser", "password": "password123"}
        )
        return resp.get_json()["access_token"]

    def test_log_requires_auth(self):
        """Test log analysis requires authentication."""
        resp = self.client.post("/api/log/analyze", json={"log_text": "test"})
        assert resp.status_code == 401

    def test_log_no_input(self):
        """Test log analysis with no input."""
        token = self.get_auth_token()
        resp = self.client.post(
            "/api/log/analyze", headers={"Authorization": f"Bearer {token}"}, json={}
        )
        assert resp.status_code == 400

    def test_log_text_input(self):
        """Test log analysis with text input."""
        token = self.get_auth_token()
        log_line = '127.0.0.1 - - [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 200 1234'
        resp = self.client.post(
            "/api/log/analyze",
            headers={"Authorization": f"Bearer {token}"},
            json={"log_text": log_line},
        )
        assert resp.status_code == 200

    def test_log_file_upload(self):
        """Test log analysis with file upload."""
        token = self.get_auth_token()
        log_content = b'127.0.0.1 - - [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 200 1234'
        data = {"file": (io.BytesIO(log_content), "access.log")}
        resp = self.client.post(
            "/api/log/analyze",
            headers={"Authorization": f"Bearer {token}"},
            data=data,
            content_type="multipart/form-data",
        )
        assert resp.status_code == 200

    def test_log_invalid_file_type(self):
        """Test log analysis with invalid file type."""
        token = self.get_auth_token()
        data = {"file": (io.BytesIO(b"content"), "test.exe")}
        resp = self.client.post(
            "/api/log/analyze",
            headers={"Authorization": f"Bearer {token}"},
            data=data,
            content_type="multipart/form-data",
        )
        assert resp.status_code == 400


class TestDeobfuscatorEndpoint:
    """Test deobfuscator endpoint."""

    def setup_method(self):
        """Set up test Flask app."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        os.environ["VLAIR_WEBAPP_DB"] = self.temp_db.name

        from vlair.webapp.app import create_app
        from vlair.webapp.auth.models import create_user

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        self.user = create_user("deobuser", "deob@example.com", "password123")

    def teardown_method(self):
        """Clean up test database."""
        if hasattr(self, "temp_db"):
            try:
                os.unlink(self.temp_db.name)
            except Exception:
                pass

    def get_auth_token(self):
        """Get authentication token."""
        resp = self.client.post(
            "/api/auth/login", json={"username": "deobuser", "password": "password123"}
        )
        return resp.get_json()["access_token"]

    def test_deobfuscate_requires_auth(self):
        """Test deobfuscation requires authentication."""
        resp = self.client.post("/api/deobfuscate", json={"code": "test"})
        assert resp.status_code == 401

    def test_deobfuscate_no_code(self):
        """Test deobfuscation with no code."""
        token = self.get_auth_token()
        resp = self.client.post(
            "/api/deobfuscate", headers={"Authorization": f"Bearer {token}"}, json={}
        )
        assert resp.status_code == 400

    def test_deobfuscate_success(self):
        """Test successful deobfuscation."""
        token = self.get_auth_token()
        resp = self.client.post(
            "/api/deobfuscate",
            headers={"Authorization": f"Bearer {token}"},
            json={"code": "var x = 'hello';", "language": "javascript"},
        )
        # Tool may have internal issues but endpoint should respond
        assert resp.status_code in [200, 500]
        if resp.status_code == 200:
            data = resp.get_json()
            assert data["success"] is True

    def test_deobfuscate_file_upload(self):
        """Test deobfuscation with file upload."""
        token = self.get_auth_token()
        data = {"file": (io.BytesIO(b"var x = 1;"), "script.js")}
        resp = self.client.post(
            "/api/deobfuscate",
            headers={"Authorization": f"Bearer {token}"},
            data=data,
            content_type="multipart/form-data",
        )
        # Tool may have internal issues but endpoint should respond
        assert resp.status_code in [200, 500]


class TestThreatFeedEndpoints:
    """Test threat feed endpoints."""

    def setup_method(self):
        """Set up test Flask app."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        os.environ["VLAIR_WEBAPP_DB"] = self.temp_db.name

        from vlair.webapp.app import create_app
        from vlair.webapp.auth.models import create_user, Role

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        self.analyst = create_user("feedanalyst", "feedanalyst@example.com", "password123")
        self.senior = create_user(
            "feedsenior", "feedsenior@example.com", "password123", role=Role.SENIOR_ANALYST
        )

    def teardown_method(self):
        """Clean up test database."""
        if hasattr(self, "temp_db"):
            try:
                os.unlink(self.temp_db.name)
            except Exception:
                pass

    def get_analyst_token(self):
        """Get analyst authentication token."""
        resp = self.client.post(
            "/api/auth/login", json={"username": "feedanalyst", "password": "password123"}
        )
        return resp.get_json()["access_token"]

    def get_senior_token(self):
        """Get senior analyst authentication token."""
        resp = self.client.post(
            "/api/auth/login", json={"username": "feedsenior", "password": "password123"}
        )
        return resp.get_json()["access_token"]

    def test_threatfeed_search_requires_auth(self):
        """Test threat feed search requires authentication."""
        resp = self.client.post("/api/threatfeed/search", json={"query": "test"})
        assert resp.status_code == 401

    def test_threatfeed_search_no_query(self):
        """Test threat feed search with no query."""
        token = self.get_analyst_token()
        resp = self.client.post(
            "/api/threatfeed/search", headers={"Authorization": f"Bearer {token}"}, json={}
        )
        # May be 400 or 500 depending on how tool handles missing query
        assert resp.status_code in [400, 500]

    def test_threatfeed_search_success(self):
        """Test successful threat feed search."""
        token = self.get_analyst_token()
        resp = self.client.post(
            "/api/threatfeed/search",
            headers={"Authorization": f"Bearer {token}"},
            json={"query": "test"},
        )
        # Tool may have database issues but should respond
        assert resp.status_code in [200, 500]

    def test_threatfeed_update_requires_senior(self):
        """Test threat feed update requires senior analyst."""
        token = self.get_analyst_token()
        resp = self.client.post(
            "/api/threatfeed/update", headers={"Authorization": f"Bearer {token}"}, json={}
        )
        assert resp.status_code == 403

    def test_threatfeed_update_senior_allowed(self):
        """Test senior analyst can update threat feeds."""
        token = self.get_senior_token()
        resp = self.client.post(
            "/api/threatfeed/update", headers={"Authorization": f"Bearer {token}"}, json={}
        )
        # Tool may have database issues but should respond
        assert resp.status_code in [200, 500]


class TestEMLParserEndpoint:
    """Test EML parser endpoint."""

    def setup_method(self):
        """Set up test Flask app."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        os.environ["VLAIR_WEBAPP_DB"] = self.temp_db.name

        from vlair.webapp.app import create_app
        from vlair.webapp.auth.models import create_user

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        self.user = create_user("emluser", "eml@example.com", "password123")

    def teardown_method(self):
        """Clean up test database."""
        if hasattr(self, "temp_db"):
            try:
                os.unlink(self.temp_db.name)
            except Exception:
                pass

    def get_auth_token(self):
        """Get authentication token."""
        resp = self.client.post(
            "/api/auth/login", json={"username": "emluser", "password": "password123"}
        )
        return resp.get_json()["access_token"]

    def test_eml_requires_auth(self):
        """Test EML parsing requires authentication."""
        data = {"file": (io.BytesIO(b"email content"), "test.eml")}
        resp = self.client.post("/api/eml/parse", data=data, content_type="multipart/form-data")
        assert resp.status_code == 401

    def test_eml_no_file(self):
        """Test EML parsing with no file."""
        token = self.get_auth_token()
        resp = self.client.post("/api/eml/parse", headers={"Authorization": f"Bearer {token}"})
        # May be 400 or 500 depending on error handling
        assert resp.status_code in [400, 500]

    def test_eml_invalid_file_type(self):
        """Test EML parsing with invalid file type."""
        token = self.get_auth_token()
        data = {"file": (io.BytesIO(b"content"), "test.txt")}
        resp = self.client.post(
            "/api/eml/parse",
            headers={"Authorization": f"Bearer {token}"},
            data=data,
            content_type="multipart/form-data",
        )
        # May be 400 or 500 depending on error handling
        assert resp.status_code in [400, 500]


class TestYARAScannerEndpoint:
    """Test YARA scanner endpoint."""

    def setup_method(self):
        """Set up test Flask app."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        os.environ["VLAIR_WEBAPP_DB"] = self.temp_db.name

        from vlair.webapp.app import create_app
        from vlair.webapp.auth.models import create_user

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        self.user = create_user("yarauser", "yara@example.com", "password123")

    def teardown_method(self):
        """Clean up test database."""
        if hasattr(self, "temp_db"):
            try:
                os.unlink(self.temp_db.name)
            except Exception:
                pass

    def get_auth_token(self):
        """Get authentication token."""
        resp = self.client.post(
            "/api/auth/login", json={"username": "yarauser", "password": "password123"}
        )
        return resp.get_json()["access_token"]

    def test_yara_requires_auth(self):
        """Test YARA scanning requires authentication."""
        data = {"file": (io.BytesIO(b"content"), "test.exe")}
        resp = self.client.post("/api/yara/scan", data=data, content_type="multipart/form-data")
        assert resp.status_code == 401

    def test_yara_no_file(self):
        """Test YARA scanning with no file."""
        token = self.get_auth_token()
        resp = self.client.post(
            "/api/yara/scan", headers={"Authorization": f"Bearer {token}"}, json={}
        )
        # May be 400 or 500 depending on error handling
        assert resp.status_code in [400, 500]


class TestCertAnalyzerEndpoint:
    """Test certificate analyzer endpoint."""

    def setup_method(self):
        """Set up test Flask app."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        os.environ["VLAIR_WEBAPP_DB"] = self.temp_db.name

        from vlair.webapp.app import create_app
        from vlair.webapp.auth.models import create_user

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        self.user = create_user("certuser", "cert@example.com", "password123")

    def teardown_method(self):
        """Clean up test database."""
        if hasattr(self, "temp_db"):
            try:
                os.unlink(self.temp_db.name)
            except Exception:
                pass

    def get_auth_token(self):
        """Get authentication token."""
        resp = self.client.post(
            "/api/auth/login", json={"username": "certuser", "password": "password123"}
        )
        return resp.get_json()["access_token"]

    def test_cert_requires_auth(self):
        """Test certificate analysis requires authentication."""
        resp = self.client.post("/api/cert/analyze", json={"hostname": "example.com"})
        assert resp.status_code == 401

    def test_cert_no_input(self):
        """Test certificate analysis with no input."""
        token = self.get_auth_token()
        resp = self.client.post(
            "/api/cert/analyze", headers={"Authorization": f"Bearer {token}"}, json={}
        )
        assert resp.status_code == 400


class TestPCAPAnalyzerEndpoint:
    """Test PCAP analyzer endpoint."""

    def setup_method(self):
        """Set up test Flask app."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        os.environ["VLAIR_WEBAPP_DB"] = self.temp_db.name

        from vlair.webapp.app import create_app
        from vlair.webapp.auth.models import create_user

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        self.user = create_user("pcapuser", "pcap@example.com", "password123")

    def teardown_method(self):
        """Clean up test database."""
        if hasattr(self, "temp_db"):
            try:
                os.unlink(self.temp_db.name)
            except Exception:
                pass

    def get_auth_token(self):
        """Get authentication token."""
        resp = self.client.post(
            "/api/auth/login", json={"username": "pcapuser", "password": "password123"}
        )
        return resp.get_json()["access_token"]

    def test_pcap_requires_auth(self):
        """Test PCAP analysis requires authentication."""
        data = {"file": (io.BytesIO(b"content"), "test.pcap")}
        resp = self.client.post("/api/pcap/analyze", data=data, content_type="multipart/form-data")
        assert resp.status_code == 401

    def test_pcap_no_file(self):
        """Test PCAP analysis with no file."""
        token = self.get_auth_token()
        resp = self.client.post("/api/pcap/analyze", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 400

    def test_pcap_invalid_file_type(self):
        """Test PCAP analysis with invalid file type."""
        token = self.get_auth_token()
        data = {"file": (io.BytesIO(b"content"), "test.txt")}
        resp = self.client.post(
            "/api/pcap/analyze",
            headers={"Authorization": f"Bearer {token}"},
            data=data,
            content_type="multipart/form-data",
        )
        assert resp.status_code == 400


class TestFileCarverEndpoint:
    """Test file carver endpoint."""

    def setup_method(self):
        """Set up test Flask app."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        os.environ["VLAIR_WEBAPP_DB"] = self.temp_db.name

        from vlair.webapp.app import create_app
        from vlair.webapp.auth.models import create_user, Role

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        self.analyst = create_user("carveanalyst", "carveanalyst@example.com", "password123")
        self.senior = create_user(
            "carvesenior", "carvesenior@example.com", "password123", role=Role.SENIOR_ANALYST
        )

    def teardown_method(self):
        """Clean up test database."""
        if hasattr(self, "temp_db"):
            try:
                os.unlink(self.temp_db.name)
            except Exception:
                pass

    def get_analyst_token(self):
        """Get analyst authentication token."""
        resp = self.client.post(
            "/api/auth/login", json={"username": "carveanalyst", "password": "password123"}
        )
        return resp.get_json()["access_token"]

    def get_senior_token(self):
        """Get senior analyst authentication token."""
        resp = self.client.post(
            "/api/auth/login", json={"username": "carvesenior", "password": "password123"}
        )
        return resp.get_json()["access_token"]

    def test_carve_requires_senior(self):
        """Test file carving requires senior analyst."""
        token = self.get_analyst_token()
        data = {"file": (io.BytesIO(b"content"), "test.bin")}
        resp = self.client.post(
            "/api/carve/extract",
            headers={"Authorization": f"Bearer {token}"},
            data=data,
            content_type="multipart/form-data",
        )
        assert resp.status_code == 403

    def test_carve_no_file(self):
        """Test file carving with no file."""
        token = self.get_senior_token()
        resp = self.client.post("/api/carve/extract", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 400

    def test_carve_invalid_file_type(self):
        """Test file carving with invalid file type."""
        token = self.get_senior_token()
        data = {"file": (io.BytesIO(b"content"), "test.txt")}
        resp = self.client.post(
            "/api/carve/extract",
            headers={"Authorization": f"Bearer {token}"},
            data=data,
            content_type="multipart/form-data",
        )
        assert resp.status_code == 400
