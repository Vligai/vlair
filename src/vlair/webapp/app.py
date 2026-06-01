"""
vlair Web Application - Flask application factory.

Entry point
-----------
    from vlair.webapp.app import create_app
    app = create_app()
    app.run()

Or via gunicorn::

    gunicorn "vlair.webapp.app:create_app()"

Environment variables
----------------------
VLAIR_SECRET_KEY        - JWT signing secret (required in production)
VLAIR_WEBAPP_DB         - SQLite DB path (default ~/.vlair/webapp.db)
VLAIR_OPEN_REGISTRATION - "true"/"false" (default true)
VLAIR_ACCESS_TTL        - Access token TTL in seconds (default 900)
VLAIR_REFRESH_TTL       - Refresh token TTL in seconds (default 604800)
ANTHROPIC_API_KEY       - Anthropic API key (required for /api/ai/summarize)

Tool endpoints and their required roles
----------------------------------------
All tool endpoints require at least Role.ANALYST.

Endpoint                Role Required
----------------------  ---------------
/api/ioc/extract        analyst
/api/hash/lookup        analyst
/api/intel/analyze      analyst
/api/url/analyze        analyst
/api/log/analyze        analyst
/api/eml/parse          analyst
/api/yara/scan          analyst
/api/cert/analyze       analyst
/api/deobfuscate        analyst
/api/pcap/analyze       analyst
/api/threatfeed/search  analyst
/api/threatfeed/update  senior_analyst
/api/carve/extract      senior_analyst
/api/admin/*            admin
/api/ai/summarize       analyst
/api/ai/status          authenticated
"""

import os
import sys
import json
import uuid
import tempfile
import threading
from pathlib import Path
from datetime import datetime
from typing import Any, Optional

from flask import Flask, g, jsonify, request, send_from_directory, render_template
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# App-level tool instance cache (P-4)
#
# Tool classes do non-trivial work in __init__ (SQLite connects, env-var
# reads).  Instantiating them once per process and sharing across requests
# avoids that overhead under load.
#
# Only tools whose constructor args are constant across requests (i.e.
# derived purely from env vars or hard-coded defaults) are cached here.
# Tools whose __init__ takes per-request parameters (e.g. IOCExtractor
# with caller-supplied defang/exclude_private_ips flags) are NOT cached.
# ---------------------------------------------------------------------------

_TOOL_CACHE: dict[str, Any] = {}
_TOOL_CACHE_LOCK = threading.Lock()


def _get_tool(cls, *args, **kwargs):
    """Return a cached singleton instance of *cls*, creating it if needed."""
    key = cls.__qualname__
    if key not in _TOOL_CACHE:
        with _TOOL_CACHE_LOCK:
            if key not in _TOOL_CACHE:
                _TOOL_CACHE[key] = cls(*args, **kwargs)
    return _TOOL_CACHE[key]


# ---------------------------------------------------------------------------
# Bootstrap imports
# ---------------------------------------------------------------------------

# Allow running from the repository root as well as when installed
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from vlair.webapp.auth import Role, init_db, require_auth, require_role
from vlair.webapp.auth.routes import auth_bp, admin_bp
from vlair.webapp.tasks import get_task_manager
from vlair.ai.summarizer import ThreatSummarizer, SummaryConfig

# ---------------------------------------------------------------------------
# AI summarizer singleton (lazy-init)
# ---------------------------------------------------------------------------

_ai_summarizer: Optional[ThreatSummarizer] = None


def _get_summarizer() -> ThreatSummarizer:
    global _ai_summarizer
    if _ai_summarizer is None:
        _ai_summarizer = ThreatSummarizer()
    return _ai_summarizer


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__, template_folder="templates", static_folder="static")

    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB
    app.config["UPLOAD_FOLDER"] = tempfile.gettempdir()
    secret = os.getenv("VLAIR_SECRET_KEY", "change-me-in-production")
    if secret == "change-me-in-production" and os.getenv("FLASK_ENV") == "production":
        raise RuntimeError(
            "VLAIR_SECRET_KEY environment variable must be set in production. "
            'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
        )
    app.config["SECRET_KEY"] = secret

    # Initialize database
    init_db()

    # Register auth and admin blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)

    # Register tool routes
    _register_tool_routes(app)

    # Register utility routes
    _register_utility_routes(app)

    # Request ID tracing
    @app.before_request
    def _set_request_id():
        g.request_id = request.headers.get("X-Request-ID", uuid.uuid4().hex[:12])

    # Security headers
    @app.after_request
    def _set_security_headers(response):
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self'"
        )
        response.headers["X-Request-ID"] = g.get("request_id", "")
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # Error handlers
    @app.errorhandler(413)
    def too_large(_err):
        return jsonify({"error": "File too large. Maximum size is 16 MB"}), 413

    @app.errorhandler(404)
    def not_found(_err):
        return jsonify({"error": "Endpoint not found"}), 404

    @app.errorhandler(500)
    def internal(_err):
        return jsonify({"error": "Internal server error"}), 500

    # Trust one upstream proxy hop (Nginx/Caddy/cloud LB) so that
    # request.is_secure reflects the original client's protocol and HSTS fires.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

    return app


# ---------------------------------------------------------------------------
# Allowed extensions helper
# ---------------------------------------------------------------------------

ALLOWED_EXTENSIONS = {
    "eml": {".eml", ".msg"},
    "ioc": {".txt", ".md", ".log", ".json"},
    "log": {".log", ".txt"},
    "pcap": {".pcap", ".pcapng", ".cap"},
    "hash": {".txt", ".csv"},
    "yara": {".yar", ".yara", ".txt"},
    "cert": {".crt", ".cer", ".pem", ".der"},
    "script": {".js", ".ps1", ".vbs", ".bat", ".py", ".txt"},
    "binary": {".bin", ".exe", ".dll", ".img", ".raw", ".dd"},
}


def _allowed(filename: str, file_type: str) -> bool:
    if "." not in filename:
        return False
    ext = "." + filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS.get(file_type, set())


def _save_upload(file, label: str) -> str:
    """Save an uploaded file to /tmp and return the path."""
    filename = secure_filename(file.filename) or f"upload_{label}"
    path = os.path.join(tempfile.gettempdir(), filename)
    file.save(path)
    return path


# Directories that user-supplied paths are allowed to reference
_SAFE_PATH_ROOTS = [
    Path(tempfile.gettempdir()).resolve(),
    Path.home() / ".vlair",
]


def _validate_path(user_path: str) -> str:
    """
    Resolve a user-supplied path and ensure it falls within an allowed
    directory.  Returns the resolved path string or raises ValueError.
    """
    resolved = Path(user_path).resolve()
    for safe_root in _SAFE_PATH_ROOTS:
        try:
            resolved.relative_to(safe_root)
            return str(resolved)
        except ValueError:
            continue
    raise ValueError(
        f"Path '{user_path}' is outside allowed directories. " "Upload the file or place it in ~/.vlair/ instead."
    )


# ---------------------------------------------------------------------------
# Tool route registration
# ---------------------------------------------------------------------------


def _register_tool_routes(app: Flask) -> None:

    # ------------------------------------------------------------------
    # IOC Extractor
    # ------------------------------------------------------------------
    @app.post("/api/ioc/extract")
    @require_role(Role.ANALYST)
    def extract_iocs():
        """
        Extract IOCs from text or uploaded file.

        Body (JSON): {"text": str, "types": [...], "defang": bool, "exclude_private_ips": bool}
        OR multipart with "file" field.
        """
        try:
            from vlair.tools.ioc_extractor import IOCExtractor

            data = request.get_json(silent=True) or {}
            text = data.get("text", "")

            if "file" in request.files:
                f = request.files["file"]
                if f and _allowed(f.filename, "ioc"):
                    text = f.read().decode("utf-8", errors="ignore")

            if not text:
                return jsonify({"error": "No text or file provided"}), 400

            extractor = IOCExtractor(
                defang=data.get("defang", False),
                refang=False,
                exclude_private_ips=data.get("exclude_private_ips", True),
            )
            results = extractor.extract_from_text(text, types=data.get("types", ["all"]))

            total = (
                len(results.get("ips", []))
                + len(results.get("domains", []))
                + len(results.get("urls", []))
                + len(results.get("emails", []))
                + sum(len(v) for v in results.get("hashes", {}).values())
                + len(results.get("cves", []))
            )

            return jsonify(
                {
                    "success": True,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "statistics": {"total_iocs": total},
                    "results": results,
                }
            )
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------
    # Hash Lookup
    # ------------------------------------------------------------------
    @app.post("/api/hash/lookup")
    @require_role(Role.ANALYST)
    def lookup_hashes():
        """
        Look up file hashes.

        Body: {"hashes": ["hash1", ...]}
        """
        try:
            from vlair.tools.hash_lookup import HashLookup

            data = request.get_json(silent=True) or {}
            hashes = data.get("hashes", [])
            if isinstance(hashes, str):
                hashes = [h.strip() for h in hashes.splitlines() if h.strip()]
            if not hashes:
                return jsonify({"error": "No hashes provided"}), 400

            lookup = _get_tool(HashLookup)
            results = [lookup.lookup(h.strip()) for h in hashes if h.strip()]
            results = [r for r in results if r]

            verdicts: dict = {}
            for r in results:
                v = r.get("verdict", "unknown")
                verdicts[v] = verdicts.get(v, 0) + 1

            return jsonify(
                {
                    "success": True,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "statistics": {"total": len(results), "verdicts": verdicts},
                    "results": results,
                }
            )
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------
    # Domain / IP Intel
    # ------------------------------------------------------------------
    @app.post("/api/intel/analyze")
    @require_role(Role.ANALYST)
    def analyze_intel():
        """
        Analyze domains/IPs.

        Body: {"targets": ["8.8.8.8", "example.com"]}
        """
        try:
            from vlair.tools.domain_ip_intel import IntelligenceGatherer

            data = request.get_json(silent=True) or {}
            targets = data.get("targets", [])
            if isinstance(targets, str):
                targets = [t.strip() for t in targets.splitlines() if t.strip()]
            if not targets:
                return jsonify({"error": "No targets provided"}), 400

            intel = _get_tool(IntelligenceGatherer)
            results = [intel.analyze(t.strip()) for t in targets]
            results = [r for r in results if r]

            risk_levels: dict = {}
            for r in results:
                cl = r.get("classification", "unknown")
                risk_levels[cl] = risk_levels.get(cl, 0) + 1

            return jsonify(
                {
                    "success": True,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "statistics": {"total": len(results), "risk_levels": risk_levels},
                    "results": results,
                }
            )
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------
    # URL Analyzer
    # ------------------------------------------------------------------
    @app.post("/api/url/analyze")
    @require_role(Role.ANALYST)
    def analyze_url():
        """
        Analyze URLs for threats.

        Body: {"urls": ["http://example.com"], "cache_enabled": bool}
        """
        try:
            from vlair.tools.url_analyzer import URLAnalyzer

            data = request.get_json(silent=True) or {}
            urls = data.get("urls", [])
            if isinstance(urls, str):
                urls = [urls]
            if not urls:
                return jsonify({"error": "No URLs provided"}), 400

            analyzer = _get_tool(URLAnalyzer)
            results = [analyzer.analyze(u) for u in urls]

            verdicts: dict = {}
            for r in results:
                v = r.get("verdict", "unknown")
                verdicts[v] = verdicts.get(v, 0) + 1

            return jsonify(
                {
                    "success": True,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "statistics": {"total": len(results), "verdicts": verdicts},
                    "results": results,
                }
            )
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------
    # Log Analyzer
    # ------------------------------------------------------------------
    @app.post("/api/log/analyze")
    @require_role(Role.ANALYST)
    def analyze_logs():
        """Analyze security log files, optionally with Sigma rules."""
        try:
            from vlair.tools.log_analyzer import LogAnalyzer

            log_type = request.form.get("log_type", "auto")
            sigma_rules = None
            sigma_min_level = "low"
            temp_path = None

            if "file" in request.files:
                f = request.files["file"]
                if not f or not _allowed(f.filename, "log"):
                    return jsonify({"error": "Invalid file type"}), 400
                temp_path = _save_upload(f, "log")
                # multipart/form-data sigma params
                sigma_param = request.form.get("sigma_rules", "").strip()
                sigma_min_level = request.form.get("sigma_min_level", "low").strip()
            else:
                data = request.get_json(silent=True) or {}
                text = data.get("log_text", "")
                if not text:
                    return jsonify({"error": "No log file or text provided"}), 400
                log_type = data.get("log_type", "auto")
                sigma_param = str(data.get("sigma_rules", "")).strip()
                sigma_min_level = str(data.get("sigma_min_level", "low")).strip()
                temp_path = os.path.join(tempfile.gettempdir(), f"vlair_log_{os.getpid()}.log")
                with open(temp_path, "w") as fh:
                    fh.write(text)

            # Resolve sigma_rules param — "builtin" passes through; filesystem paths are validated
            if sigma_param == "builtin":
                sigma_rules = "builtin"
            elif sigma_param:
                try:
                    sigma_rules = _validate_path(sigma_param)
                except ValueError as ve:
                    return jsonify({"error": str(ve)}), 400

            try:
                analyzer = _get_tool(LogAnalyzer)
                results = analyzer.analyze_file(
                    temp_path,
                    log_type=log_type,
                    sigma_rules=sigma_rules,
                    sigma_min_level=sigma_min_level,
                )
            finally:
                if temp_path and os.path.exists(temp_path):
                    os.remove(temp_path)

            meta = results.get("metadata", {})
            response: dict = {
                "success": True,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "statistics": results.get("statistics", {}),
                "alerts": results.get("alerts", []),
                "top_ips": results.get("top_ips", []),
                "top_paths": results.get("top_paths", []),
            }
            # Sigma metadata (task 7.2)
            if "sigma_rules_loaded" in meta:
                response["sigma_rules_loaded"] = meta["sigma_rules_loaded"]
                response["sigma_rules_evaluated"] = meta["sigma_rules_evaluated"]
                response["skipped_rules"] = meta.get("skipped_rules", [])

            return jsonify(response)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------
    # EML Parser
    # ------------------------------------------------------------------
    @app.post("/api/eml/parse")
    @require_role(Role.ANALYST)
    def parse_email():
        """Parse and analyze .eml files."""
        try:
            from vlair.tools.eml_parser import EMLParser

            if "file" not in request.files:
                return jsonify({"error": "No file provided"}), 400
            f = request.files["file"]
            if not f or not _allowed(f.filename, "eml"):
                return jsonify({"error": "Invalid file type. Expected .eml"}), 400

            temp_path = _save_upload(f, "eml")
            try:
                use_vt = request.form.get("use_virustotal", "false").lower() == "true"
                parser = EMLParser(use_virustotal=use_vt)
                results = parser.parse(temp_path)
            finally:
                os.remove(temp_path)

            return jsonify(
                {
                    "success": True,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "results": results,
                }
            )
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------
    # YARA Scanner
    # ------------------------------------------------------------------
    @app.post("/api/yara/scan")
    @require_role(Role.ANALYST)
    def yara_scan():
        """Scan a file with YARA rules."""
        try:
            from vlair.tools.yara_scanner import YARAScanner

            rules_path = request.form.get("rules_path") or ((request.get_json(silent=True) or {}).get("rules_path"))
            if rules_path:
                try:
                    rules_path = _validate_path(rules_path)
                except ValueError as path_err:
                    return jsonify({"error": str(path_err)}), 400
            temp_path = None

            if "file" in request.files:
                f = request.files["file"]
                temp_path = _save_upload(f, "sample")

            if not temp_path:
                file_path = (request.get_json(silent=True) or {}).get("file_path")
                if not file_path:
                    return jsonify({"error": "No file provided"}), 400
                try:
                    temp_path = _validate_path(file_path)
                except ValueError as path_err:
                    return jsonify({"error": str(path_err)}), 400
                _cleanup = False
            else:
                _cleanup = True

            try:
                scanner = YARAScanner(rules_path=rules_path)
                results = scanner.scan_file(temp_path)
            finally:
                if _cleanup and os.path.exists(temp_path):
                    os.remove(temp_path)

            return jsonify(
                {
                    "success": True,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "statistics": {
                        "matches": len(results.get("matches", [])),
                        "rules_loaded": results.get("rules_loaded", 0),
                    },
                    "results": results,
                }
            )
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------
    # Certificate Analyzer
    # ------------------------------------------------------------------
    @app.post("/api/cert/analyze")
    @require_role(Role.ANALYST)
    def cert_analyze():
        """
        Analyze SSL/TLS certificates.

        Body (JSON): {"hostname": "example.com", "port": 443}
        OR multipart with .pem/.crt file.
        """
        try:
            from vlair.tools.cert_analyzer import CertificateAnalyzer

            if "file" in request.files:
                f = request.files["file"]
                if f and _allowed(f.filename, "cert"):
                    cert_data = f.read()
                    analyzer = _get_tool(CertificateAnalyzer)
                    results = analyzer.analyze_certificate_data(cert_data)
                    return jsonify(
                        {
                            "success": True,
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                            "results": results,
                        }
                    )

            data = request.get_json(silent=True) or {}
            hostname = data.get("hostname")
            if not hostname:
                return jsonify({"error": "hostname or certificate file required"}), 400

            analyzer = _get_tool(CertificateAnalyzer)
            results = analyzer.analyze_host(hostname, data.get("port", 443))
            return jsonify(
                {
                    "success": True,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "results": results,
                }
            )
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------
    # Deobfuscator
    # ------------------------------------------------------------------
    @app.post("/api/deobfuscate")
    @require_role(Role.ANALYST)
    def deobfuscate():
        """
        Deobfuscate malicious scripts.

        Body: {"code": str, "language": "auto"|"javascript"|"powershell"|...}
        OR multipart with script file.
        """
        try:
            from vlair.tools.deobfuscator import Deobfuscator

            code = None
            language = "auto"

            if "file" in request.files:
                f = request.files["file"]
                if f and _allowed(f.filename, "script"):
                    code = f.read().decode("utf-8", errors="ignore")
                    language = request.form.get("language", "auto")

            if not code:
                data = request.get_json(silent=True) or {}
                code = data.get("code")
                language = data.get("language", "auto")

            if not code:
                return jsonify({"error": "No script code provided"}), 400

            d = _get_tool(Deobfuscator)
            results = d.deobfuscate(code, language=language)

            iocs = results.get("iocs", {})
            total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))

            return jsonify(
                {
                    "success": True,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "statistics": {
                        "layers_decoded": results.get("layers", 0),
                        "iocs_found": total_iocs,
                    },
                    "results": results,
                }
            )
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------
    # PCAP Analyzer
    # ------------------------------------------------------------------
    @app.post("/api/pcap/analyze")
    @require_role(Role.ANALYST)
    def pcap_analyze():
        """Analyze .pcap/.pcapng files."""
        try:
            from vlair.tools.pcap_analyzer import PCAPAnalyzer

            if "file" not in request.files:
                return jsonify({"error": "No file provided"}), 400
            f = request.files["file"]
            if not f or not _allowed(f.filename, "pcap"):
                return jsonify({"error": "Invalid file type. Expected .pcap or .pcapng"}), 400

            temp_path = _save_upload(f, "pcap")
            try:
                analyzer = _get_tool(PCAPAnalyzer)
                results = analyzer.analyze(temp_path)
            finally:
                os.remove(temp_path)

            return jsonify(
                {
                    "success": True,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "statistics": results.get("statistics", {}),
                    "alerts": results.get("alerts", []),
                    "protocols": results.get("protocols", {}),
                    "top_talkers": results.get("top_talkers", []),
                }
            )
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------
    # Threat Feed Aggregator (search = analyst, update = senior_analyst)
    # ------------------------------------------------------------------
    @app.post("/api/threatfeed/search")
    @require_role(Role.ANALYST)
    def threatfeed_search():
        """Search threat feed for IOCs."""
        try:
            from vlair.tools.threat_feed_aggregator import ThreatFeedAggregator

            data = request.get_json(silent=True) or {}
            query = data.get("query")
            if not query:
                return jsonify({"error": "query is required"}), 400

            agg = _get_tool(ThreatFeedAggregator)
            results = agg.search(
                query,
                ioc_type=data.get("ioc_type"),
                min_confidence=data.get("min_confidence", 0),
            )

            avg_conf = sum(r.get("confidence", 0) for r in results) / len(results) if results else 0
            return jsonify(
                {
                    "success": True,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "statistics": {"total": len(results), "avg_confidence": avg_conf},
                    "results": results,
                }
            )
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    @app.post("/api/threatfeed/update")
    @require_role(Role.SENIOR_ANALYST)
    def threatfeed_update():
        """Pull fresh data from threat feed sources."""
        try:
            from vlair.tools.threat_feed_aggregator import ThreatFeedAggregator

            data = request.get_json(silent=True) or {}
            agg = _get_tool(ThreatFeedAggregator)
            results = agg.update_feeds(sources=data.get("sources"))
            return jsonify(
                {
                    "success": True,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "statistics": results.get("statistics", {}),
                    "results": results,
                }
            )
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------
    # File Carver (senior_analyst - operates on forensic images)
    # ------------------------------------------------------------------
    @app.post("/api/carve/extract")
    @require_role(Role.SENIOR_ANALYST)
    def carve_files():
        """Extract embedded files from disk images or memory dumps."""
        try:
            from vlair.tools.file_carver import FileCarver

            if "file" not in request.files:
                return jsonify({"error": "No file provided"}), 400
            f = request.files["file"]
            if not f or not _allowed(f.filename, "binary"):
                return jsonify({"error": "Invalid file type for carving"}), 400

            temp_path = _save_upload(f, "image")
            output_dir = os.path.join(tempfile.gettempdir(), f"vlair_carved_{os.getpid()}")
            os.makedirs(output_dir, exist_ok=True)

            try:
                carver = _get_tool(FileCarver)
                results = carver.carve(temp_path, output_dir=output_dir)
            finally:
                os.remove(temp_path)

            return jsonify(
                {
                    "success": True,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "statistics": {
                        "files_carved": len(results.get("files", [])),
                        "file_types": results.get("file_types", {}),
                        "output_directory": output_dir,
                    },
                    "results": results,
                }
            )
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------
    # AI Analysis (Phase 6.1)
    # ------------------------------------------------------------------
    @app.post("/api/ai/summarize")
    @require_role(Role.ANALYST)
    def ai_summarize():
        """
        Generate a Claude-powered threat summary from an existing tool result.

        Body (JSON): {
            "ioc_value":   str,   # primary indicator (hash, domain, filename, …)
            "ioc_type":    str,   # hash|domain|ip|url|email|log|pcap|cert|script|ioc
            "tool_result": dict,  # parsed JSON from a vlair tool endpoint
            "depth":       str    # quick|standard|thorough (optional, default standard)
        }
        """
        body = request.get_json(silent=True) or {}
        ioc_value = str(body.get("ioc_value", "")).strip()
        ioc_type = str(body.get("ioc_type", "unknown")).strip()
        tool_result = body.get("tool_result", {})
        depth = body.get("depth", "standard")

        if not ioc_value or not tool_result:
            return jsonify({"error": "ioc_value and tool_result are required"}), 400

        summarizer = _get_summarizer()
        if not summarizer.is_available():
            return jsonify({"error": "AI analysis unavailable. Set ANTHROPIC_API_KEY."}), 503

        try:
            result = summarizer.summarize(ioc_value, ioc_type, tool_result, depth)
            return jsonify(
                {
                    "success": True,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "analysis": result,
                }
            )
        except Exception as exc:
            return jsonify({"error": f"AI analysis failed: {str(exc)}"}), 500

    @app.get("/api/ai/status")
    @require_auth
    def ai_status():
        """Return AI availability and configured model."""
        summarizer = _get_summarizer()
        return jsonify({"available": summarizer.is_available(), "model": summarizer.config.model})

    # ------------------------------------------------------------------
    # Background Task Queue
    # ------------------------------------------------------------------
    @app.post("/api/tasks/<tool>")
    @require_role(Role.ANALYST)
    def submit_task(tool):
        """Submit a long-running tool job for background execution.

        Supported tools: yara, pcap.
        Returns 202 with a task_id and poll URL.
        """
        if tool not in ("yara", "pcap"):
            return jsonify({"error": f"Unsupported tool '{tool}'. Use 'yara' or 'pcap'."}), 400

        try:
            if tool == "yara":
                rules_path = request.form.get("rules_path") or ((request.get_json(silent=True) or {}).get("rules_path"))
                if rules_path:
                    try:
                        rules_path = _validate_path(rules_path)
                    except ValueError as path_err:
                        return jsonify({"error": str(path_err)}), 400

                temp_path = None
                _cleanup = True

                if "file" in request.files:
                    f = request.files["file"]
                    temp_path = _save_upload(f, "sample")
                else:
                    file_path = (request.get_json(silent=True) or {}).get("file_path")
                    if not file_path:
                        return jsonify({"error": "No file provided"}), 400
                    try:
                        temp_path = _validate_path(file_path)
                    except ValueError as path_err:
                        return jsonify({"error": str(path_err)}), 400
                    _cleanup = False

                # Capture values for closure (no Flask request context)
                _rules = rules_path
                _target = temp_path
                _do_cleanup = _cleanup

                def _run_yara():
                    from vlair.tools.yara_scanner import YaraScanner

                    try:
                        scanner = YaraScanner(rules_path=_rules)
                        return scanner.scan_file(_target)
                    finally:
                        if _do_cleanup and os.path.exists(_target):
                            os.remove(_target)

                task_id = get_task_manager().submit("yara", _run_yara)

            else:  # pcap
                if "file" not in request.files:
                    return jsonify({"error": "No file provided"}), 400
                f = request.files["file"]
                if not f or not _allowed(f.filename, "pcap"):
                    return jsonify({"error": "Invalid file type. Expected .pcap or .pcapng"}), 400
                _target = _save_upload(f, "pcap")

                def _run_pcap():
                    from vlair.tools.pcap_analyzer import PCAPAnalyzer

                    try:
                        analyzer = _get_tool(PCAPAnalyzer)
                        return analyzer.analyze(_target)
                    finally:
                        if os.path.exists(_target):
                            os.remove(_target)

                task_id = get_task_manager().submit("pcap", _run_pcap)

            return (
                jsonify(
                    {
                        "task_id": task_id,
                        "status": "pending",
                        "poll_url": f"/api/tasks/{task_id}",
                    }
                ),
                202,
            )
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    @app.get("/api/tasks/<task_id>")
    @require_role(Role.ANALYST)
    def get_task_status(task_id):
        """Poll the status of a background task."""
        status = get_task_manager().get_status(task_id)
        if status is None:
            return jsonify({"error": "Task not found"}), 404

        resp = jsonify(status)
        if status["status"] in ("pending", "running"):
            resp.headers["Retry-After"] = "2"
        return resp


# ---------------------------------------------------------------------------
# Utility / informational routes
# ---------------------------------------------------------------------------


def _register_utility_routes(app: Flask) -> None:

    @app.get("/api/health")
    def health():
        """Public health check endpoint."""
        return jsonify(
            {
                "status": "healthy",
                "version": "5.1.0",
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        )

    @app.get("/api/endpoints")
    @require_auth
    def list_endpoints():
        """Return a summary of all available tool endpoints with required roles."""
        return jsonify(
            {
                "endpoints": [
                    {
                        "path": "/api/ioc/extract",
                        "method": "POST",
                        "role": "analyst",
                        "description": "Extract IOCs from text or file",
                    },
                    {
                        "path": "/api/hash/lookup",
                        "method": "POST",
                        "role": "analyst",
                        "description": "Look up file hashes",
                    },
                    {
                        "path": "/api/intel/analyze",
                        "method": "POST",
                        "role": "analyst",
                        "description": "Analyze domains and IP addresses",
                    },
                    {
                        "path": "/api/url/analyze",
                        "method": "POST",
                        "role": "analyst",
                        "description": "Analyze URLs for threats",
                    },
                    {
                        "path": "/api/log/analyze",
                        "method": "POST",
                        "role": "analyst",
                        "description": "Analyze security logs",
                    },
                    {
                        "path": "/api/eml/parse",
                        "method": "POST",
                        "role": "analyst",
                        "description": "Parse and analyze email files",
                    },
                    {
                        "path": "/api/yara/scan",
                        "method": "POST",
                        "role": "analyst",
                        "description": "Scan files with YARA rules",
                    },
                    {
                        "path": "/api/cert/analyze",
                        "method": "POST",
                        "role": "analyst",
                        "description": "Analyze SSL/TLS certificates",
                    },
                    {
                        "path": "/api/deobfuscate",
                        "method": "POST",
                        "role": "analyst",
                        "description": "Deobfuscate malicious scripts",
                    },
                    {
                        "path": "/api/pcap/analyze",
                        "method": "POST",
                        "role": "analyst",
                        "description": "Analyze PCAP network captures",
                    },
                    {
                        "path": "/api/threatfeed/search",
                        "method": "POST",
                        "role": "analyst",
                        "description": "Search threat feed database",
                    },
                    {
                        "path": "/api/threatfeed/update",
                        "method": "POST",
                        "role": "senior_analyst",
                        "description": "Update threat feed data",
                    },
                    {
                        "path": "/api/carve/extract",
                        "method": "POST",
                        "role": "senior_analyst",
                        "description": "Extract files from disk images",
                    },
                    {
                        "path": "/api/auth/register",
                        "method": "POST",
                        "role": "public",
                        "description": "Register a new account",
                    },
                    {
                        "path": "/api/auth/login",
                        "method": "POST",
                        "role": "public",
                        "description": "Login and get tokens",
                    },
                    {
                        "path": "/api/auth/refresh",
                        "method": "POST",
                        "role": "public",
                        "description": "Refresh access token",
                    },
                    {
                        "path": "/api/auth/me",
                        "method": "GET",
                        "role": "authenticated",
                        "description": "Get current user profile",
                    },
                    {
                        "path": "/api/auth/keys",
                        "method": "POST",
                        "role": "authenticated",
                        "description": "Create API key",
                    },
                    {
                        "path": "/api/admin/users",
                        "method": "GET",
                        "role": "admin",
                        "description": "List all users",
                    },
                    {
                        "path": "/api/admin/audit",
                        "method": "GET",
                        "role": "senior_analyst",
                        "description": "Query audit log",
                    },
                    {
                        "path": "/api/ai/summarize",
                        "method": "POST",
                        "role": "analyst",
                        "description": "Claude-powered threat summary for a tool result",
                    },
                    {
                        "path": "/api/ai/status",
                        "method": "GET",
                        "role": "authenticated",
                        "description": "AI analysis availability and model info",
                    },
                    {
                        "path": "/api/tasks/<tool>",
                        "method": "POST",
                        "role": "analyst",
                        "description": "Submit background task (yara, pcap)",
                    },
                    {
                        "path": "/api/tasks/<task_id>",
                        "method": "GET",
                        "role": "analyst",
                        "description": "Poll background task status",
                    },
                ]
            }
        )

    # ------------------------------------------------------------------
    # SPA catch-all: serve the Vue.js frontend for any non-API route
    # ------------------------------------------------------------------
    @app.get("/")
    @app.get("/<path:path>")
    def spa_index(path=""):
        """Serve the Vue.js SPA for all non-API routes."""
        if path.startswith("api/"):
            return jsonify({"error": "Endpoint not found"}), 404
        return render_template("index.html")
