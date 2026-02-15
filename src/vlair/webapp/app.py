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
"""

import os
import sys
import json
import tempfile
from pathlib import Path
from datetime import datetime

from flask import Flask, jsonify, request
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# Bootstrap imports
# ---------------------------------------------------------------------------

# Allow running from the repository root as well as when installed
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from vlair.webapp.auth import Role, init_db, require_auth, require_role
from vlair.webapp.auth.routes import auth_bp, admin_bp


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__, template_folder="templates", static_folder="static")

    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB
    app.config["UPLOAD_FOLDER"] = tempfile.gettempdir()
    app.config["SECRET_KEY"] = os.getenv("VLAIR_SECRET_KEY", "change-me-in-production")

    # Initialize database
    init_db()

    # Register auth and admin blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)

    # Register tool routes
    _register_tool_routes(app)

    # Register utility routes
    _register_utility_routes(app)

    # Error handlers
    @app.errorhandler(413)
    def too_large(_err):
        return jsonify({"error": "File too large. Maximum size is 50 MB"}), 413

    @app.errorhandler(404)
    def not_found(_err):
        return jsonify({"error": "Endpoint not found"}), 404

    @app.errorhandler(500)
    def internal(_err):
        return jsonify({"error": "Internal server error"}), 500

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

            lookup = HashLookup()
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

            intel = IntelligenceGatherer()
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

            analyzer = URLAnalyzer(cache_enabled=data.get("cache_enabled", True))
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
        """Analyze security log files."""
        try:
            from vlair.tools.log_analyzer import LogAnalyzer

            log_type = request.form.get("log_type", "auto")
            temp_path = None

            if "file" in request.files:
                f = request.files["file"]
                if not f or not _allowed(f.filename, "log"):
                    return jsonify({"error": "Invalid file type"}), 400
                temp_path = _save_upload(f, "log")
            else:
                data = request.get_json(silent=True) or {}
                text = data.get("log_text", "")
                if not text:
                    return jsonify({"error": "No log file or text provided"}), 400
                log_type = data.get("log_type", "auto")
                temp_path = os.path.join(tempfile.gettempdir(), f"vlair_log_{os.getpid()}.log")
                with open(temp_path, "w") as fh:
                    fh.write(text)

            try:
                analyzer = LogAnalyzer()
                results = analyzer.analyze_file(temp_path, log_type=log_type)
            finally:
                if temp_path and os.path.exists(temp_path):
                    os.remove(temp_path)

            return jsonify(
                {
                    "success": True,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "statistics": results.get("statistics", {}),
                    "alerts": results.get("alerts", []),
                    "top_ips": results.get("top_ips", []),
                    "top_paths": results.get("top_paths", []),
                }
            )
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

            rules_path = request.form.get("rules_path") or (
                (request.get_json(silent=True) or {}).get("rules_path")
            )
            temp_path = None

            if "file" in request.files:
                f = request.files["file"]
                temp_path = _save_upload(f, "sample")

            if not temp_path:
                file_path = (request.get_json(silent=True) or {}).get("file_path")
                if not file_path:
                    return jsonify({"error": "No file provided"}), 400
                temp_path = file_path
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
                    analyzer = CertificateAnalyzer()
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

            analyzer = CertificateAnalyzer()
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

            d = Deobfuscator()
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
                analyzer = PCAPAnalyzer()
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

            agg = ThreatFeedAggregator()
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
            agg = ThreatFeedAggregator()
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
                carver = FileCarver()
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
                ]
            }
        )
