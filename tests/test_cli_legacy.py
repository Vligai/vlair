#!/usr/bin/env python3
"""
Comprehensive tests for the legacy CLI (src/vlair/cli/legacy.py).

Tests cover:
- Parser creation and subcommand existence
- Argument parsing for every subcommand
- main() routing to each tool's main() with correct sys.argv reconstruction
- No-args help display
- Unknown command handling
"""

import sys
import pytest
from unittest.mock import patch, MagicMock

from vlair.cli.legacy import create_parser, main


def _capture_argv(storage):
    """Return a side_effect callable that snapshots sys.argv when the mock is called."""

    def _side_effect(*args, **kwargs):
        storage["argv"] = list(sys.argv)

    return _side_effect


# ---------------------------------------------------------------------------
# 1. TestCreateParser - verify parser creation, subcommands exist
# ---------------------------------------------------------------------------
class TestCreateParser:
    """Verify that create_parser() returns a valid parser with all subcommands."""

    def test_returns_parser(self):
        parser = create_parser()
        assert parser is not None
        assert parser.prog == "vlair"

    def test_version_action(self):
        parser = create_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])
        assert exc_info.value.code == 0

    @pytest.mark.parametrize(
        "subcommand",
        ["eml", "ioc", "hash", "intel", "log", "pcap", "url", "yara", "cert", "deobfuscate"],
    )
    def test_subcommand_exists(self, subcommand):
        """Each expected subcommand should be recognized without error."""
        parser = create_parser()
        # Subcommands that require a positional arg need one provided.
        positional_map = {
            "eml": ["eml", "test.eml"],
            "ioc": ["ioc"],
            "hash": ["hash"],
            "intel": ["intel"],
            "log": ["log", "test.log"],
            "pcap": ["pcap", "test.pcap"],
            "url": ["url"],
            "yara": ["yara"],
            "cert": ["cert"],
            "deobfuscate": ["deobfuscate"],
        }
        args, _ = parser.parse_known_args(positional_map[subcommand])
        assert args.command == subcommand

    def test_no_command_gives_none(self):
        parser = create_parser()
        args, _ = parser.parse_known_args([])
        assert args.command is None


# ---------------------------------------------------------------------------
# 2. TestParseEML
# ---------------------------------------------------------------------------
class TestParseEML:
    """Test argument parsing for the 'eml' subcommand."""

    def setup_method(self):
        self.parser = create_parser()

    def test_minimal(self):
        args = self.parser.parse_args(["eml", "email.eml"])
        assert args.command == "eml"
        assert args.eml == "email.eml"
        assert args.output is None
        assert args.vt is False
        assert args.verbose is False

    def test_all_options(self):
        args = self.parser.parse_args(
            ["eml", "email.eml", "--output", "report.json", "--vt", "--verbose"]
        )
        assert args.eml == "email.eml"
        assert args.output == "report.json"
        assert args.vt is True
        assert args.verbose is True

    def test_short_output(self):
        args = self.parser.parse_args(["eml", "email.eml", "-o", "out.json"])
        assert args.output == "out.json"

    def test_missing_file_raises(self):
        with pytest.raises(SystemExit):
            self.parser.parse_args(["eml"])


# ---------------------------------------------------------------------------
# 3. TestParseIOC
# ---------------------------------------------------------------------------
class TestParseIOC:
    """Test argument parsing for the 'ioc' subcommand."""

    def setup_method(self):
        self.parser = create_parser()

    def test_minimal(self):
        args = self.parser.parse_args(["ioc"])
        assert args.command == "ioc"
        assert args.input is None
        assert args.file is None
        assert args.format == "json"
        assert args.refang is False
        assert args.defang is False
        assert args.exclude_private is False

    def test_positional_input(self):
        args = self.parser.parse_args(["ioc", "report.txt"])
        assert args.input == "report.txt"

    def test_all_options(self):
        args = self.parser.parse_args(
            [
                "ioc",
                "report.txt",
                "--file",
                "extra.txt",
                "--output",
                "iocs.csv",
                "--format",
                "csv",
                "--types",
                "ip",
                "domain",
                "--refang",
                "--defang",
                "--exclude-private",
            ]
        )
        assert args.input == "report.txt"
        assert args.file == "extra.txt"
        assert args.output == "iocs.csv"
        assert args.format == "csv"
        assert args.types == ["ip", "domain"]
        assert args.refang is True
        assert args.defang is True
        assert args.exclude_private is True

    def test_format_choices(self):
        for fmt in ["json", "csv", "txt", "stix"]:
            args = self.parser.parse_args(["ioc", "--format", fmt])
            assert args.format == fmt

    def test_invalid_format(self):
        with pytest.raises(SystemExit):
            self.parser.parse_args(["ioc", "--format", "xml"])


# ---------------------------------------------------------------------------
# 4. TestParseHash
# ---------------------------------------------------------------------------
class TestParseHash:
    """Test argument parsing for the 'hash' subcommand."""

    def setup_method(self):
        self.parser = create_parser()

    def test_minimal(self):
        args = self.parser.parse_args(["hash"])
        assert args.command == "hash"
        assert args.hash is None
        assert args.no_cache is False
        assert args.rate_limit == 4
        assert args.verbose is False

    def test_positional_hash(self):
        h = "44d88612fea8a8f36de82e1278abb02f"
        args = self.parser.parse_args(["hash", h])
        assert args.hash == h

    def test_all_options(self):
        args = self.parser.parse_args(
            [
                "hash",
                "abc123",
                "--file",
                "hashes.txt",
                "--output",
                "out.json",
                "--format",
                "csv",
                "--no-cache",
                "--rate-limit",
                "10",
                "--verbose",
            ]
        )
        assert args.hash == "abc123"
        assert args.file == "hashes.txt"
        assert args.output == "out.json"
        assert args.format == "csv"
        assert args.no_cache is True
        assert args.rate_limit == 10
        assert args.verbose is True

    def test_verbose_short(self):
        args = self.parser.parse_args(["hash", "-v"])
        assert args.verbose is True

    def test_format_choices(self):
        for fmt in ["json", "csv", "txt"]:
            args = self.parser.parse_args(["hash", "--format", fmt])
            assert args.format == fmt


# ---------------------------------------------------------------------------
# 5. TestParseIntel
# ---------------------------------------------------------------------------
class TestParseIntel:
    """Test argument parsing for the 'intel' subcommand."""

    def setup_method(self):
        self.parser = create_parser()

    def test_minimal(self):
        args = self.parser.parse_args(["intel"])
        assert args.command == "intel"
        assert args.target is None
        assert args.verbose is False

    def test_positional_target(self):
        args = self.parser.parse_args(["intel", "malicious.com"])
        assert args.target == "malicious.com"

    def test_all_options(self):
        args = self.parser.parse_args(
            [
                "intel",
                "8.8.8.8",
                "--file",
                "domains.txt",
                "--output",
                "out.json",
                "--format",
                "csv",
                "--verbose",
            ]
        )
        assert args.target == "8.8.8.8"
        assert args.file == "domains.txt"
        assert args.output == "out.json"
        assert args.format == "csv"
        assert args.verbose is True

    def test_format_choices(self):
        for fmt in ["json", "csv"]:
            args = self.parser.parse_args(["intel", "--format", fmt])
            assert args.format == fmt

    def test_invalid_format(self):
        with pytest.raises(SystemExit):
            self.parser.parse_args(["intel", "--format", "txt"])


# ---------------------------------------------------------------------------
# 6. TestParseLog
# ---------------------------------------------------------------------------
class TestParseLog:
    """Test argument parsing for the 'log' subcommand."""

    def setup_method(self):
        self.parser = create_parser()

    def test_minimal(self):
        args = self.parser.parse_args(["log", "access.log"])
        assert args.command == "log"
        assert args.log_file == "access.log"
        assert args.type == "auto"
        assert args.format == "json"
        assert args.verbose is False

    def test_all_options(self):
        args = self.parser.parse_args(
            [
                "log",
                "access.log",
                "--type",
                "apache",
                "--output",
                "out.json",
                "--format",
                "txt",
                "--verbose",
            ]
        )
        assert args.log_file == "access.log"
        assert args.type == "apache"
        assert args.output == "out.json"
        assert args.format == "txt"
        assert args.verbose is True

    def test_type_choices(self):
        for t in ["auto", "apache", "nginx", "syslog"]:
            args = self.parser.parse_args(["log", "f.log", "--type", t])
            assert args.type == t

    def test_missing_file_raises(self):
        with pytest.raises(SystemExit):
            self.parser.parse_args(["log"])

    def test_short_flags(self):
        args = self.parser.parse_args(["log", "f.log", "-t", "nginx", "-f", "csv", "-v"])
        assert args.type == "nginx"
        assert args.format == "csv"
        assert args.verbose is True


# ---------------------------------------------------------------------------
# 7. TestParsePCAP
# ---------------------------------------------------------------------------
class TestParsePCAP:
    """Test argument parsing for the 'pcap' subcommand."""

    def setup_method(self):
        self.parser = create_parser()

    def test_minimal(self):
        args = self.parser.parse_args(["pcap", "capture.pcap"])
        assert args.command == "pcap"
        assert args.pcap_file == "capture.pcap"
        assert args.format == "json"
        assert args.verbose is False

    def test_all_options(self):
        args = self.parser.parse_args(
            ["pcap", "capture.pcap", "--output", "out.json", "--format", "txt", "--verbose"]
        )
        assert args.pcap_file == "capture.pcap"
        assert args.output == "out.json"
        assert args.format == "txt"
        assert args.verbose is True

    def test_missing_file_raises(self):
        with pytest.raises(SystemExit):
            self.parser.parse_args(["pcap"])

    def test_short_flags(self):
        args = self.parser.parse_args(["pcap", "c.pcap", "-o", "out.json", "-f", "csv", "-v"])
        assert args.output == "out.json"
        assert args.format == "csv"
        assert args.verbose is True


# ---------------------------------------------------------------------------
# 8. TestParseURL
# ---------------------------------------------------------------------------
class TestParseURL:
    """Test argument parsing for the 'url' subcommand."""

    def setup_method(self):
        self.parser = create_parser()

    def test_minimal(self):
        args = self.parser.parse_args(["url"])
        assert args.command == "url"
        assert args.url is None
        assert args.no_cache is False
        assert args.verbose is False

    def test_positional_url(self):
        args = self.parser.parse_args(["url", "http://evil.com"])
        assert args.url == "http://evil.com"

    def test_all_options(self):
        args = self.parser.parse_args(
            [
                "url",
                "http://evil.com",
                "--file",
                "urls.txt",
                "--output",
                "out.json",
                "--format",
                "txt",
                "--no-cache",
                "--verbose",
            ]
        )
        assert args.url == "http://evil.com"
        assert args.file == "urls.txt"
        assert args.output == "out.json"
        assert args.format == "txt"
        assert args.no_cache is True
        assert args.verbose is True


# ---------------------------------------------------------------------------
# 9. TestParseCert
# ---------------------------------------------------------------------------
class TestParseCert:
    """Test argument parsing for the 'cert' subcommand."""

    def setup_method(self):
        self.parser = create_parser()

    def test_minimal(self):
        args = self.parser.parse_args(["cert"])
        assert args.command == "cert"
        assert args.target is None
        assert args.port == 443
        assert args.format == "txt"
        assert args.verbose is False

    def test_positional_target(self):
        args = self.parser.parse_args(["cert", "https://example.com"])
        assert args.target == "https://example.com"

    def test_all_options(self):
        args = self.parser.parse_args(
            [
                "cert",
                "example.com",
                "--file",
                "cert.pem",
                "--file-list",
                "domains.txt",
                "--hostname",
                "example.com",
                "--port",
                "8443",
                "--ct-search",
                "example.com",
                "--format",
                "json",
                "--output",
                "out.json",
                "--verbose",
            ]
        )
        assert args.target == "example.com"
        assert args.file == "cert.pem"
        assert args.file_list == "domains.txt"
        assert args.hostname == "example.com"
        assert args.port == 8443
        assert args.ct_search == "example.com"
        assert args.format == "json"
        assert args.output == "out.json"
        assert args.verbose is True

    def test_format_choices(self):
        for fmt in ["json", "txt"]:
            args = self.parser.parse_args(["cert", "--format", fmt])
            assert args.format == fmt


# ---------------------------------------------------------------------------
# 10. TestParseDeobfuscate
# ---------------------------------------------------------------------------
class TestParseDeobfuscate:
    """Test argument parsing for the 'deobfuscate' subcommand."""

    def setup_method(self):
        self.parser = create_parser()

    def test_minimal(self):
        args = self.parser.parse_args(["deobfuscate"])
        assert args.command == "deobfuscate"
        assert args.input_file is None
        assert args.language == "auto"
        assert args.max_layers == 10
        assert args.extract_iocs is False
        assert args.format == "txt"
        assert args.verbose is False
        assert args.decode_base64 is None
        assert args.decode_hex is None
        assert args.decode_url is None

    def test_positional_input(self):
        args = self.parser.parse_args(["deobfuscate", "malware.js"])
        assert args.input_file == "malware.js"

    def test_all_options(self):
        args = self.parser.parse_args(
            [
                "deobfuscate",
                "malware.ps1",
                "--language",
                "powershell",
                "--max-layers",
                "5",
                "--extract-iocs",
                "--format",
                "json",
                "--output",
                "out.json",
                "--verbose",
                "--decode-base64",
                "SGVsbG8=",
                "--decode-hex",
                "48656c6c6f",
                "--decode-url",
                "%48%65%6c%6c%6f",
            ]
        )
        assert args.input_file == "malware.ps1"
        assert args.language == "powershell"
        assert args.max_layers == 5
        assert args.extract_iocs is True
        assert args.format == "json"
        assert args.output == "out.json"
        assert args.verbose is True
        assert args.decode_base64 == "SGVsbG8="
        assert args.decode_hex == "48656c6c6f"
        assert args.decode_url == "%48%65%6c%6c%6f"

    def test_language_choices(self):
        for lang in ["auto", "powershell", "javascript", "vbscript", "batch"]:
            args = self.parser.parse_args(["deobfuscate", "--language", lang])
            assert args.language == lang

    def test_invalid_language(self):
        with pytest.raises(SystemExit):
            self.parser.parse_args(["deobfuscate", "--language", "ruby"])


# ---------------------------------------------------------------------------
# 11. TestMainNoArgs - no args shows help and exits 0
# ---------------------------------------------------------------------------
class TestMainNoArgs:
    """When no arguments are provided, main() should print help and exit(0)."""

    def test_no_args_exits_zero(self):
        with patch.object(sys, "argv", ["vlair"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    def test_no_args_prints_help(self, capsys):
        with patch.object(sys, "argv", ["vlair"]):
            with pytest.raises(SystemExit):
                main()
        captured = capsys.readouterr()
        assert "Security Operations Toolkit" in captured.out
        assert "Available Commands" in captured.out


# ---------------------------------------------------------------------------
# 12. TestMainRouting - verify each command routes to the correct tool
# ---------------------------------------------------------------------------
class TestMainRouting:
    """
    For each subcommand, mock the tool's main() function and verify:
    - The correct tool main() is called
    - sys.argv is reconstructed with the expected values

    We use a side_effect to capture sys.argv at call time, because
    patch.object restores sys.argv when the context manager exits.
    """

    # -- EML routing --

    @patch("vlair.tools.eml_parser.main")
    def test_eml_minimal(self, mock_eml_main):
        captured = {}
        mock_eml_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "eml", "phish.eml"]):
            main()
        mock_eml_main.assert_called_once()
        assert captured["argv"] == ["emlParser.py", "phish.eml"]

    @patch("vlair.tools.eml_parser.main")
    def test_eml_all_options(self, mock_eml_main):
        captured = {}
        mock_eml_main.side_effect = _capture_argv(captured)
        with patch.object(
            sys, "argv", ["vlair", "eml", "phish.eml", "--output", "r.json", "--vt", "--verbose"]
        ):
            main()
        mock_eml_main.assert_called_once()
        assert captured["argv"] == [
            "emlParser.py", "phish.eml", "--output", "r.json", "--vt", "--verbose"
        ]

    @patch("vlair.tools.eml_parser.main")
    def test_eml_short_output(self, mock_eml_main):
        captured = {}
        mock_eml_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "eml", "phish.eml", "-o", "r.json"]):
            main()
        mock_eml_main.assert_called_once()
        assert "--output" in captured["argv"]
        assert "r.json" in captured["argv"]

    # -- IOC routing --

    @patch("vlair.tools.ioc_extractor.main")
    def test_ioc_minimal(self, mock_ioc_main):
        captured = {}
        mock_ioc_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "ioc"]):
            main()
        mock_ioc_main.assert_called_once()
        assert captured["argv"][0] == "extractor.py"
        assert "--format" in captured["argv"]
        assert "json" in captured["argv"]

    @patch("vlair.tools.ioc_extractor.main")
    def test_ioc_all_options(self, mock_ioc_main):
        captured = {}
        mock_ioc_main.side_effect = _capture_argv(captured)
        with patch.object(
            sys,
            "argv",
            [
                "vlair", "ioc", "report.txt",
                "--file", "extra.txt",
                "--output", "iocs.csv",
                "--format", "csv",
                "--types", "ip", "domain",
                "--refang", "--defang", "--exclude-private",
            ],
        ):
            main()
        mock_ioc_main.assert_called_once()
        argv = captured["argv"]
        assert argv[0] == "extractor.py"
        assert "report.txt" in argv
        assert "--file" in argv and "extra.txt" in argv
        assert "--output" in argv and "iocs.csv" in argv
        assert "--format" in argv and "csv" in argv
        assert "--types" in argv
        assert "ip" in argv and "domain" in argv
        assert "--refang" in argv
        assert "--defang" in argv
        assert "--exclude-private" in argv

    @patch("vlair.tools.ioc_extractor.main")
    def test_ioc_with_file_and_refang(self, mock_ioc_main):
        captured = {}
        mock_ioc_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "ioc", "--file", "iocs.txt", "--refang"]):
            main()
        mock_ioc_main.assert_called_once()
        assert "--file" in captured["argv"]
        assert "iocs.txt" in captured["argv"]
        assert "--refang" in captured["argv"]

    # -- Hash routing --

    @patch("vlair.tools.hash_lookup.main")
    def test_hash_minimal(self, mock_hash_main):
        captured = {}
        mock_hash_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "hash"]):
            main()
        mock_hash_main.assert_called_once()
        assert captured["argv"][0] == "lookup.py"

    @patch("vlair.tools.hash_lookup.main")
    def test_hash_all_options(self, mock_hash_main):
        captured = {}
        mock_hash_main.side_effect = _capture_argv(captured)
        with patch.object(
            sys,
            "argv",
            [
                "vlair", "hash", "abc123",
                "--file", "hashes.txt",
                "--output", "out.json",
                "--format", "csv",
                "--no-cache",
                "--rate-limit", "10",
                "--verbose",
            ],
        ):
            main()
        mock_hash_main.assert_called_once()
        argv = captured["argv"]
        assert argv[0] == "lookup.py"
        assert "abc123" in argv
        assert "--file" in argv and "hashes.txt" in argv
        assert "--output" in argv and "out.json" in argv
        assert "--format" in argv and "csv" in argv
        assert "--no-cache" in argv
        assert "--rate-limit" in argv and "10" in argv
        assert "--verbose" in argv

    @patch("vlair.tools.hash_lookup.main")
    def test_hash_rate_limit_default_included(self, mock_hash_main):
        """rate_limit defaults to 4 and is always included when truthy."""
        captured = {}
        mock_hash_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "hash", "abc123"]):
            main()
        mock_hash_main.assert_called_once()
        assert "--rate-limit" in captured["argv"]
        assert "4" in captured["argv"]

    @patch("vlair.tools.hash_lookup.main")
    def test_hash_no_cache(self, mock_hash_main):
        captured = {}
        mock_hash_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "hash", "abc123", "--no-cache"]):
            main()
        assert "--no-cache" in captured["argv"]

    # -- Intel routing --

    @patch("vlair.tools.domain_ip_intel.main")
    def test_intel_minimal(self, mock_intel_main):
        captured = {}
        mock_intel_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "intel"]):
            main()
        mock_intel_main.assert_called_once()
        assert captured["argv"][0] == "intel.py"

    @patch("vlair.tools.domain_ip_intel.main")
    def test_intel_all_options(self, mock_intel_main):
        captured = {}
        mock_intel_main.side_effect = _capture_argv(captured)
        with patch.object(
            sys,
            "argv",
            [
                "vlair", "intel", "evil.com",
                "--file", "domains.txt",
                "--output", "out.json",
                "--format", "csv",
                "--verbose",
            ],
        ):
            main()
        mock_intel_main.assert_called_once()
        argv = captured["argv"]
        assert argv[0] == "intel.py"
        assert "evil.com" in argv
        assert "--file" in argv and "domains.txt" in argv
        assert "--output" in argv and "out.json" in argv
        assert "--format" in argv and "csv" in argv
        assert "--verbose" in argv

    @patch("vlair.tools.domain_ip_intel.main")
    def test_intel_verbose_short(self, mock_intel_main):
        captured = {}
        mock_intel_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "intel", "8.8.8.8", "-v"]):
            main()
        mock_intel_main.assert_called_once()
        assert "--verbose" in captured["argv"]

    # -- Log routing --

    @patch("vlair.tools.log_analyzer.main")
    def test_log_minimal(self, mock_log_main):
        captured = {}
        mock_log_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "log", "access.log"]):
            main()
        mock_log_main.assert_called_once()
        assert captured["argv"][0] == "analyzer.py"
        assert "access.log" in captured["argv"]

    @patch("vlair.tools.log_analyzer.main")
    def test_log_all_options(self, mock_log_main):
        captured = {}
        mock_log_main.side_effect = _capture_argv(captured)
        with patch.object(
            sys,
            "argv",
            [
                "vlair", "log", "access.log",
                "--type", "apache",
                "--output", "out.json",
                "--format", "txt",
                "--verbose",
            ],
        ):
            main()
        mock_log_main.assert_called_once()
        argv = captured["argv"]
        assert argv[0] == "analyzer.py"
        assert "access.log" in argv
        assert "--type" in argv and "apache" in argv
        assert "--output" in argv and "out.json" in argv
        assert "--format" in argv and "txt" in argv
        assert "--verbose" in argv

    @patch("vlair.tools.log_analyzer.main")
    def test_log_type_auto_included(self, mock_log_main):
        """--type defaults to 'auto' and is included when truthy."""
        captured = {}
        mock_log_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "log", "f.log"]):
            main()
        assert "--type" in captured["argv"]
        assert "auto" in captured["argv"]

    # -- PCAP routing --

    @patch("vlair.tools.pcap_analyzer.main")
    def test_pcap_minimal(self, mock_pcap_main):
        captured = {}
        mock_pcap_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "pcap", "capture.pcap"]):
            main()
        mock_pcap_main.assert_called_once()
        assert captured["argv"][0] == "analyzer.py"
        assert "capture.pcap" in captured["argv"]

    @patch("vlair.tools.pcap_analyzer.main")
    def test_pcap_all_options(self, mock_pcap_main):
        captured = {}
        mock_pcap_main.side_effect = _capture_argv(captured)
        with patch.object(
            sys,
            "argv",
            [
                "vlair", "pcap", "capture.pcap",
                "--output", "out.json",
                "--format", "txt",
                "--verbose",
            ],
        ):
            main()
        mock_pcap_main.assert_called_once()
        argv = captured["argv"]
        assert argv[0] == "analyzer.py"
        assert "capture.pcap" in argv
        assert "--output" in argv and "out.json" in argv
        assert "--format" in argv and "txt" in argv
        assert "--verbose" in argv

    @patch("vlair.tools.pcap_analyzer.main")
    def test_pcap_format_and_verbose(self, mock_pcap_main):
        captured = {}
        mock_pcap_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "pcap", "c.pcap", "-f", "csv", "-v"]):
            main()
        mock_pcap_main.assert_called_once()
        assert "--format" in captured["argv"]
        assert "--verbose" in captured["argv"]

    # -- URL routing --

    @patch("vlair.tools.url_analyzer.main")
    def test_url_minimal(self, mock_url_main):
        captured = {}
        mock_url_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "url"]):
            main()
        mock_url_main.assert_called_once()
        assert captured["argv"][0] == "analyzer.py"

    @patch("vlair.tools.url_analyzer.main")
    def test_url_all_options(self, mock_url_main):
        captured = {}
        mock_url_main.side_effect = _capture_argv(captured)
        with patch.object(
            sys,
            "argv",
            [
                "vlair", "url", "http://evil.com",
                "--file", "urls.txt",
                "--output", "out.json",
                "--format", "txt",
                "--no-cache",
                "--verbose",
            ],
        ):
            main()
        mock_url_main.assert_called_once()
        argv = captured["argv"]
        assert argv[0] == "analyzer.py"
        assert "http://evil.com" in argv
        assert "--file" in argv and "urls.txt" in argv
        assert "--output" in argv and "out.json" in argv
        assert "--format" in argv and "txt" in argv
        assert "--no-cache" in argv
        assert "--verbose" in argv

    @patch("vlair.tools.url_analyzer.main")
    def test_url_no_cache(self, mock_url_main):
        captured = {}
        mock_url_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "url", "http://evil.com", "--no-cache"]):
            main()
        assert "--no-cache" in captured["argv"]

    # -- YARA routing --

    @patch("vlair.tools.yara_scanner.main")
    def test_yara_minimal(self, mock_yara_main):
        captured = {}
        mock_yara_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "yara"]):
            main()
        mock_yara_main.assert_called_once()
        assert captured["argv"][0] == "scanner.py"

    @patch("vlair.tools.yara_scanner.main")
    def test_yara_passthrough_args(self, mock_yara_main):
        captured = {}
        mock_yara_main.side_effect = _capture_argv(captured)
        with patch.object(
            sys,
            "argv",
            ["vlair", "yara", "scan", "/samples/", "--rules", "./rules/", "--recursive"],
        ):
            main()
        mock_yara_main.assert_called_once()
        argv = captured["argv"]
        assert argv[0] == "scanner.py"
        assert "scan" in argv
        assert "/samples/" in argv
        assert "--rules" in argv
        assert "./rules/" in argv
        assert "--recursive" in argv

    @patch("vlair.tools.yara_scanner.main")
    def test_yara_single_arg(self, mock_yara_main):
        captured = {}
        mock_yara_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "yara", "validate"]):
            main()
        mock_yara_main.assert_called_once()
        assert "validate" in captured["argv"]

    # -- Cert routing --

    @patch("vlair.tools.cert_analyzer.main")
    def test_cert_minimal(self, mock_cert_main):
        captured = {}
        mock_cert_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "cert"]):
            main()
        mock_cert_main.assert_called_once()
        assert captured["argv"][0] == "analyzer.py"

    @patch("vlair.tools.cert_analyzer.main")
    def test_cert_all_options(self, mock_cert_main):
        captured = {}
        mock_cert_main.side_effect = _capture_argv(captured)
        with patch.object(
            sys,
            "argv",
            [
                "vlair", "cert", "example.com",
                "--file", "cert.pem",
                "--file-list", "domains.txt",
                "--hostname", "example.com",
                "--port", "8443",
                "--ct-search", "example.com",
                "--format", "json",
                "--output", "out.json",
                "--verbose",
            ],
        ):
            main()
        mock_cert_main.assert_called_once()
        argv = captured["argv"]
        assert argv[0] == "analyzer.py"
        assert "example.com" in argv
        assert "--file" in argv and "cert.pem" in argv
        assert "--file-list" in argv and "domains.txt" in argv
        assert "--hostname" in argv
        assert "--port" in argv and "8443" in argv
        assert "--ct-search" in argv
        assert "--format" in argv and "json" in argv
        assert "--output" in argv and "out.json" in argv
        assert "--verbose" in argv

    @patch("vlair.tools.cert_analyzer.main")
    def test_cert_default_port_not_included(self, mock_cert_main):
        """Port 443 (default) should NOT be added to sys.argv."""
        captured = {}
        mock_cert_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "cert", "example.com"]):
            main()
        mock_cert_main.assert_called_once()
        assert "--port" not in captured["argv"]

    @patch("vlair.tools.cert_analyzer.main")
    def test_cert_non_default_port_included(self, mock_cert_main):
        captured = {}
        mock_cert_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "cert", "example.com", "--port", "8443"]):
            main()
        assert "--port" in captured["argv"]
        assert "8443" in captured["argv"]

    # -- Deobfuscate routing --

    @patch("vlair.tools.deobfuscator.main")
    def test_deobfuscate_minimal(self, mock_deobf_main):
        captured = {}
        mock_deobf_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "deobfuscate"]):
            main()
        mock_deobf_main.assert_called_once()
        assert captured["argv"][0] == "deobfuscator.py"

    @patch("vlair.tools.deobfuscator.main")
    def test_deobfuscate_all_options(self, mock_deobf_main):
        captured = {}
        mock_deobf_main.side_effect = _capture_argv(captured)
        with patch.object(
            sys,
            "argv",
            [
                "vlair", "deobfuscate", "malware.ps1",
                "--language", "powershell",
                "--max-layers", "5",
                "--extract-iocs",
                "--format", "json",
                "--output", "out.json",
                "--verbose",
                "--decode-base64", "SGVsbG8=",
                "--decode-hex", "48656c6c6f",
                "--decode-url", "%48%65%6c%6c%6f",
            ],
        ):
            main()
        mock_deobf_main.assert_called_once()
        argv = captured["argv"]
        assert argv[0] == "deobfuscator.py"
        assert "malware.ps1" in argv
        assert "--language" in argv and "powershell" in argv
        assert "--max-layers" in argv and "5" in argv
        assert "--extract-iocs" in argv
        assert "--format" in argv and "json" in argv
        assert "--output" in argv and "out.json" in argv
        assert "--verbose" in argv
        assert "--decode-base64" in argv and "SGVsbG8=" in argv
        assert "--decode-hex" in argv and "48656c6c6f" in argv
        assert "--decode-url" in argv and "%48%65%6c%6c%6f" in argv

    @patch("vlair.tools.deobfuscator.main")
    def test_deobfuscate_default_language_not_included(self, mock_deobf_main):
        """Language 'auto' (default) should NOT be added to reconstructed sys.argv."""
        captured = {}
        mock_deobf_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "deobfuscate", "malware.js"]):
            main()
        mock_deobf_main.assert_called_once()
        assert "--language" not in captured["argv"]

    @patch("vlair.tools.deobfuscator.main")
    def test_deobfuscate_non_default_language_included(self, mock_deobf_main):
        captured = {}
        mock_deobf_main.side_effect = _capture_argv(captured)
        with patch.object(
            sys, "argv", ["vlair", "deobfuscate", "malware.js", "--language", "javascript"]
        ):
            main()
        assert "--language" in captured["argv"]
        assert "javascript" in captured["argv"]

    @patch("vlair.tools.deobfuscator.main")
    def test_deobfuscate_default_max_layers_not_included(self, mock_deobf_main):
        """max_layers=10 (default) should NOT be added to reconstructed sys.argv."""
        captured = {}
        mock_deobf_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "deobfuscate", "malware.js"]):
            main()
        mock_deobf_main.assert_called_once()
        assert "--max-layers" not in captured["argv"]

    @patch("vlair.tools.deobfuscator.main")
    def test_deobfuscate_non_default_max_layers_included(self, mock_deobf_main):
        captured = {}
        mock_deobf_main.side_effect = _capture_argv(captured)
        with patch.object(
            sys, "argv", ["vlair", "deobfuscate", "malware.js", "--max-layers", "3"]
        ):
            main()
        assert "--max-layers" in captured["argv"]
        assert "3" in captured["argv"]

    @patch("vlair.tools.deobfuscator.main")
    def test_deobfuscate_decode_options(self, mock_deobf_main):
        captured = {}
        mock_deobf_main.side_effect = _capture_argv(captured)
        with patch.object(
            sys,
            "argv",
            ["vlair", "deobfuscate", "--decode-base64", "dGVzdA=="],
        ):
            main()
        mock_deobf_main.assert_called_once()
        assert "--decode-base64" in captured["argv"]
        assert "dGVzdA==" in captured["argv"]


# ---------------------------------------------------------------------------
# 13. TestUnknownCommand - unknown command shows help
# ---------------------------------------------------------------------------
class TestUnknownCommand:
    """When an unrecognized command is provided, main() should print help and exit(1)."""

    def test_unknown_command_exits_nonzero(self):
        """
        parse_known_args with an unknown command results in args.command being None
        (since it is not a registered subparser), which hits the else branch -> exit(1).
        """
        with patch.object(sys, "argv", ["vlair", "doesnotexist"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code != 0


# ---------------------------------------------------------------------------
# Additional edge case tests
# ---------------------------------------------------------------------------
class TestMainEdgeCases:
    """Edge cases and additional coverage for main()."""

    @patch("vlair.tools.eml_parser.main")
    def test_remaining_args_forwarded_eml(self, mock_eml_main):
        """Unknown extra arguments should be forwarded via 'remaining'."""
        captured = {}
        mock_eml_main.side_effect = _capture_argv(captured)
        with patch.object(
            sys, "argv", ["vlair", "eml", "email.eml", "--custom-flag", "value"]
        ):
            main()
        mock_eml_main.assert_called_once()
        assert "--custom-flag" in captured["argv"]
        assert "value" in captured["argv"]

    @patch("vlair.tools.ioc_extractor.main")
    def test_remaining_args_forwarded_ioc(self, mock_ioc_main):
        captured = {}
        mock_ioc_main.side_effect = _capture_argv(captured)
        with patch.object(
            sys, "argv", ["vlair", "ioc", "report.txt", "--extra", "stuff"]
        ):
            main()
        mock_ioc_main.assert_called_once()
        assert "--extra" in captured["argv"]
        assert "stuff" in captured["argv"]

    @patch("vlair.tools.hash_lookup.main")
    def test_remaining_args_forwarded_hash(self, mock_hash_main):
        captured = {}
        mock_hash_main.side_effect = _capture_argv(captured)
        with patch.object(
            sys, "argv", ["vlair", "hash", "abc", "--unknown-flag"]
        ):
            main()
        mock_hash_main.assert_called_once()
        assert "--unknown-flag" in captured["argv"]

    @patch("vlair.tools.yara_scanner.main")
    def test_yara_empty_args(self, mock_yara_main):
        """YARA with no extra args should just have scanner.py."""
        captured = {}
        mock_yara_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "yara"]):
            main()
        mock_yara_main.assert_called_once()
        assert captured["argv"] == ["scanner.py"]

    @patch("vlair.tools.pcap_analyzer.main")
    def test_remaining_args_forwarded_pcap(self, mock_pcap_main):
        captured = {}
        mock_pcap_main.side_effect = _capture_argv(captured)
        with patch.object(
            sys, "argv", ["vlair", "pcap", "c.pcap", "--extra-flag"]
        ):
            main()
        mock_pcap_main.assert_called_once()
        assert "--extra-flag" in captured["argv"]

    @patch("vlair.tools.url_analyzer.main")
    def test_url_only_file(self, mock_url_main):
        captured = {}
        mock_url_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "url", "--file", "urls.txt"]):
            main()
        mock_url_main.assert_called_once()
        assert "--file" in captured["argv"]
        assert "urls.txt" in captured["argv"]
        assert captured["argv"][0] == "analyzer.py"

    @patch("vlair.tools.cert_analyzer.main")
    def test_cert_ct_search_only(self, mock_cert_main):
        captured = {}
        mock_cert_main.side_effect = _capture_argv(captured)
        with patch.object(sys, "argv", ["vlair", "cert", "--ct-search", "example.com"]):
            main()
        mock_cert_main.assert_called_once()
        assert "--ct-search" in captured["argv"]
        assert "example.com" in captured["argv"]


# ---------------------------------------------------------------------------
# Exact sys.argv reconstruction tests (strict ordering)
# ---------------------------------------------------------------------------
class TestSysArgvReconstruction:
    """Verify the exact sys.argv list produced for each tool (strict ordering checks)."""

    @patch("vlair.tools.eml_parser.main")
    def test_eml_exact_argv(self, mock_eml_main):
        captured = {}
        mock_eml_main.side_effect = _capture_argv(captured)
        with patch.object(
            sys, "argv", ["vlair", "eml", "test.eml", "--output", "r.json", "--vt", "--verbose"]
        ):
            main()
        assert captured["argv"] == [
            "emlParser.py", "test.eml", "--output", "r.json", "--vt", "--verbose",
        ]

    @patch("vlair.tools.log_analyzer.main")
    def test_log_exact_argv(self, mock_log_main):
        captured = {}
        mock_log_main.side_effect = _capture_argv(captured)
        with patch.object(
            sys,
            "argv",
            ["vlair", "log", "access.log", "--type", "apache", "--output", "o.json", "--format", "txt", "--verbose"],
        ):
            main()
        assert captured["argv"] == [
            "analyzer.py", "access.log",
            "--type", "apache",
            "--output", "o.json",
            "--format", "txt",
            "--verbose",
        ]

    @patch("vlair.tools.pcap_analyzer.main")
    def test_pcap_exact_argv(self, mock_pcap_main):
        captured = {}
        mock_pcap_main.side_effect = _capture_argv(captured)
        with patch.object(
            sys,
            "argv",
            ["vlair", "pcap", "capture.pcap", "--output", "o.json", "--format", "txt", "--verbose"],
        ):
            main()
        assert captured["argv"] == [
            "analyzer.py", "capture.pcap",
            "--output", "o.json",
            "--format", "txt",
            "--verbose",
        ]

    @patch("vlair.tools.yara_scanner.main")
    def test_yara_exact_argv(self, mock_yara_main):
        captured = {}
        mock_yara_main.side_effect = _capture_argv(captured)
        with patch.object(
            sys, "argv", ["vlair", "yara", "scan", "/samples/", "--rules", "r/", "--recursive"]
        ):
            main()
        assert captured["argv"] == [
            "scanner.py", "scan", "/samples/", "--rules", "r/", "--recursive",
        ]

    @patch("vlair.tools.domain_ip_intel.main")
    def test_intel_exact_argv(self, mock_intel_main):
        captured = {}
        mock_intel_main.side_effect = _capture_argv(captured)
        with patch.object(
            sys,
            "argv",
            ["vlair", "intel", "evil.com", "--file", "d.txt", "--output", "o.json", "--format", "csv", "--verbose"],
        ):
            main()
        assert captured["argv"] == [
            "intel.py", "evil.com",
            "--file", "d.txt",
            "--output", "o.json",
            "--format", "csv",
            "--verbose",
        ]
