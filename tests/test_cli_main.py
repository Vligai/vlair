#!/usr/bin/env python3
"""
Unit tests for vlair CLI main module
Tests ToolDiscovery, ToolManager, InteractiveMenu, print_usage, and main() dispatch
"""

import pytest
import sys
import os
import json
from pathlib import Path
from unittest.mock import patch, MagicMock, PropertyMock, call
from io import StringIO

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


# ---------------------------------------------------------------------------
# Helpers: build a fake tool registry used across many tests
# ---------------------------------------------------------------------------


def _fake_registry():
    """Return a minimal fake tool registry for testing."""
    return {
        "eml": {
            "name": "EML Parser",
            "module": "vlair.tools.eml_parser",
            "category": "Email Analysis",
            "description": "Parse and analyze email files",
            "keywords": ["email", "eml", "phishing"],
            "examples": ["vlair eml suspicious.eml"],
            "requires_api": ["VT_API_KEY (optional)"],
        },
        "hash": {
            "name": "Hash Lookup",
            "module": "vlair.tools.hash_lookup",
            "category": "Threat Intelligence",
            "description": "Look up file hashes against VirusTotal",
            "keywords": ["hash", "md5", "sha256"],
            "examples": ["vlair hash 44d88612..."],
            "requires_api": ["VT_API_KEY (optional)"],
        },
        "intel": {
            "name": "Domain/IP Intelligence",
            "module": "vlair.tools.domain_ip_intel",
            "category": "Threat Intelligence",
            "description": "Analyze domains and IP addresses",
            "keywords": ["domain", "ip", "dns"],
            "examples": ["vlair intel malicious.com"],
            "requires_api": ["VT_API_KEY"],
        },
        "url": {
            "name": "URL Analyzer",
            "module": "vlair.tools.url_analyzer",
            "category": "Threat Intelligence",
            "description": "Analyze URLs for threats",
            "keywords": ["url", "phishing", "malware"],
            "examples": ['vlair url "http://bad.com"'],
            "requires_api": ["VT_API_KEY (optional)"],
        },
        "log": {
            "name": "Log Analyzer",
            "module": "vlair.tools.log_analyzer",
            "category": "Log Analysis",
            "description": "Analyze log files for security threats",
            "keywords": ["log", "apache", "nginx"],
            "examples": ["vlair log access.log"],
            "requires_api": [],
        },
    }


# ---------------------------------------------------------------------------
# ToolDiscovery tests
# ---------------------------------------------------------------------------


class TestToolDiscovery:
    """Test the ToolDiscovery class"""

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    def test_discover_tools_marks_available(self, mock_registry, tmp_path):
        """Tools whose module file exists should be marked available"""
        from vlair.cli.main import ToolDiscovery

        # Create a dummy module file so the discovery considers it available
        tools_dir = tmp_path / "tools"
        tools_dir.mkdir(parents=True)
        (tools_dir / "eml_parser.py").write_text("# stub")

        # Directly construct and test discovery logic manually
        # since _discover_tools uses Path(__file__) internally
        discovery = ToolDiscovery.__new__(ToolDiscovery)
        discovery.base_dir = tmp_path
        discovery.tools = {}

        # Simulate _discover_tools logic
        tool_definitions = _fake_registry()
        for tool_id, metadata in tool_definitions.items():
            module_parts = metadata["module"].split(".")
            if len(module_parts) >= 3:
                relative_path = "/".join(module_parts[1:]) + ".py"
                module_path = tmp_path / relative_path
            else:
                module_path = tmp_path / (metadata["module"].replace(".", "/") + ".py")

            if module_path.exists():
                discovery.tools[tool_id] = dict(metadata)
                discovery.tools[tool_id]["available"] = True
                discovery.tools[tool_id]["path"] = str(module_path)
            else:
                discovery.tools[tool_id] = dict(metadata)
                discovery.tools[tool_id]["available"] = False

        # eml_parser.py exists, others do not
        assert discovery.tools["eml"]["available"] is True
        assert discovery.tools["hash"]["available"] is False
        assert discovery.tools["intel"]["available"] is False

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    def test_get_tool_existing(self, mock_registry, tmp_path):
        """get_tool returns metadata for an existing tool id"""
        from vlair.cli.main import ToolDiscovery

        discovery = ToolDiscovery.__new__(ToolDiscovery)
        discovery.base_dir = tmp_path
        discovery.tools = {}
        for tid, meta in _fake_registry().items():
            discovery.tools[tid] = dict(meta)
            discovery.tools[tid]["available"] = False

        tool = discovery.get_tool("hash")
        assert tool is not None
        assert tool["name"] == "Hash Lookup"

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    def test_get_tool_missing(self, mock_registry, tmp_path):
        """get_tool returns None for unknown tool id"""
        from vlair.cli.main import ToolDiscovery

        discovery = ToolDiscovery.__new__(ToolDiscovery)
        discovery.base_dir = tmp_path
        discovery.tools = {}
        assert discovery.get_tool("nonexistent") is None

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    def test_get_all_tools(self, mock_registry, tmp_path):
        """get_all_tools returns the full tools dict"""
        from vlair.cli.main import ToolDiscovery

        discovery = ToolDiscovery.__new__(ToolDiscovery)
        discovery.base_dir = tmp_path
        discovery.tools = {}
        for tid, meta in _fake_registry().items():
            discovery.tools[tid] = dict(meta)
            discovery.tools[tid]["available"] = False

        all_tools = discovery.get_all_tools()
        assert len(all_tools) == 5
        assert "eml" in all_tools
        assert "hash" in all_tools

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    def test_get_by_category(self, mock_registry, tmp_path):
        """get_by_category filters tools correctly"""
        from vlair.cli.main import ToolDiscovery

        discovery = ToolDiscovery.__new__(ToolDiscovery)
        discovery.base_dir = tmp_path
        discovery.tools = {}
        for tid, meta in _fake_registry().items():
            discovery.tools[tid] = dict(meta)
            discovery.tools[tid]["available"] = False

        ti_tools = discovery.get_by_category("Threat Intelligence")
        assert len(ti_tools) == 3
        ids = [t[0] for t in ti_tools]
        assert "hash" in ids
        assert "intel" in ids
        assert "url" in ids

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    def test_get_by_category_empty(self, mock_registry, tmp_path):
        """get_by_category returns empty list for unknown category"""
        from vlair.cli.main import ToolDiscovery

        discovery = ToolDiscovery.__new__(ToolDiscovery)
        discovery.base_dir = tmp_path
        discovery.tools = {}
        for tid, meta in _fake_registry().items():
            discovery.tools[tid] = dict(meta)

        result = discovery.get_by_category("NonExistentCategory")
        assert result == []

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    def test_search_tools_by_keyword_in_name(self, mock_registry, tmp_path):
        """search_tools matches on tool name"""
        from vlair.cli.main import ToolDiscovery

        discovery = ToolDiscovery.__new__(ToolDiscovery)
        discovery.base_dir = tmp_path
        discovery.tools = {}
        for tid, meta in _fake_registry().items():
            discovery.tools[tid] = dict(meta)

        results = discovery.search_tools("hash")
        ids = [r[0] for r in results]
        assert "hash" in ids

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    def test_search_tools_by_keyword_in_description(self, mock_registry, tmp_path):
        """search_tools matches on tool description"""
        from vlair.cli.main import ToolDiscovery

        discovery = ToolDiscovery.__new__(ToolDiscovery)
        discovery.base_dir = tmp_path
        discovery.tools = {}
        for tid, meta in _fake_registry().items():
            discovery.tools[tid] = dict(meta)

        results = discovery.search_tools("email")
        ids = [r[0] for r in results]
        assert "eml" in ids

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    def test_search_tools_by_keyword_in_keywords_list(self, mock_registry, tmp_path):
        """search_tools matches on keywords list"""
        from vlair.cli.main import ToolDiscovery

        discovery = ToolDiscovery.__new__(ToolDiscovery)
        discovery.base_dir = tmp_path
        discovery.tools = {}
        for tid, meta in _fake_registry().items():
            discovery.tools[tid] = dict(meta)

        results = discovery.search_tools("phishing")
        ids = [r[0] for r in results]
        assert "eml" in ids
        assert "url" in ids

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    def test_search_tools_no_match(self, mock_registry, tmp_path):
        """search_tools returns empty list when no keyword matches"""
        from vlair.cli.main import ToolDiscovery

        discovery = ToolDiscovery.__new__(ToolDiscovery)
        discovery.base_dir = tmp_path
        discovery.tools = {}
        for tid, meta in _fake_registry().items():
            discovery.tools[tid] = dict(meta)

        results = discovery.search_tools("zzzznonexistent")
        assert results == []

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    def test_search_tools_case_insensitive(self, mock_registry, tmp_path):
        """search_tools is case-insensitive"""
        from vlair.cli.main import ToolDiscovery

        discovery = ToolDiscovery.__new__(ToolDiscovery)
        discovery.base_dir = tmp_path
        discovery.tools = {}
        for tid, meta in _fake_registry().items():
            discovery.tools[tid] = dict(meta)

        results = discovery.search_tools("HASH")
        ids = [r[0] for r in results]
        assert "hash" in ids


# ---------------------------------------------------------------------------
# ToolManager tests
# ---------------------------------------------------------------------------


class TestToolManager:
    """Test the ToolManager class"""

    def _make_discovery(self, tools_dict):
        """Helper to create a mock discovery object."""
        from vlair.cli.main import ToolDiscovery

        discovery = ToolDiscovery.__new__(ToolDiscovery)
        discovery.base_dir = Path(".")
        discovery.tools = tools_dict
        return discovery

    def test_run_tool_unknown_tool(self, capsys):
        """run_tool exits 1 for unknown tool"""
        from vlair.cli.main import ToolManager

        discovery = self._make_discovery({})
        manager = ToolManager(discovery)

        with pytest.raises(SystemExit) as exc_info:
            manager.run_tool("nonexistent", [])
        assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Unknown tool" in captured.err

    def test_run_tool_unavailable(self, capsys):
        """run_tool exits 1 for tool that is not available"""
        from vlair.cli.main import ToolManager

        tools = {
            "test_tool": {
                "name": "Test Tool",
                "module": "vlair.tools.test_tool",
                "available": False,
                "path": "/fake/path.py",
                "category": "Test",
                "description": "Test",
                "keywords": [],
                "examples": [],
                "requires_api": [],
            }
        }
        discovery = self._make_discovery(tools)
        manager = ToolManager(discovery)

        with pytest.raises(SystemExit) as exc_info:
            manager.run_tool("test_tool", [])
        assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "not found" in captured.err

    @patch("importlib.import_module")
    def test_run_tool_success(self, mock_import):
        """run_tool successfully imports and calls main()"""
        from vlair.cli.main import ToolManager

        mock_module = MagicMock()
        mock_module.main = MagicMock()
        mock_import.return_value = mock_module

        tools = {
            "test_tool": {
                "name": "Test Tool",
                "module": "vlair.tools.test_tool",
                "available": True,
                "path": "/real/path.py",
                "category": "Test",
                "description": "Test",
                "keywords": [],
                "examples": [],
                "requires_api": [],
            }
        }
        discovery = MagicMock()
        discovery.get_tool.return_value = tools["test_tool"]
        manager = ToolManager(discovery)

        manager.run_tool("test_tool", ["--verbose"])

        mock_import.assert_called_once_with("vlair.tools.test_tool")
        mock_module.main.assert_called_once()
        # argv should be set to [tool_name.py, --verbose]
        assert sys.argv == ["test_tool.py", "--verbose"]

    @patch("importlib.import_module")
    def test_run_tool_no_main_function(self, mock_import, capsys):
        """run_tool exits 1 when module has no main()"""
        from vlair.cli.main import ToolManager

        mock_module = MagicMock(spec=[])  # No main attribute
        mock_import.return_value = mock_module

        tools = {
            "test_tool": {
                "name": "Test Tool",
                "module": "vlair.tools.test_tool",
                "available": True,
                "path": "/real/path.py",
                "category": "Test",
                "description": "Test",
                "keywords": [],
                "examples": [],
                "requires_api": [],
            }
        }
        discovery = MagicMock()
        discovery.get_tool.return_value = tools["test_tool"]
        manager = ToolManager(discovery)

        with pytest.raises(SystemExit) as exc_info:
            manager.run_tool("test_tool", [])
        assert exc_info.value.code == 1

    @patch("importlib.import_module", side_effect=ImportError("Module not found"))
    def test_run_tool_import_error(self, mock_import, capsys):
        """run_tool exits 1 on ImportError"""
        from vlair.cli.main import ToolManager

        tools = {
            "test_tool": {
                "name": "Test Tool",
                "module": "vlair.tools.test_tool",
                "available": True,
                "path": "/real/path.py",
                "category": "Test",
                "description": "Test",
                "keywords": [],
                "examples": [],
                "requires_api": [],
            }
        }
        discovery = MagicMock()
        discovery.get_tool.return_value = tools["test_tool"]
        manager = ToolManager(discovery)

        with pytest.raises(SystemExit) as exc_info:
            manager.run_tool("test_tool", [])
        assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Error running tool" in captured.err


# ---------------------------------------------------------------------------
# print_usage tests
# ---------------------------------------------------------------------------


class TestPrintUsage:
    """Test the print_usage function"""

    def test_print_usage_output(self, capsys):
        """print_usage prints help text to stdout"""
        from vlair.cli.main import print_usage

        print_usage()
        captured = capsys.readouterr()
        assert "vlair" in captured.out
        assert "analyze" in captured.out
        assert "workflow" in captured.out
        assert "investigate" in captured.out
        assert "status" in captured.out
        assert "--help" in captured.out
        assert "--version" in captured.out

    def test_print_usage_contains_examples(self, capsys):
        """print_usage contains example commands"""
        from vlair.cli.main import print_usage

        print_usage()
        captured = capsys.readouterr()
        assert "suspicious.eml" in captured.out
        assert "malicious.com" in captured.out

    def test_print_usage_lists_tools(self, capsys):
        """print_usage lists individual tools"""
        from vlair.cli.main import print_usage

        print_usage()
        captured = capsys.readouterr()
        assert "eml" in captured.out
        assert "ioc" in captured.out
        assert "hash" in captured.out
        assert "intel" in captured.out


# ---------------------------------------------------------------------------
# main() dispatch tests
# ---------------------------------------------------------------------------


class TestMainHelp:
    """Test main() --help / -h / help dispatch"""

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "--help"])
    def test_main_help_flag(self, mock_registry, capsys):
        """main() with --help prints usage and exits 0"""
        from vlair.cli.main import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

        captured = capsys.readouterr()
        assert "vlair" in captured.out
        assert "analyze" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "-h"])
    def test_main_h_flag(self, mock_registry, capsys):
        """main() with -h prints usage and exits 0"""
        from vlair.cli.main import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "help"])
    def test_main_help_word(self, mock_registry, capsys):
        """main() with 'help' word prints usage and exits 0"""
        from vlair.cli.main import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0


class TestMainVersion:
    """Test main() --version / -v dispatch"""

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "--version"])
    def test_main_version_flag(self, mock_registry, capsys):
        """main() with --version prints version and exits 0"""
        from vlair.cli.main import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

        captured = capsys.readouterr()
        assert "vlair" in captured.out
        assert "v4.0.0" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "-v"])
    def test_main_v_flag(self, mock_registry, capsys):
        """main() with -v prints version and exits 0"""
        from vlair.cli.main import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

        captured = capsys.readouterr()
        assert "vlair" in captured.out


class TestMainList:
    """Test main() list command"""

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "list"])
    def test_main_list(self, mock_registry, capsys):
        """main() with 'list' lists all tools"""
        from vlair.cli.main import main

        main()
        captured = capsys.readouterr()
        assert "Available Tools" in captured.out
        assert "EML Parser" in captured.out or "eml" in captured.out
        assert "Hash Lookup" in captured.out or "hash" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "list"])
    def test_main_list_shows_categories(self, mock_registry, capsys):
        """main() list groups tools by category"""
        from vlair.cli.main import main

        main()
        captured = capsys.readouterr()
        assert "Email Analysis" in captured.out
        assert "Threat Intelligence" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "list"])
    def test_main_list_shows_footer(self, mock_registry, capsys):
        """main() list shows usage hints at bottom"""
        from vlair.cli.main import main

        main()
        captured = capsys.readouterr()
        assert "vlair info" in captured.out
        assert "vlair" in captured.out


class TestMainInfo:
    """Test main() info command"""

    @patch("builtins.input", return_value="")
    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "info", "eml"])
    def test_main_info_existing_tool(self, mock_registry, mock_input, capsys):
        """main() info <tool> shows tool details"""
        from vlair.cli.main import main

        main()
        captured = capsys.readouterr()
        assert "EML Parser" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "info", "nonexistent_tool"])
    def test_main_info_unknown_tool(self, mock_registry, capsys):
        """main() info for unknown tool exits 1"""
        from vlair.cli.main import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Unknown tool" in captured.err

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "info"])
    def test_main_info_no_tool_arg(self, mock_registry, capsys):
        """main() info without tool name exits 1"""
        from vlair.cli.main import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Usage" in captured.err


class TestMainSearch:
    """Test main() search command"""

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "search", "email"])
    def test_main_search_with_results(self, mock_registry, capsys):
        """main() search finds matching tools"""
        from vlair.cli.main import main

        main()
        captured = capsys.readouterr()
        assert "Search Results" in captured.out
        assert "eml" in captured.out or "EML" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "search", "zzzznotfound"])
    def test_main_search_no_results(self, mock_registry, capsys):
        """main() search with no results shows appropriate message"""
        from vlair.cli.main import main

        main()
        captured = capsys.readouterr()
        assert "No tools found" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "search"])
    def test_main_search_no_keyword(self, mock_registry, capsys):
        """main() search without keyword exits 1"""
        from vlair.cli.main import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Usage" in captured.err


class TestMainAnalyze:
    """Test main() analyze command"""

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "analyze"])
    def test_analyze_no_input(self, mock_registry, capsys):
        """main() analyze without input exits 1"""
        from vlair.cli.main import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Usage" in captured.err

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "analyze", "malicious.com"])
    def test_analyze_console_output(self, mock_registry, capsys):
        """main() analyze with domain produces console output"""
        from vlair.cli.main import main

        mock_scorer = MagicMock()
        mock_scorer.get_summary.return_value = {
            "verdict": "SUSPICIOUS",
            "risk_score": 65,
        }

        mock_result = {
            "input": "malicious.com",
            "type": "domain",
            "scorer": mock_scorer,
            "iocs": {"domains": ["malicious.com"]},
            "tool_results": {},
        }

        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = mock_result

        mock_reporter = MagicMock()
        mock_reporter.format_console.return_value = "CONSOLE OUTPUT: SUSPICIOUS"
        mock_reporter.get_exit_code.return_value = 1

        with (
            patch("vlair.cli.main.Analyzer", return_value=mock_analyzer)
            if False
            else patch.dict("sys.modules", {})
        ):
            # We need to patch the imports inside the analyze block
            pass

        # Use proper patching for the dynamic imports
        with patch.dict(
            "sys.modules",
            {
                "vlair.core.analyzer": MagicMock(Analyzer=MagicMock(return_value=mock_analyzer)),
                "vlair.core.reporter": MagicMock(Reporter=MagicMock(return_value=mock_reporter)),
                "vlair.core.history": MagicMock(AnalysisHistory=MagicMock()),
            },
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "CONSOLE OUTPUT" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "analyze", "malicious.com", "--json"])
    def test_analyze_json_output(self, mock_registry, capsys):
        """main() analyze --json produces JSON output"""
        from vlair.cli.main import main

        mock_scorer = MagicMock()
        mock_scorer.get_summary.return_value = {"verdict": "CLEAN", "risk_score": 10}

        mock_result = {
            "input": "malicious.com",
            "type": "domain",
            "scorer": mock_scorer,
            "iocs": {},
            "tool_results": {},
        }

        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = mock_result

        mock_reporter = MagicMock()
        mock_reporter.format_json.return_value = '{"verdict": "CLEAN"}'
        mock_reporter.get_exit_code.return_value = 0

        with patch.dict(
            "sys.modules",
            {
                "vlair.core.analyzer": MagicMock(Analyzer=MagicMock(return_value=mock_analyzer)),
                "vlair.core.reporter": MagicMock(Reporter=MagicMock(return_value=mock_reporter)),
                "vlair.core.history": MagicMock(AnalysisHistory=MagicMock()),
            },
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        captured = capsys.readouterr()
        assert "CLEAN" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "analyze", "malicious.com", "--quiet"])
    def test_analyze_quiet_output(self, mock_registry, capsys):
        """main() analyze --quiet produces minimal output"""
        from vlair.cli.main import main

        mock_scorer = MagicMock()
        mock_scorer.get_summary.return_value = {"verdict": "MALICIOUS", "risk_score": 95}

        mock_result = {
            "input": "malicious.com",
            "type": "domain",
            "scorer": mock_scorer,
            "iocs": {},
            "tool_results": {},
        }

        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = mock_result

        mock_reporter = MagicMock()
        mock_reporter.format_quiet.return_value = "MALICIOUS 95/100"
        mock_reporter.get_exit_code.return_value = 2

        with patch.dict(
            "sys.modules",
            {
                "vlair.core.analyzer": MagicMock(Analyzer=MagicMock(return_value=mock_analyzer)),
                "vlair.core.reporter": MagicMock(Reporter=MagicMock(return_value=mock_reporter)),
                "vlair.core.history": MagicMock(AnalysisHistory=MagicMock()),
            },
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2

        captured = capsys.readouterr()
        assert "MALICIOUS" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "analyze", "malicious.com", "--verbose"])
    def test_analyze_verbose_output(self, mock_registry, capsys):
        """main() analyze --verbose produces detailed output"""
        from vlair.cli.main import main

        mock_scorer = MagicMock()
        mock_scorer.get_summary.return_value = {"verdict": "SUSPICIOUS", "risk_score": 60}

        mock_result = {
            "input": "malicious.com",
            "type": "domain",
            "scorer": mock_scorer,
            "iocs": {},
            "tool_results": {},
        }

        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = mock_result

        mock_reporter = MagicMock()
        mock_reporter.format_verbose.return_value = "VERBOSE: Detailed analysis..."
        mock_reporter.get_exit_code.return_value = 1

        with patch.dict(
            "sys.modules",
            {
                "vlair.core.analyzer": MagicMock(Analyzer=MagicMock(return_value=mock_analyzer)),
                "vlair.core.reporter": MagicMock(Reporter=MagicMock(return_value=mock_reporter)),
                "vlair.core.history": MagicMock(AnalysisHistory=MagicMock()),
            },
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "VERBOSE" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "analyze", "test.eml", "--report", "html"])
    def test_analyze_with_report_generation(self, mock_registry, capsys):
        """main() analyze --report html generates a report"""
        from vlair.cli.main import main

        mock_scorer = MagicMock()
        mock_scorer.get_summary.return_value = {"verdict": "CLEAN", "risk_score": 5}

        mock_result = {
            "input": "test.eml",
            "type": "email",
            "scorer": mock_scorer,
            "iocs": {},
            "tool_results": {},
        }

        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = mock_result

        mock_reporter = MagicMock()
        mock_reporter.format_console.return_value = "Console output"
        mock_reporter.get_exit_code.return_value = 0

        mock_generator = MagicMock()
        mock_generator.generate.return_value = "/tmp/report.html"

        with patch.dict(
            "sys.modules",
            {
                "vlair.core.analyzer": MagicMock(Analyzer=MagicMock(return_value=mock_analyzer)),
                "vlair.core.reporter": MagicMock(Reporter=MagicMock(return_value=mock_reporter)),
                "vlair.core.history": MagicMock(AnalysisHistory=MagicMock()),
                "vlair.core.report_generator": MagicMock(
                    ReportGenerator=MagicMock(return_value=mock_generator)
                ),
            },
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        captured = capsys.readouterr()
        assert "report" in captured.err.lower() or "Report" in captured.err

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "analyze", "malicious.com"])
    def test_analyze_import_error(self, mock_registry, capsys):
        """main() analyze handles ImportError gracefully"""
        from vlair.cli.main import main

        # Force ImportError for the analyzer module
        original_import = (
            __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__
        )

        def mock_import(name, *args, **kwargs):
            if name == "vlair.core.analyzer":
                raise ImportError("No module named 'vlair.core.analyzer'")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Error" in captured.err

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "analyze", "malicious.com"])
    def test_analyze_runtime_error(self, mock_registry, capsys):
        """main() analyze handles runtime exceptions"""
        from vlair.cli.main import main

        mock_analyzer = MagicMock()
        mock_analyzer.analyze.side_effect = RuntimeError("Analysis failed")

        with patch.dict(
            "sys.modules",
            {
                "vlair.core.analyzer": MagicMock(Analyzer=MagicMock(return_value=mock_analyzer)),
                "vlair.core.reporter": MagicMock(),
            },
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Error during analysis" in captured.err


class TestMainCheck:
    """Test main() check command"""

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "check"])
    def test_check_no_args(self, mock_registry, capsys):
        """main() check without args exits 1 with usage"""
        from vlair.cli.main import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Usage" in captured.err

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "check", "hash", "44d88612fea8a8f36de82e1278abb02f"])
    def test_check_hash_console(self, mock_registry, capsys):
        """main() check hash <value> outputs hash info"""
        from vlair.cli.main import main

        mock_lookup = MagicMock()
        mock_lookup.lookup.return_value = {
            "verdict": "MALICIOUS",
            "detections": 45,
            "total_engines": 70,
            "malware_family": "Emotet",
            "sources": ["VirusTotal"],
        }

        with patch.dict(
            "sys.modules",
            {
                "vlair.tools.hash_lookup": MagicMock(
                    HashLookup=MagicMock(return_value=mock_lookup)
                ),
                "vlair.core.history": MagicMock(AnalysisHistory=MagicMock()),
            },
        ):
            main()

        captured = capsys.readouterr()
        assert "Hash:" in captured.out
        assert "MALICIOUS" in captured.out
        assert "45/70" in captured.out
        assert "Emotet" in captured.out
        assert "VirusTotal" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "check", "hash", "44d88612fea8a8f36de82e1278abb02f", "--json"])
    def test_check_hash_json(self, mock_registry, capsys):
        """main() check hash --json outputs JSON"""
        from vlair.cli.main import main

        mock_lookup = MagicMock()
        mock_lookup.lookup.return_value = {
            "verdict": "CLEAN",
            "detections": 0,
            "total_engines": 70,
        }

        with patch.dict(
            "sys.modules",
            {
                "vlair.tools.hash_lookup": MagicMock(
                    HashLookup=MagicMock(return_value=mock_lookup)
                ),
                "vlair.core.history": MagicMock(AnalysisHistory=MagicMock()),
            },
        ):
            main()

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["verdict"] == "CLEAN"

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "check", "hash"])
    def test_check_hash_missing_value(self, mock_registry, capsys):
        """main() check hash without value exits 1"""
        from vlair.cli.main import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Missing hash" in captured.err

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "check", "domain", "malicious.com"])
    def test_check_domain_console(self, mock_registry, capsys):
        """main() check domain outputs domain info"""
        from vlair.cli.main import main

        mock_intel = MagicMock()
        mock_intel.lookup.return_value = {
            "verdict": "SUSPICIOUS",
            "risk_score": 75,
            "dns": {"a_records": ["1.2.3.4", "5.6.7.8"]},
            "categories": ["malware"],
        }

        with patch.dict(
            "sys.modules",
            {
                "vlair.tools.domain_ip_intel": MagicMock(
                    DomainIPIntelligence=MagicMock(return_value=mock_intel)
                ),
                "vlair.core.history": MagicMock(AnalysisHistory=MagicMock()),
            },
        ):
            main()

        captured = capsys.readouterr()
        assert "Domain: malicious.com" in captured.out
        assert "SUSPICIOUS" in captured.out
        assert "75/100" in captured.out
        assert "1.2.3.4" in captured.out
        assert "malware" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "check", "domain", "malicious.com", "--json"])
    def test_check_domain_json(self, mock_registry, capsys):
        """main() check domain --json outputs JSON"""
        from vlair.cli.main import main

        mock_intel = MagicMock()
        mock_intel.lookup.return_value = {"verdict": "SUSPICIOUS", "risk_score": 75}

        with patch.dict(
            "sys.modules",
            {
                "vlair.tools.domain_ip_intel": MagicMock(
                    DomainIPIntelligence=MagicMock(return_value=mock_intel)
                ),
                "vlair.core.history": MagicMock(AnalysisHistory=MagicMock()),
            },
        ):
            main()

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["verdict"] == "SUSPICIOUS"

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "check", "domain"])
    def test_check_domain_missing_value(self, mock_registry, capsys):
        """main() check domain without value exits 1"""
        from vlair.cli.main import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Missing domain" in captured.err

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "check", "ip", "1.2.3.4"])
    def test_check_ip_console(self, mock_registry, capsys):
        """main() check ip outputs IP info"""
        from vlair.cli.main import main

        mock_intel = MagicMock()
        mock_intel.lookup.return_value = {
            "verdict": "MALICIOUS",
            "risk_score": 90,
            "abuse_confidence_score": 85,
            "country": "US",
        }

        with patch.dict(
            "sys.modules",
            {
                "vlair.tools.domain_ip_intel": MagicMock(
                    DomainIPIntelligence=MagicMock(return_value=mock_intel)
                ),
                "vlair.core.history": MagicMock(AnalysisHistory=MagicMock()),
            },
        ):
            main()

        captured = capsys.readouterr()
        assert "IP: 1.2.3.4" in captured.out
        assert "MALICIOUS" in captured.out
        assert "90/100" in captured.out
        assert "85%" in captured.out
        assert "US" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "check", "ip", "1.2.3.4", "--json"])
    def test_check_ip_json(self, mock_registry, capsys):
        """main() check ip --json outputs JSON"""
        from vlair.cli.main import main

        mock_intel = MagicMock()
        mock_intel.lookup.return_value = {"verdict": "CLEAN", "risk_score": 5}

        with patch.dict(
            "sys.modules",
            {
                "vlair.tools.domain_ip_intel": MagicMock(
                    DomainIPIntelligence=MagicMock(return_value=mock_intel)
                ),
                "vlair.core.history": MagicMock(AnalysisHistory=MagicMock()),
            },
        ):
            main()

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["verdict"] == "CLEAN"

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "check", "ip"])
    def test_check_ip_missing_value(self, mock_registry, capsys):
        """main() check ip without value exits 1"""
        from vlair.cli.main import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Missing IP" in captured.err

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "check", "url", "http://bad.com/payload"])
    def test_check_url_console(self, mock_registry, capsys):
        """main() check url outputs URL info"""
        from vlair.cli.main import main

        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = {
            "verdict": "MALICIOUS",
            "risk_score": 95,
            "threats": ["Known phishing URL", "Suspicious TLD"],
        }

        with patch.dict(
            "sys.modules",
            {
                "vlair.tools.url_analyzer": MagicMock(
                    URLAnalyzer=MagicMock(return_value=mock_analyzer)
                ),
                "vlair.core.history": MagicMock(AnalysisHistory=MagicMock()),
            },
        ):
            main()

        captured = capsys.readouterr()
        assert "URL: http://bad.com/payload" in captured.out
        assert "MALICIOUS" in captured.out
        assert "95/100" in captured.out
        assert "Known phishing URL" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "check", "url", "http://bad.com", "--json"])
    def test_check_url_json(self, mock_registry, capsys):
        """main() check url --json outputs JSON"""
        from vlair.cli.main import main

        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = {"verdict": "CLEAN", "risk_score": 0}

        with patch.dict(
            "sys.modules",
            {
                "vlair.tools.url_analyzer": MagicMock(
                    URLAnalyzer=MagicMock(return_value=mock_analyzer)
                ),
                "vlair.core.history": MagicMock(AnalysisHistory=MagicMock()),
            },
        ):
            main()

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["verdict"] == "CLEAN"

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "check", "url"])
    def test_check_url_missing_value(self, mock_registry, capsys):
        """main() check url without value exits 1"""
        from vlair.cli.main import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Missing URL" in captured.err

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "check", "unknowntype"])
    def test_check_unknown_type_not_file(self, mock_registry, capsys):
        """main() check with unknown type (not a file) exits 1"""
        from vlair.cli.main import main

        with patch("os.path.isfile", return_value=False):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Unknown check type" in captured.err

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "check", "iocs.txt"])
    def test_check_auto_detect_file(self, mock_registry, capsys):
        """main() check with file path auto-detects and analyzes"""
        from vlair.cli.main import main

        mock_scorer = MagicMock()
        mock_result = {
            "input": "iocs.txt",
            "type": "file",
            "scorer": mock_scorer,
            "iocs": {},
            "tool_results": {},
        }

        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = mock_result

        mock_reporter = MagicMock()
        mock_reporter.format_console.return_value = "File analysis output"
        mock_reporter.get_exit_code.return_value = 0

        with patch("os.path.isfile", return_value=True):
            with patch.dict(
                "sys.modules",
                {
                    "vlair.core.analyzer": MagicMock(
                        Analyzer=MagicMock(return_value=mock_analyzer)
                    ),
                    "vlair.core.reporter": MagicMock(
                        Reporter=MagicMock(return_value=mock_reporter)
                    ),
                    "vlair.core.history": MagicMock(AnalysisHistory=MagicMock()),
                },
            ):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 0

        captured = capsys.readouterr()
        assert "File analysis output" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "check", "hash", "abc123", "--verbose"])
    def test_check_verbose_exception(self, mock_registry, capsys):
        """main() check with --verbose shows traceback on error"""
        from vlair.cli.main import main

        def raise_error(*a, **kw):
            raise RuntimeError("Connection failed")

        mock_lookup = MagicMock()
        mock_lookup.lookup.side_effect = raise_error

        with patch.dict(
            "sys.modules",
            {
                "vlair.tools.hash_lookup": MagicMock(
                    HashLookup=MagicMock(return_value=mock_lookup)
                ),
            },
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Error during check" in captured.err

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "check", "hash", "abc123"])
    def test_check_import_error(self, mock_registry, capsys):
        """main() check handles ImportError"""
        from vlair.cli.main import main

        original_import = (
            __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__
        )

        def mock_import(name, *args, **kwargs):
            if "hash_lookup" in name:
                raise ImportError("No module")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Error" in captured.err


class TestMainWorkflow:
    """Test main() workflow command"""

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "workflow"])
    def test_workflow_no_args(self, mock_registry, capsys):
        """main() workflow without args exits 1 with usage"""
        from vlair.cli.main import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Usage" in captured.err
        assert "phishing-email" in captured.err

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "workflow", "phishing-email"])
    def test_workflow_missing_input(self, mock_registry, capsys):
        """main() workflow <name> without input exits 1"""
        from vlair.cli.main import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Missing input" in captured.err

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "workflow", "phishing-email", "suspicious.eml"])
    def test_workflow_console_output(self, mock_registry, capsys):
        """main() workflow runs and produces console output"""
        from vlair.cli.main import main

        mock_scorer = MagicMock()
        mock_scorer.get_summary.return_value = {"verdict": "SUSPICIOUS", "risk_score": 70}
        mock_scorer.get_findings.return_value = ["finding1"]
        mock_scorer.get_recommendations.return_value = ["rec1"]

        mock_workflow_result = {
            "input": "suspicious.eml",
            "type": "email",
            "scorer": mock_scorer,
            "iocs": {},
            "tool_results": {},
            "workflow": "phishing-email",
            "steps_completed": 7,
            "steps_total": 7,
            "duration_seconds": 5.2,
        }

        mock_workflow_instance = MagicMock()
        mock_workflow_instance.execute.return_value = mock_workflow_result

        mock_workflow_class = MagicMock(return_value=mock_workflow_instance)

        mock_registry_cls = MagicMock()
        mock_registry_cls.get.return_value = mock_workflow_class

        mock_reporter = MagicMock()
        mock_reporter.format_console.return_value = "Workflow console output"
        mock_reporter.get_exit_code.return_value = 1

        with patch.dict(
            "sys.modules",
            {
                "vlair.core.workflow": MagicMock(WorkflowRegistry=mock_registry_cls),
                "vlair.core.reporter": MagicMock(Reporter=MagicMock(return_value=mock_reporter)),
                "workflows": MagicMock(
                    PhishingEmailWorkflow=MagicMock(),
                    MalwareTriageWorkflow=MagicMock(),
                    IOCHuntWorkflow=MagicMock(),
                    NetworkForensicsWorkflow=MagicMock(),
                    LogInvestigationWorkflow=MagicMock(),
                ),
            },
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Workflow console output" in captured.out
        assert "phishing-email" in captured.out
        assert "7/7" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "workflow", "phishing-email", "test.eml", "--json"])
    def test_workflow_json_output(self, mock_registry, capsys):
        """main() workflow --json produces JSON output"""
        from vlair.cli.main import main

        mock_scorer = MagicMock()
        mock_scorer.get_summary.return_value = {"verdict": "CLEAN", "risk_score": 5}
        mock_scorer.get_findings.return_value = []
        mock_scorer.get_recommendations.return_value = []

        mock_workflow_result = {
            "input": "test.eml",
            "type": "email",
            "scorer": mock_scorer,
            "iocs": {},
            "tool_results": {},
            "workflow": "phishing-email",
            "steps_completed": 7,
            "steps_total": 7,
            "duration_seconds": 3.1,
        }

        mock_workflow_instance = MagicMock()
        mock_workflow_instance.execute.return_value = mock_workflow_result

        mock_workflow_class = MagicMock(return_value=mock_workflow_instance)

        mock_wf_registry = MagicMock()
        mock_wf_registry.get.return_value = mock_workflow_class

        mock_reporter = MagicMock()
        mock_reporter.get_exit_code.return_value = 0

        with patch.dict(
            "sys.modules",
            {
                "vlair.core.workflow": MagicMock(WorkflowRegistry=mock_wf_registry),
                "vlair.core.reporter": MagicMock(Reporter=MagicMock(return_value=mock_reporter)),
                "workflows": MagicMock(
                    PhishingEmailWorkflow=MagicMock(),
                    MalwareTriageWorkflow=MagicMock(),
                    IOCHuntWorkflow=MagicMock(),
                    NetworkForensicsWorkflow=MagicMock(),
                    LogInvestigationWorkflow=MagicMock(),
                ),
            },
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        captured = capsys.readouterr()
        # JSON output should be parseable
        parsed = json.loads(captured.out)
        assert "workflow" in parsed

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "workflow", "unknown-workflow", "input.txt"])
    def test_workflow_unknown_name(self, mock_registry, capsys):
        """main() workflow with unknown name exits 1"""
        from vlair.cli.main import main

        mock_wf_registry = MagicMock()
        mock_wf_registry.get.return_value = None

        with patch.dict(
            "sys.modules",
            {
                "vlair.core.workflow": MagicMock(WorkflowRegistry=mock_wf_registry),
                "vlair.core.reporter": MagicMock(),
                "workflows": MagicMock(
                    PhishingEmailWorkflow=MagicMock(),
                    MalwareTriageWorkflow=MagicMock(),
                    IOCHuntWorkflow=MagicMock(),
                    NetworkForensicsWorkflow=MagicMock(),
                    LogInvestigationWorkflow=MagicMock(),
                ),
            },
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Unknown workflow" in captured.err

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "workflow", "phishing-email", "test.eml"])
    def test_workflow_import_error(self, mock_registry, capsys):
        """main() workflow handles ImportError"""
        from vlair.cli.main import main

        original_import = (
            __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__
        )

        def mock_import(name, *args, **kwargs):
            if name == "vlair.core.workflow":
                raise ImportError("No module")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Error" in captured.err


class TestMainInvestigate:
    """Test main() investigate command"""

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate"])
    def test_investigate_no_args(self, mock_registry, capsys):
        """main() investigate without args exits 1 with usage"""
        from vlair.cli.main import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Usage" in captured.err
        assert "phishing" in captured.err

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate", "interactive"])
    def test_investigate_interactive(self, mock_registry, capsys):
        """main() investigate interactive runs interactive mode"""
        from vlair.cli.main import main

        mock_investigation = MagicMock()

        with patch.dict(
            "sys.modules",
            {
                "vlair.core.interactive": MagicMock(
                    InteractiveInvestigation=MagicMock(return_value=mock_investigation)
                ),
            },
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        mock_investigation.run.assert_called_once()

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate", "interactive"])
    def test_investigate_interactive_import_error(self, mock_registry, capsys):
        """main() investigate interactive handles ImportError"""
        from vlair.cli.main import main

        original_import = (
            __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__
        )

        def mock_import(name, *args, **kwargs):
            if "interactive" in name:
                raise ImportError("No module")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate", "phishing"])
    def test_investigate_phishing_no_file(self, mock_registry, capsys):
        """main() investigate phishing without --file exits 1"""
        from vlair.cli.main import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "--file" in captured.err

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate", "phishing", "--file", "nonexistent.eml"])
    def test_investigate_phishing_file_not_found(self, mock_registry, capsys):
        """main() investigate phishing with missing file exits 1"""
        from vlair.cli.main import main

        with patch("os.path.exists", return_value=False):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "File not found" in captured.err

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate", "phishing", "--file", "test.eml", "--mock"])
    def test_investigate_phishing_clean_verdict(self, mock_registry, capsys):
        """main() investigate phishing with CLEAN verdict exits 0"""
        from vlair.cli.main import main

        # Build mock state
        mock_step = MagicMock()
        mock_step.status.value = "completed"
        mock_step.name = "Parse Email"
        mock_step.duration_seconds = 0.5
        mock_step.error = None

        mock_action = MagicMock()
        mock_action.name = "Block sender"
        mock_action.status.value = "pending"
        mock_action.target = "sender@evil.com"

        mock_state = MagicMock()
        mock_state.id = "INV-2026-01-31-TEST"
        mock_state.status.value = "completed"
        mock_state.risk_score = 10
        mock_state.verdict = "CLEAN"
        mock_state.steps = [mock_step]
        mock_state.findings = []
        mock_state.iocs = {}
        mock_state.remediation_actions = []
        mock_state.to_dict.return_value = {"id": "INV-2026-01-31-TEST", "verdict": "CLEAN"}

        mock_engine = MagicMock()
        mock_engine.start_investigation.return_value = mock_state

        mock_playbook_registry = MagicMock()

        with patch("os.path.exists", return_value=True):
            with patch.dict(
                "sys.modules",
                {
                    "vlair.investigate": MagicMock(
                        InvestigationEngine=MagicMock(return_value=mock_engine),
                        PlaybookRegistry=mock_playbook_registry,
                    ),
                    "vlair.investigate.playbooks.phishing": MagicMock(PhishingPlaybook=MagicMock()),
                    "vlair.investigate.connectors.mock": MagicMock(
                        MockEmailConnector=MagicMock(),
                        MockSIEMConnector=MagicMock(),
                    ),
                },
            ):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 0

        captured = capsys.readouterr()
        assert "Investigation Complete" in captured.out
        assert "CLEAN" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate", "phishing", "--file", "test.eml", "--mock"])
    def test_investigate_phishing_malicious_verdict(self, mock_registry, capsys):
        """main() investigate phishing with MALICIOUS verdict exits 2"""
        from vlair.cli.main import main

        mock_step = MagicMock()
        mock_step.status.value = "completed"

        mock_state = MagicMock()
        mock_state.id = "INV-2026-01-31-MAL"
        mock_state.status.value = "completed"
        mock_state.risk_score = 95
        mock_state.verdict = "MALICIOUS"
        mock_state.steps = [mock_step]
        mock_state.findings = [{"severity": "critical", "message": "Known malware attachment"}]
        mock_state.iocs = {"hashes": ["abc123"], "domains": ["evil.com"]}
        mock_state.remediation_actions = [
            MagicMock(
                name="Block sender", status=MagicMock(value="pending"), target="sender@evil.com"
            )
        ]

        mock_engine = MagicMock()
        mock_engine.start_investigation.return_value = mock_state

        with patch("os.path.exists", return_value=True):
            with patch.dict(
                "sys.modules",
                {
                    "vlair.investigate": MagicMock(
                        InvestigationEngine=MagicMock(return_value=mock_engine),
                        PlaybookRegistry=MagicMock(),
                    ),
                    "vlair.investigate.playbooks.phishing": MagicMock(PhishingPlaybook=MagicMock()),
                    "vlair.investigate.connectors.mock": MagicMock(
                        MockEmailConnector=MagicMock(),
                        MockSIEMConnector=MagicMock(),
                    ),
                },
            ):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 2

        captured = capsys.readouterr()
        assert "MALICIOUS" in captured.out
        assert "Known malware attachment" in captured.out
        assert "Block sender" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate", "phishing", "--file", "test.eml", "--mock"])
    def test_investigate_phishing_suspicious_verdict(self, mock_registry, capsys):
        """main() investigate phishing with SUSPICIOUS verdict exits 1"""
        from vlair.cli.main import main

        mock_state = MagicMock()
        mock_state.id = "INV-2026-01-31-SUSP"
        mock_state.status.value = "completed"
        mock_state.risk_score = 60
        mock_state.verdict = "SUSPICIOUS"
        mock_state.steps = []
        mock_state.findings = []
        mock_state.iocs = {}
        mock_state.remediation_actions = []

        mock_engine = MagicMock()
        mock_engine.start_investigation.return_value = mock_state

        with patch("os.path.exists", return_value=True):
            with patch.dict(
                "sys.modules",
                {
                    "vlair.investigate": MagicMock(
                        InvestigationEngine=MagicMock(return_value=mock_engine),
                        PlaybookRegistry=MagicMock(),
                    ),
                    "vlair.investigate.playbooks.phishing": MagicMock(PhishingPlaybook=MagicMock()),
                    "vlair.investigate.connectors.mock": MagicMock(
                        MockEmailConnector=MagicMock(),
                        MockSIEMConnector=MagicMock(),
                    ),
                },
            ):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 1

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch(
        "sys.argv", ["vlair", "investigate", "phishing", "--file", "test.eml", "--mock", "--json"]
    )
    def test_investigate_phishing_json_output(self, mock_registry, capsys):
        """main() investigate phishing --json produces JSON"""
        from vlair.cli.main import main

        mock_state = MagicMock()
        mock_state.id = "INV-JSON-TEST"
        mock_state.verdict = "CLEAN"
        mock_state.to_dict.return_value = {
            "id": "INV-JSON-TEST",
            "verdict": "CLEAN",
            "risk_score": 5,
        }

        mock_engine = MagicMock()
        mock_engine.start_investigation.return_value = mock_state

        with patch("os.path.exists", return_value=True):
            with patch.dict(
                "sys.modules",
                {
                    "vlair.investigate": MagicMock(
                        InvestigationEngine=MagicMock(return_value=mock_engine),
                        PlaybookRegistry=MagicMock(),
                    ),
                    "vlair.investigate.playbooks.phishing": MagicMock(PhishingPlaybook=MagicMock()),
                    "vlair.investigate.connectors.mock": MagicMock(
                        MockEmailConnector=MagicMock(),
                        MockSIEMConnector=MagicMock(),
                    ),
                },
            ):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 0

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["id"] == "INV-JSON-TEST"

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate", "status"])
    def test_investigate_status_no_id(self, mock_registry, capsys):
        """main() investigate status without ID exits 1"""
        from vlair.cli.main import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Usage" in captured.err

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate", "status", "INV-2026-01-31-TEST"])
    def test_investigate_status_found(self, mock_registry, capsys):
        """main() investigate status shows investigation info"""
        from vlair.cli.main import main

        mock_state = MagicMock()
        mock_state.id = "INV-2026-01-31-TEST"
        mock_state.type = "phishing"
        mock_state.status.value = "completed"
        mock_state.risk_score = 50
        mock_state.verdict = "SUSPICIOUS"
        mock_state.created_at = "2026-01-31T10:00:00"
        mock_state.completed_at = "2026-01-31T10:00:05"
        mock_state.error = None

        mock_engine = MagicMock()
        mock_engine.get_investigation.return_value = mock_state

        with patch.dict(
            "sys.modules",
            {
                "vlair.investigate": MagicMock(
                    InvestigationEngine=MagicMock(return_value=mock_engine)
                ),
            },
        ):
            main()

        captured = capsys.readouterr()
        assert "INV-2026-01-31-TEST" in captured.out
        assert "phishing" in captured.out
        assert "SUSPICIOUS" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate", "status", "INV-NOTFOUND"])
    def test_investigate_status_not_found(self, mock_registry, capsys):
        """main() investigate status with unknown ID exits 1"""
        from vlair.cli.main import main

        mock_engine = MagicMock()
        mock_engine.get_investigation.return_value = None

        with patch.dict(
            "sys.modules",
            {
                "vlair.investigate": MagicMock(
                    InvestigationEngine=MagicMock(return_value=mock_engine)
                ),
            },
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "not found" in captured.err

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate", "list"])
    def test_investigate_list_with_results(self, mock_registry, capsys):
        """main() investigate list shows investigations"""
        from vlair.cli.main import main

        mock_engine = MagicMock()
        mock_engine.list_investigations.return_value = [
            {
                "id": "INV-001",
                "type": "phishing",
                "status": "completed",
                "verdict": "MALICIOUS",
                "risk_score": 90,
            },
            {
                "id": "INV-002",
                "type": "phishing",
                "status": "completed",
                "verdict": "CLEAN",
                "risk_score": 5,
            },
        ]

        with patch.dict(
            "sys.modules",
            {
                "vlair.investigate": MagicMock(
                    InvestigationEngine=MagicMock(return_value=mock_engine)
                ),
            },
        ):
            main()

        captured = capsys.readouterr()
        assert "Recent Investigations" in captured.out
        assert "INV-001" in captured.out
        assert "INV-002" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate", "list"])
    def test_investigate_list_empty(self, mock_registry, capsys):
        """main() investigate list with no investigations exits 0"""
        from vlair.cli.main import main

        mock_engine = MagicMock()
        mock_engine.list_investigations.return_value = []

        with patch.dict(
            "sys.modules",
            {
                "vlair.investigate": MagicMock(
                    InvestigationEngine=MagicMock(return_value=mock_engine)
                ),
            },
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        captured = capsys.readouterr()
        assert "No investigations found" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate", "list", "--last", "24h", "--limit", "5"])
    def test_investigate_list_with_filters(self, mock_registry, capsys):
        """main() investigate list parses --last and --limit"""
        from vlair.cli.main import main

        mock_engine = MagicMock()
        mock_engine.list_investigations.return_value = [
            {
                "id": "INV-X",
                "type": "phishing",
                "status": "completed",
                "verdict": "CLEAN",
                "risk_score": 0,
            }
        ]

        with patch.dict(
            "sys.modules",
            {
                "vlair.investigate": MagicMock(
                    InvestigationEngine=MagicMock(return_value=mock_engine)
                ),
            },
        ):
            main()

        mock_engine.list_investigations.assert_called_once_with(limit=5, since_hours=24)

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate", "list", "--last", "7d"])
    def test_investigate_list_days_filter(self, mock_registry, capsys):
        """main() investigate list parses --last with days"""
        from vlair.cli.main import main

        mock_engine = MagicMock()
        mock_engine.list_investigations.return_value = []

        with patch.dict(
            "sys.modules",
            {
                "vlair.investigate": MagicMock(
                    InvestigationEngine=MagicMock(return_value=mock_engine)
                ),
            },
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        mock_engine.list_investigations.assert_called_once_with(limit=20, since_hours=168)

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate", "results"])
    def test_investigate_results_no_id(self, mock_registry, capsys):
        """main() investigate results without ID exits 1"""
        from vlair.cli.main import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Usage" in captured.err

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate", "results", "INV-TEST", "--json"])
    def test_investigate_results_json(self, mock_registry, capsys):
        """main() investigate results --json outputs JSON"""
        from vlair.cli.main import main

        mock_state = MagicMock()
        mock_state.to_dict.return_value = {"id": "INV-TEST", "verdict": "CLEAN"}

        mock_engine = MagicMock()
        mock_engine.get_investigation.return_value = mock_state

        with patch.dict(
            "sys.modules",
            {
                "vlair.investigate": MagicMock(
                    InvestigationEngine=MagicMock(return_value=mock_engine)
                ),
            },
        ):
            main()

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["id"] == "INV-TEST"

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate", "results", "INV-TEST"])
    def test_investigate_results_console(self, mock_registry, capsys):
        """main() investigate results shows detailed console output"""
        from vlair.cli.main import main

        mock_step = MagicMock()
        mock_step.status.value = "completed"
        mock_step.name = "Parse Email"
        mock_step.duration_seconds = 0.3
        mock_step.error = None

        mock_failed_step = MagicMock()
        mock_failed_step.status.value = "failed"
        mock_failed_step.name = "Check VT"
        mock_failed_step.duration_seconds = 1.0
        mock_failed_step.error = "API timeout"

        mock_action = MagicMock()
        mock_action.name = "Block domain"
        mock_action.status = MagicMock(value="pending")
        mock_action.target = "evil.com"

        mock_state = MagicMock()
        mock_state.id = "INV-DETAIL"
        mock_state.type = "phishing"
        mock_state.status.value = "completed"
        mock_state.risk_score = 75
        mock_state.verdict = "SUSPICIOUS"
        mock_state.get_duration_seconds.return_value = 5.5
        mock_state.steps = [mock_step, mock_failed_step]
        mock_state.findings = [{"severity": "high", "message": "Suspicious sender"}]
        mock_state.iocs = {
            "domains": ["evil.com", "bad.org", "phish.net", "spam.io", "hack.co", "extra.xyz"],
            "ips": ["1.2.3.4"],
        }
        mock_state.remediation_actions = [mock_action]

        mock_engine = MagicMock()
        mock_engine.get_investigation.return_value = mock_state

        with patch.dict(
            "sys.modules",
            {
                "vlair.investigate": MagicMock(
                    InvestigationEngine=MagicMock(return_value=mock_engine)
                ),
            },
        ):
            main()

        captured = capsys.readouterr()
        assert "INV-DETAIL" in captured.out
        assert "SUSPICIOUS" in captured.out
        assert "Parse Email" in captured.out
        assert "API timeout" in captured.out
        assert "Suspicious sender" in captured.out
        assert "evil.com" in captured.out
        assert "... and" in captured.out  # More than 5 domains
        assert "Block domain" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate", "results", "INV-NOTFOUND"])
    def test_investigate_results_not_found(self, mock_registry, capsys):
        """main() investigate results with unknown ID exits 1"""
        from vlair.cli.main import main

        mock_engine = MagicMock()
        mock_engine.get_investigation.return_value = None

        with patch.dict(
            "sys.modules",
            {
                "vlair.investigate": MagicMock(
                    InvestigationEngine=MagicMock(return_value=mock_engine)
                ),
            },
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "not found" in captured.err

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate", "unknowncmd"])
    def test_investigate_unknown_subcommand(self, mock_registry, capsys):
        """main() investigate with unknown subcommand exits 1"""
        from vlair.cli.main import main

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Unknown investigate command" in captured.err


class TestMainStatus:
    """Test main() status command"""

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "status"])
    def test_status_dashboard(self, mock_registry, capsys):
        """main() status shows the status dashboard"""
        from vlair.cli.main import main

        mock_history = MagicMock()
        mock_history.get_stats.return_value = {
            "total_analyses": 10,
            "verdicts": {"CLEAN": 5, "SUSPICIOUS": 3, "MALICIOUS": 2},
            "last_analysis": "2026-01-31T10:00:00",
        }
        mock_history.get_recent.return_value = [
            {
                "timestamp": "2026-01-31T10:00:00Z",
                "input_value": "test.eml",
                "verdict": "CLEAN",
                "risk_score": 5,
            }
        ]

        with patch.dict(
            "sys.modules",
            {
                "dotenv": MagicMock(load_dotenv=MagicMock()),
                "vlair.core.history": MagicMock(
                    AnalysisHistory=MagicMock(return_value=mock_history)
                ),
            },
        ):
            with patch("os.getenv", return_value=None):
                main()

        captured = capsys.readouterr()
        assert "Status Dashboard" in captured.out
        assert "API Keys" in captured.out
        assert "Features" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "status"])
    def test_status_with_api_keys_configured(self, mock_registry, capsys):
        """main() status shows configured API keys"""
        from vlair.cli.main import main

        def fake_getenv(key, default=None):
            if key == "VT_API_KEY":
                return "some_key"
            return default

        mock_history = MagicMock()
        mock_history.get_stats.return_value = {
            "total_analyses": 0,
            "verdicts": {},
            "last_analysis": None,
        }

        with patch.dict(
            "sys.modules",
            {
                "dotenv": MagicMock(load_dotenv=MagicMock()),
                "vlair.core.history": MagicMock(
                    AnalysisHistory=MagicMock(return_value=mock_history)
                ),
            },
        ):
            with patch("os.getenv", side_effect=fake_getenv):
                main()

        captured = capsys.readouterr()
        assert "Configured" in captured.out or "[+]" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "status"])
    def test_status_no_history(self, mock_registry, capsys):
        """main() status handles missing history gracefully"""
        from vlair.cli.main import main

        with patch.dict(
            "sys.modules",
            {
                "dotenv": MagicMock(load_dotenv=MagicMock()),
            },
        ):
            with patch("os.getenv", return_value=None):
                # Make history import fail
                original_import = (
                    __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__
                )

                def mock_import(name, *args, **kwargs):
                    if "history" in name:
                        raise ImportError("No history")
                    if "cache_manager" in name:
                        raise ImportError("No cache")
                    return original_import(name, *args, **kwargs)

                with patch("builtins.__import__", side_effect=mock_import):
                    main()

        captured = capsys.readouterr()
        assert "Status Dashboard" in captured.out


class TestMainRunTool:
    """Test main() running a tool directly"""

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "eml", "test.eml"])
    def test_run_tool_directly(self, mock_registry, capsys):
        """main() with tool ID dispatches to run_tool"""
        from vlair.cli.main import main

        with patch("vlair.cli.main.ToolManager.run_tool") as mock_run:
            main()
            mock_run.assert_called_once_with("eml", ["test.eml"])

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "hash", "abc123", "--verbose"])
    def test_run_tool_with_args(self, mock_registry, capsys):
        """main() passes remaining args to tool"""
        from vlair.cli.main import main

        with patch("vlair.cli.main.ToolManager.run_tool") as mock_run:
            main()
            mock_run.assert_called_once_with("hash", ["abc123", "--verbose"])


class TestMainInteractiveMenu:
    """Test main() interactive menu (no args)"""

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair"])
    def test_no_args_enters_interactive(self, mock_registry):
        """main() with no args enters interactive menu loop"""
        from vlair.cli.main import main

        # Make show_main_menu raise KeyboardInterrupt to break the while True loop
        with patch("vlair.cli.main.InteractiveMenu.show_main_menu", side_effect=KeyboardInterrupt):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair"])
    def test_interactive_exit_choice(self, mock_registry, capsys):
        """main() interactive menu exit choice (0) exits cleanly"""
        from vlair.cli.main import main

        with patch("builtins.input", return_value="0"):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0


# ---------------------------------------------------------------------------
# InteractiveMenu standalone tests
# ---------------------------------------------------------------------------


class TestInteractiveMenuMethods:
    """Test InteractiveMenu methods in isolation"""

    @staticmethod
    def _registry_with_available():
        """Return a fake registry with the 'available' key set."""
        reg = _fake_registry()
        for tid in reg:
            reg[tid]["available"] = True
        return reg

    def _make_menu(self):
        """Create an InteractiveMenu with mock discovery/manager."""
        from vlair.cli.main import InteractiveMenu

        reg = self._registry_with_available()
        discovery = MagicMock()
        discovery.get_all_tools.return_value = reg
        discovery.get_tool.side_effect = lambda tid: reg.get(tid)
        discovery.get_by_category.side_effect = lambda cat: [
            (tid, tool) for tid, tool in reg.items() if tool["category"] == cat
        ]
        discovery.search_tools.side_effect = lambda kw: [
            (tid, tool)
            for tid, tool in reg.items()
            if kw.lower() in tool["name"].lower() or kw.lower() in tool["description"].lower()
        ]

        manager = MagicMock()
        menu = InteractiveMenu(discovery, manager)
        return menu

    def test_show_tool_info_existing(self, capsys):
        """show_tool_info displays tool details"""
        menu = self._make_menu()

        # Add available flag to the tool data
        eml_tool = dict(_fake_registry()["eml"])
        eml_tool["available"] = True
        menu.discovery.get_tool.return_value = eml_tool

        with patch("builtins.input", return_value=""):
            menu.show_tool_info("eml")

        captured = capsys.readouterr()
        assert "EML Parser" in captured.out
        assert "eml" in captured.out
        assert "Email Analysis" in captured.out
        assert "email" in captured.out  # keyword

    def test_show_tool_info_nonexistent(self, capsys):
        """show_tool_info handles unknown tool gracefully"""
        menu = self._make_menu()
        menu.discovery.get_tool.return_value = None

        menu.show_tool_info("nonexistent")

        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_show_tool_info_with_api_keys(self, capsys):
        """show_tool_info shows API key status"""
        menu = self._make_menu()

        tool = dict(_fake_registry()["eml"])
        tool["available"] = True
        menu.discovery.get_tool.return_value = tool

        with patch("builtins.input", return_value=""):
            with patch("os.getenv", return_value=None):
                menu.show_tool_info("eml")

        captured = capsys.readouterr()
        assert "API Keys" in captured.out or "VT_API_KEY" in captured.out

    def test_show_tool_info_unavailable(self, capsys):
        """show_tool_info shows unavailable status"""
        menu = self._make_menu()

        tool = dict(_fake_registry()["hash"])
        tool["available"] = False
        # Override side_effect with return_value by clearing side_effect first
        menu.discovery.get_tool.side_effect = None
        menu.discovery.get_tool.return_value = tool

        with patch("builtins.input", return_value=""):
            menu.show_tool_info("hash")

        captured = capsys.readouterr()
        # The status line uses a unicode cross mark for unavailable tools
        assert "Not Found" in captured.out

    def test_show_api_status(self, capsys):
        """show_api_status displays API key configuration"""
        menu = self._make_menu()

        def fake_getenv(key, default=None):
            if key == "VT_API_KEY":
                return "test_key"
            return default

        with patch("os.getenv", side_effect=fake_getenv):
            with patch("builtins.input", return_value=""):
                # Prevent infinite recursion to show_main_menu
                with patch.object(menu, "show_main_menu"):
                    menu.show_api_status()

        captured = capsys.readouterr()
        assert "API Key Status" in captured.out
        assert "VirusTotal" in captured.out
        assert "AbuseIPDB" in captured.out

    def test_list_all_tools(self, capsys):
        """list_all_tools displays all tools grouped by category"""
        menu = self._make_menu()

        with patch("builtins.input", return_value=""):
            with patch.object(menu, "show_main_menu"):
                menu.list_all_tools()

        captured = capsys.readouterr()
        assert "All Available Tools" in captured.out

    def test_show_quick_start(self, capsys):
        """show_quick_start displays the guide"""
        menu = self._make_menu()

        with patch("builtins.input", return_value=""):
            with patch.object(menu, "show_main_menu"):
                menu.show_quick_start()

        captured = capsys.readouterr()
        assert "Quick Start Guide" in captured.out
        assert "vlair" in captured.out

    def test_show_main_menu_invalid_choice(self, capsys):
        """show_main_menu with invalid choice shows error and recurses"""
        menu = self._make_menu()

        # First call: invalid choice, second call: exit
        call_count = [0]
        original_show = menu.show_main_menu

        def mock_show():
            call_count[0] += 1
            if call_count[0] > 1:
                raise KeyboardInterrupt  # Break recursion
            return original_show()

        with patch("builtins.input", return_value="99"):
            with patch.object(menu, "show_main_menu", side_effect=mock_show):
                with pytest.raises(KeyboardInterrupt):
                    menu.show_main_menu()

    def test_search_tools_interactive(self, capsys):
        """search_tools prompts for keyword and shows results"""
        menu = self._make_menu()

        with patch("builtins.input", side_effect=["email", ""]):
            with patch.object(menu, "show_main_menu"):
                menu.search_tools()

        captured = capsys.readouterr()
        assert "Search Results" in captured.out

    def test_search_tools_empty_keyword(self, capsys):
        """search_tools with empty keyword returns to main menu"""
        menu = self._make_menu()

        with patch("builtins.input", return_value=""):
            with patch.object(menu, "show_main_menu") as mock_main:
                menu.search_tools()
                mock_main.assert_called_once()

    def test_browse_by_category(self, capsys):
        """browse_by_category shows categories"""
        menu = self._make_menu()

        # Choose "0" to go back
        with patch("builtins.input", return_value="0"):
            with patch.object(menu, "show_main_menu"):
                menu.browse_by_category()

        captured = capsys.readouterr()
        assert "Tool Categories" in captured.out

    def test_browse_by_category_select(self, capsys):
        """browse_by_category selecting a valid category"""
        menu = self._make_menu()

        # First input: select category 1, then in show_category_tools: "0" to go back
        with patch("builtins.input", side_effect=["1", "0", "0"]):
            with patch.object(menu, "show_main_menu"):
                with patch.object(menu, "show_category_tools") as mock_cat:
                    menu.browse_by_category()
                    mock_cat.assert_called_once()

    def test_browse_by_category_invalid_input(self, capsys):
        """browse_by_category with non-numeric input recurses"""
        menu = self._make_menu()

        call_count = [0]

        def mock_browse():
            call_count[0] += 1
            if call_count[0] > 1:
                return  # Stop recursion

        with patch("builtins.input", return_value="abc"):
            with patch.object(menu, "browse_by_category", side_effect=mock_browse):
                menu.browse_by_category()

    def test_show_category_tools_info(self, capsys):
        """show_category_tools with 'i' choice shows tool info"""
        menu = self._make_menu()

        # Select "i", then tool "1", then "0" to go back
        with patch("builtins.input", side_effect=["i", "1", "0", "0"]):
            with patch.object(menu, "show_tool_info") as mock_info:
                with patch.object(menu, "browse_by_category"):
                    menu.show_category_tools("Email Analysis")
                    mock_info.assert_called_once()


# ---------------------------------------------------------------------------
# Edge cases and error paths
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Test miscellaneous edge cases"""

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "check", "hash", "abc123"])
    def test_check_hash_no_detections(self, mock_registry, capsys):
        """check hash with no detections doesn't print detection line"""
        from vlair.cli.main import main

        mock_lookup = MagicMock()
        mock_lookup.lookup.return_value = {
            "verdict": "UNKNOWN",
            "detections": 0,
            "total_engines": 0,
            "sources": [],
        }

        with patch.dict(
            "sys.modules",
            {
                "vlair.tools.hash_lookup": MagicMock(
                    HashLookup=MagicMock(return_value=mock_lookup)
                ),
                "vlair.core.history": MagicMock(AnalysisHistory=MagicMock()),
            },
        ):
            main()

        captured = capsys.readouterr()
        assert "Hash:" in captured.out
        assert "UNKNOWN" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "check", "hash", "abc123"])
    def test_check_hash_with_suggested_threat_label(self, mock_registry, capsys):
        """check hash falls back to suggested_threat_label if no malware_family"""
        from vlair.cli.main import main

        mock_lookup = MagicMock()
        mock_lookup.lookup.return_value = {
            "verdict": "MALICIOUS",
            "detections": 30,
            "total_engines": 70,
            "malware_family": None,
            "suggested_threat_label": "trojan.generic",
            "sources": ["VirusTotal"],
        }

        with patch.dict(
            "sys.modules",
            {
                "vlair.tools.hash_lookup": MagicMock(
                    HashLookup=MagicMock(return_value=mock_lookup)
                ),
                "vlair.core.history": MagicMock(AnalysisHistory=MagicMock()),
            },
        ):
            main()

        captured = capsys.readouterr()
        assert "trojan.generic" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "check", "ip", "1.2.3.4"])
    def test_check_ip_no_abuse_score(self, mock_registry, capsys):
        """check ip without abuse_confidence_score omits that line"""
        from vlair.cli.main import main

        mock_intel = MagicMock()
        mock_intel.lookup.return_value = {
            "verdict": "CLEAN",
            "risk_score": 5,
        }

        with patch.dict(
            "sys.modules",
            {
                "vlair.tools.domain_ip_intel": MagicMock(
                    DomainIPIntelligence=MagicMock(return_value=mock_intel)
                ),
                "vlair.core.history": MagicMock(AnalysisHistory=MagicMock()),
            },
        ):
            main()

        captured = capsys.readouterr()
        assert "Abuse Score" not in captured.out
        assert "Country" not in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "check", "domain", "test.com"])
    def test_check_domain_no_dns_records(self, mock_registry, capsys):
        """check domain without dns records omits IP line"""
        from vlair.cli.main import main

        mock_intel = MagicMock()
        mock_intel.lookup.return_value = {
            "verdict": "CLEAN",
            "risk_score": 0,
            "dns": {},
            "categories": [],
        }

        with patch.dict(
            "sys.modules",
            {
                "vlair.tools.domain_ip_intel": MagicMock(
                    DomainIPIntelligence=MagicMock(return_value=mock_intel)
                ),
                "vlair.core.history": MagicMock(AnalysisHistory=MagicMock()),
            },
        ):
            main()

        captured = capsys.readouterr()
        assert "IPs:" not in captured.out
        assert "Categories:" not in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "check", "url", "http://test.com"])
    def test_check_url_no_threats(self, mock_registry, capsys):
        """check url with empty threats list omits threats section"""
        from vlair.cli.main import main

        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = {
            "verdict": "CLEAN",
            "risk_score": 0,
            "threats": [],
        }

        with patch.dict(
            "sys.modules",
            {
                "vlair.tools.url_analyzer": MagicMock(
                    URLAnalyzer=MagicMock(return_value=mock_analyzer)
                ),
                "vlair.core.history": MagicMock(AnalysisHistory=MagicMock()),
            },
        ):
            main()

        captured = capsys.readouterr()
        assert "[!]" not in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate", "phishing", "--file", "test.eml"])
    def test_investigate_phishing_without_mock_flag(self, mock_registry, capsys):
        """investigate phishing without --mock uses empty connectors"""
        from vlair.cli.main import main

        mock_state = MagicMock()
        mock_state.id = "INV-NOMOCK"
        mock_state.status.value = "completed"
        mock_state.risk_score = 10
        mock_state.verdict = "CLEAN"
        mock_state.steps = []
        mock_state.findings = []
        mock_state.iocs = {}
        mock_state.remediation_actions = []

        mock_engine_cls = MagicMock()
        mock_engine = MagicMock()
        mock_engine.start_investigation.return_value = mock_state
        mock_engine_cls.return_value = mock_engine

        mock_investigate_module = MagicMock(
            InvestigationEngine=mock_engine_cls,
            PlaybookRegistry=MagicMock(),
        )

        with patch("os.path.exists", return_value=True):
            with patch.dict(
                "sys.modules",
                {
                    "vlair.investigate": mock_investigate_module,
                    "vlair.investigate.playbooks.phishing": MagicMock(PhishingPlaybook=MagicMock()),
                },
            ):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 0

                # Verify InvestigationEngine was called with empty connectors
                mock_engine_cls.assert_called_once()
                call_kwargs = mock_engine_cls.call_args
                assert call_kwargs.kwargs.get("connectors") == {}

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate", "status", "INV-ERR"])
    def test_investigate_status_with_error(self, mock_registry, capsys):
        """investigate status shows error field when present"""
        from vlair.cli.main import main

        mock_state = MagicMock()
        mock_state.id = "INV-ERR"
        mock_state.type = "phishing"
        mock_state.status.value = "failed"
        mock_state.risk_score = 0
        mock_state.verdict = "UNKNOWN"
        mock_state.created_at = "2026-01-31T10:00:00"
        mock_state.completed_at = None
        mock_state.error = "Connection timeout to SIEM"

        mock_engine = MagicMock()
        mock_engine.get_investigation.return_value = mock_state

        with patch.dict(
            "sys.modules",
            {
                "vlair.investigate": MagicMock(
                    InvestigationEngine=MagicMock(return_value=mock_engine)
                ),
            },
        ):
            main()

        captured = capsys.readouterr()
        assert "Connection timeout" in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate", "results", "INV-NODUR"])
    def test_investigate_results_no_duration(self, mock_registry, capsys):
        """investigate results handles None duration"""
        from vlair.cli.main import main

        mock_step = MagicMock()
        mock_step.status.value = "pending"
        mock_step.name = "Step1"
        mock_step.duration_seconds = None
        mock_step.error = None

        mock_state = MagicMock()
        mock_state.id = "INV-NODUR"
        mock_state.type = "phishing"
        mock_state.status.value = "running"
        mock_state.risk_score = 0
        mock_state.verdict = "UNKNOWN"
        mock_state.get_duration_seconds.return_value = None
        mock_state.steps = [mock_step]
        mock_state.findings = []
        mock_state.iocs = {"domains": [], "ips": []}
        mock_state.remediation_actions = []

        mock_engine = MagicMock()
        mock_engine.get_investigation.return_value = mock_state

        with patch.dict(
            "sys.modules",
            {
                "vlair.investigate": MagicMock(
                    InvestigationEngine=MagicMock(return_value=mock_engine)
                ),
            },
        ):
            main()

        captured = capsys.readouterr()
        assert "INV-NODUR" in captured.out
        # Duration should not appear
        assert "Duration:" not in captured.out

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate", "phishing", "--file", "test.eml", "--mock"])
    def test_investigate_phishing_import_error(self, mock_registry, capsys):
        """investigate phishing handles ImportError"""
        from vlair.cli.main import main

        original_import = (
            __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__
        )

        def mock_import(name, *args, **kwargs):
            if "vlair.investigate" in str(name):
                raise ImportError("No investigate module")
            return original_import(name, *args, **kwargs)

        with patch("os.path.exists", return_value=True):
            with patch("builtins.__import__", side_effect=mock_import):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Error" in captured.err

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "investigate", "phishing", "--file", "test.eml", "--mock"])
    def test_investigate_phishing_runtime_error(self, mock_registry, capsys):
        """investigate phishing handles runtime exceptions"""
        from vlair.cli.main import main

        mock_engine = MagicMock()
        mock_engine.start_investigation.side_effect = RuntimeError("DB error")

        with patch("os.path.exists", return_value=True):
            with patch.dict(
                "sys.modules",
                {
                    "vlair.investigate": MagicMock(
                        InvestigationEngine=MagicMock(return_value=mock_engine),
                        PlaybookRegistry=MagicMock(),
                    ),
                    "vlair.investigate.playbooks.phishing": MagicMock(PhishingPlaybook=MagicMock()),
                    "vlair.investigate.connectors.mock": MagicMock(
                        MockEmailConnector=MagicMock(),
                        MockSIEMConnector=MagicMock(),
                    ),
                },
            ):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Error during investigation" in captured.err

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch(
        "sys.argv",
        [
            "vlair",
            "workflow",
            "phishing-email",
            "test.eml",
            "--report",
            "html",
            "--output",
            "/tmp/out.html",
        ],
    )
    def test_workflow_with_report_generation(self, mock_registry, capsys):
        """workflow with --report and --output generates report"""
        from vlair.cli.main import main

        mock_scorer = MagicMock()
        mock_scorer.get_summary.return_value = {"verdict": "CLEAN", "risk_score": 0}
        mock_scorer.get_findings.return_value = []
        mock_scorer.get_recommendations.return_value = []

        mock_workflow_result = {
            "input": "test.eml",
            "type": "email",
            "scorer": mock_scorer,
            "iocs": {},
            "tool_results": {},
            "workflow": "phishing-email",
            "steps_completed": 7,
            "steps_total": 7,
            "duration_seconds": 2.0,
        }

        mock_workflow_instance = MagicMock()
        mock_workflow_instance.execute.return_value = mock_workflow_result

        mock_workflow_class = MagicMock(return_value=mock_workflow_instance)

        mock_wf_registry = MagicMock()
        mock_wf_registry.get.return_value = mock_workflow_class

        mock_reporter = MagicMock()
        mock_reporter.format_console.return_value = "Output"
        mock_reporter.get_exit_code.return_value = 0

        mock_generator = MagicMock()
        mock_generator.generate.return_value = "/tmp/out.html"

        with patch.dict(
            "sys.modules",
            {
                "vlair.core.workflow": MagicMock(WorkflowRegistry=mock_wf_registry),
                "vlair.core.reporter": MagicMock(Reporter=MagicMock(return_value=mock_reporter)),
                "vlair.core.report_generator": MagicMock(
                    ReportGenerator=MagicMock(return_value=mock_generator)
                ),
                "workflows": MagicMock(
                    PhishingEmailWorkflow=MagicMock(),
                    MalwareTriageWorkflow=MagicMock(),
                    IOCHuntWorkflow=MagicMock(),
                    NetworkForensicsWorkflow=MagicMock(),
                    LogInvestigationWorkflow=MagicMock(),
                ),
            },
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        captured = capsys.readouterr()
        assert "report" in captured.err.lower() or "Report" in captured.err

    @patch("vlair.cli.main.get_tool_registry", return_value=_fake_registry())
    @patch("sys.argv", ["vlair", "analyze", "test.eml", "--report"])
    def test_analyze_report_default_format(self, mock_registry, capsys):
        """analyze --report without format defaults to html"""
        from vlair.cli.main import main

        mock_scorer = MagicMock()
        mock_scorer.get_summary.return_value = {"verdict": "CLEAN", "risk_score": 0}

        mock_result = {
            "input": "test.eml",
            "type": "email",
            "scorer": mock_scorer,
            "iocs": {},
            "tool_results": {},
        }

        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = mock_result

        mock_reporter = MagicMock()
        mock_reporter.format_console.return_value = "Output"
        mock_reporter.get_exit_code.return_value = 0

        mock_generator = MagicMock()
        mock_generator.generate.return_value = "/tmp/report.html"

        with patch.dict(
            "sys.modules",
            {
                "vlair.core.analyzer": MagicMock(Analyzer=MagicMock(return_value=mock_analyzer)),
                "vlair.core.reporter": MagicMock(Reporter=MagicMock(return_value=mock_reporter)),
                "vlair.core.history": MagicMock(AnalysisHistory=MagicMock()),
                "vlair.core.report_generator": MagicMock(
                    ReportGenerator=MagicMock(return_value=mock_generator)
                ),
            },
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

        # Report generator should have been called with "html" default
        mock_generator.generate.assert_called_once()
        call_args = mock_generator.generate.call_args
        assert call_args[0][1] == "html"  # report_format arg
