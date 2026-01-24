#!/usr/bin/env python3
"""
Unit tests for the secops check command
Tests the quick indicator lookup functionality
"""

import pytest
import sys
import os
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from io import StringIO

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestCheckCommandRouting:
    """Test that check command routes to correct tools"""

    @patch('sys.argv', ['secops.py', 'check'])
    def test_check_no_args_shows_usage(self, capsys):
        """Test that check with no args shows usage"""
        with pytest.raises(SystemExit) as exc_info:
            import importlib
            import secops
            importlib.reload(secops)
            secops.main()
        assert exc_info.value.code == 1

    @patch('sys.argv', ['secops.py', 'check', 'hash'])
    def test_check_hash_no_value_shows_error(self, capsys):
        """Test that check hash with no value shows error"""
        with pytest.raises(SystemExit) as exc_info:
            import importlib
            import secops
            importlib.reload(secops)
            secops.main()
        assert exc_info.value.code == 1

    @patch('sys.argv', ['secops.py', 'check', 'domain'])
    def test_check_domain_no_value_shows_error(self, capsys):
        """Test that check domain with no value shows error"""
        with pytest.raises(SystemExit) as exc_info:
            import importlib
            import secops
            importlib.reload(secops)
            secops.main()
        assert exc_info.value.code == 1

    @patch('sys.argv', ['secops.py', 'check', 'ip'])
    def test_check_ip_no_value_shows_error(self, capsys):
        """Test that check ip with no value shows error"""
        with pytest.raises(SystemExit) as exc_info:
            import importlib
            import secops
            importlib.reload(secops)
            secops.main()
        assert exc_info.value.code == 1

    @patch('sys.argv', ['secops.py', 'check', 'url'])
    def test_check_url_no_value_shows_error(self, capsys):
        """Test that check url with no value shows error"""
        with pytest.raises(SystemExit) as exc_info:
            import importlib
            import secops
            importlib.reload(secops)
            secops.main()
        assert exc_info.value.code == 1

    @patch('sys.argv', ['secops.py', 'check', 'invalid_type', 'something'])
    def test_check_invalid_type_shows_error(self, capsys):
        """Test that invalid check type shows error"""
        with pytest.raises(SystemExit) as exc_info:
            import importlib
            import secops
            importlib.reload(secops)
            secops.main()
        assert exc_info.value.code == 1


class TestCheckHashCommand:
    """Test the check hash subcommand"""

    @patch('hashLookup.lookup.HashLookup')
    @patch('sys.argv', ['secops.py', 'check', 'hash', '44d88612fea8a8f36de82e1278abb02f'])
    def test_check_hash_calls_lookup(self, mock_lookup_class, capsys):
        """Test that check hash calls HashLookup"""
        mock_instance = MagicMock()
        mock_instance.lookup.return_value = {
            'verdict': 'MALICIOUS',
            'detections': 45,
            'total_engines': 70,
            'malware_family': 'Emotet',
            'sources': ['VirusTotal']
        }
        mock_lookup_class.return_value = mock_instance

        # Patch history to avoid file creation
        with patch('core.history.AnalysisHistory'):
            import importlib
            import secops
            importlib.reload(secops)
            try:
                secops.main()
            except SystemExit:
                pass

        mock_instance.lookup.assert_called_once_with('44d88612fea8a8f36de82e1278abb02f')

    @patch('hashLookup.lookup.HashLookup')
    @patch('sys.argv', ['secops.py', 'check', 'hash', '44d88612fea8a8f36de82e1278abb02f', '--json'])
    def test_check_hash_json_output(self, mock_lookup_class, capsys):
        """Test that check hash with --json outputs JSON"""
        mock_instance = MagicMock()
        result_data = {
            'verdict': 'MALICIOUS',
            'detections': 45,
            'total_engines': 70,
            'sources': ['VirusTotal']
        }
        mock_instance.lookup.return_value = result_data
        mock_lookup_class.return_value = mock_instance

        with patch('core.history.AnalysisHistory'):
            import importlib
            import secops
            importlib.reload(secops)
            try:
                secops.main()
            except SystemExit:
                pass

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output['verdict'] == 'MALICIOUS'
        assert output['detections'] == 45

    @patch('hashLookup.lookup.HashLookup')
    @patch('sys.argv', ['secops.py', 'check', 'hash', 'abc123', '--verbose'])
    def test_check_hash_verbose_flag(self, mock_lookup_class):
        """Test that verbose flag is passed to HashLookup"""
        mock_instance = MagicMock()
        mock_instance.lookup.return_value = {'verdict': 'UNKNOWN'}
        mock_lookup_class.return_value = mock_instance

        with patch('core.history.AnalysisHistory'):
            import importlib
            import secops
            importlib.reload(secops)
            try:
                secops.main()
            except SystemExit:
                pass

        mock_lookup_class.assert_called_with(verbose=True)


class TestCheckDomainCommand:
    """Test the check domain subcommand"""

    @patch('domainIpIntel.intel.DomainIPIntelligence')
    @patch('sys.argv', ['secops.py', 'check', 'domain', 'malicious.com'])
    def test_check_domain_calls_intel(self, mock_intel_class, capsys):
        """Test that check domain calls DomainIPIntel"""
        mock_instance = MagicMock()
        mock_instance.lookup.return_value = {
            'verdict': 'SUSPICIOUS',
            'risk_score': 65,
            'dns': {'a_records': ['1.2.3.4']},
            'categories': ['malware']
        }
        mock_intel_class.return_value = mock_instance

        with patch('core.history.AnalysisHistory'):
            import importlib
            import secops
            importlib.reload(secops)
            try:
                secops.main()
            except SystemExit:
                pass

        mock_instance.lookup.assert_called_once_with('malicious.com')

    @patch('domainIpIntel.intel.DomainIPIntelligence')
    @patch('sys.argv', ['secops.py', 'check', 'domain', 'example.com', '--json'])
    def test_check_domain_json_output(self, mock_intel_class, capsys):
        """Test that check domain with --json outputs JSON"""
        mock_instance = MagicMock()
        result_data = {
            'verdict': 'CLEAN',
            'risk_score': 5,
            'dns': {'a_records': ['93.184.216.34']}
        }
        mock_instance.lookup.return_value = result_data
        mock_intel_class.return_value = mock_instance

        with patch('core.history.AnalysisHistory'):
            import importlib
            import secops
            importlib.reload(secops)
            try:
                secops.main()
            except SystemExit:
                pass

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output['verdict'] == 'CLEAN'


class TestCheckIPCommand:
    """Test the check ip subcommand"""

    @patch('domainIpIntel.intel.DomainIPIntelligence')
    @patch('sys.argv', ['secops.py', 'check', 'ip', '192.168.1.1'])
    def test_check_ip_calls_intel(self, mock_intel_class, capsys):
        """Test that check ip calls DomainIPIntel"""
        mock_instance = MagicMock()
        mock_instance.lookup.return_value = {
            'verdict': 'CLEAN',
            'risk_score': 0,
            'abuse_confidence_score': 0,
            'country': 'US'
        }
        mock_intel_class.return_value = mock_instance

        with patch('core.history.AnalysisHistory'):
            import importlib
            import secops
            importlib.reload(secops)
            try:
                secops.main()
            except SystemExit:
                pass

        mock_instance.lookup.assert_called_once_with('192.168.1.1')

    @patch('domainIpIntel.intel.DomainIPIntelligence')
    @patch('sys.argv', ['secops.py', 'check', 'ip', '8.8.8.8'])
    def test_check_ip_displays_abuse_score(self, mock_intel_class, capsys):
        """Test that IP check displays abuse score"""
        mock_instance = MagicMock()
        mock_instance.lookup.return_value = {
            'verdict': 'SUSPICIOUS',
            'risk_score': 45,
            'abuse_confidence_score': 67,
            'country': 'RU'
        }
        mock_intel_class.return_value = mock_instance

        with patch('core.history.AnalysisHistory'):
            import importlib
            import secops
            importlib.reload(secops)
            try:
                secops.main()
            except SystemExit:
                pass

        captured = capsys.readouterr()
        assert 'Abuse Score: 67%' in captured.out
        assert 'Country: RU' in captured.out


class TestCheckURLCommand:
    """Test the check url subcommand"""

    @patch('urlAnalyzer.analyzer.URLAnalyzer')
    @patch('sys.argv', ['secops.py', 'check', 'url', 'http://evil.com/payload'])
    def test_check_url_calls_analyzer(self, mock_analyzer_class, capsys):
        """Test that check url calls URLAnalyzer"""
        mock_instance = MagicMock()
        mock_instance.analyze.return_value = {
            'verdict': 'MALICIOUS',
            'risk_score': 90,
            'threats': ['Known phishing URL', 'Suspicious TLD']
        }
        mock_analyzer_class.return_value = mock_instance

        with patch('core.history.AnalysisHistory'):
            import importlib
            import secops
            importlib.reload(secops)
            try:
                secops.main()
            except SystemExit:
                pass

        mock_instance.analyze.assert_called_once_with('http://evil.com/payload')

    @patch('urlAnalyzer.analyzer.URLAnalyzer')
    @patch('sys.argv', ['secops.py', 'check', 'url', 'http://safe.com'])
    def test_check_url_displays_threats(self, mock_analyzer_class, capsys):
        """Test that URL check displays threat details"""
        mock_instance = MagicMock()
        mock_instance.analyze.return_value = {
            'verdict': 'MALICIOUS',
            'risk_score': 85,
            'threats': ['Known malware distribution', 'Recently registered domain']
        }
        mock_analyzer_class.return_value = mock_instance

        with patch('core.history.AnalysisHistory'):
            import importlib
            import secops
            importlib.reload(secops)
            try:
                secops.main()
            except SystemExit:
                pass

        captured = capsys.readouterr()
        assert 'Known malware distribution' in captured.out
        assert 'Recently registered domain' in captured.out


class TestCheckFileInput:
    """Test the check command with file input"""

    @patch('core.analyzer.Analyzer')
    def test_check_with_file_uses_analyzer(self, mock_analyzer_class, capsys):
        """Test that check with a file path uses the full analyzer"""
        # Create a temp file
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False, mode='w') as f:
            f.write("192.168.1.1\nmalicious.com\n")
            temp_path = f.name

        try:
            mock_instance = MagicMock()
            mock_scorer = MagicMock()
            mock_scorer.get_summary.return_value = {'verdict': 'SUSPICIOUS', 'risk_score': 50}
            mock_instance.analyze.return_value = {
                'input': temp_path,
                'type': 'ioc_list',
                'scorer': mock_scorer,
                'iocs': {'hashes': [], 'domains': ['malicious.com'], 'ips': ['192.168.1.1'], 'urls': [], 'emails': []},
                'tool_results': {}
            }
            mock_analyzer_class.return_value = mock_instance

            with patch('sys.argv', ['secops.py', 'check', temp_path]):
                with patch('core.history.AnalysisHistory'):
                    import importlib
                    import secops
                    importlib.reload(secops)
                    try:
                        secops.main()
                    except SystemExit:
                        pass

            mock_instance.analyze.assert_called_once_with(temp_path)
        finally:
            os.unlink(temp_path)


class TestCheckHistoryRecording:
    """Test that check command records to history"""

    @patch('hashLookup.lookup.HashLookup')
    @patch('sys.argv', ['secops.py', 'check', 'hash', 'abc123'])
    def test_check_records_history(self, mock_lookup_class):
        """Test that a check operation is recorded in history"""
        mock_instance = MagicMock()
        mock_instance.lookup.return_value = {
            'verdict': 'CLEAN',
            'risk_score': 0
        }
        mock_lookup_class.return_value = mock_instance

        with patch('core.history.AnalysisHistory') as mock_history_class:
            mock_history_instance = MagicMock()
            mock_history_class.return_value = mock_history_instance

            import importlib
            import secops
            importlib.reload(secops)
            try:
                secops.main()
            except SystemExit:
                pass

            mock_history_instance.record.assert_called_once()
            call_kwargs = mock_history_instance.record.call_args
            assert call_kwargs[1]['command'] == 'check' or call_kwargs[0][4] == 'check' if call_kwargs[0] else call_kwargs[1]['command'] == 'check'


class TestCheckConsoleOutput:
    """Test console output formatting for check command"""

    @patch('hashLookup.lookup.HashLookup')
    @patch('sys.argv', ['secops.py', 'check', 'hash', '44d88612fea8a8f36de82e1278abb02f'])
    def test_hash_output_shows_verdict(self, mock_lookup_class, capsys):
        """Test that hash check shows verdict in output"""
        mock_instance = MagicMock()
        mock_instance.lookup.return_value = {
            'verdict': 'MALICIOUS',
            'detections': 50,
            'total_engines': 70,
            'malware_family': 'Emotet',
            'sources': ['VirusTotal', 'MalwareBazaar']
        }
        mock_lookup_class.return_value = mock_instance

        with patch('core.history.AnalysisHistory'):
            import importlib
            import secops
            importlib.reload(secops)
            try:
                secops.main()
            except SystemExit:
                pass

        captured = capsys.readouterr()
        assert 'MALICIOUS' in captured.out
        assert '50/70' in captured.out
        assert 'Emotet' in captured.out
        assert 'VirusTotal' in captured.out

    @patch('domainIpIntel.intel.DomainIPIntelligence')
    @patch('sys.argv', ['secops.py', 'check', 'domain', 'example.com'])
    def test_domain_output_shows_risk_score(self, mock_intel_class, capsys):
        """Test that domain check shows risk score"""
        mock_instance = MagicMock()
        mock_instance.lookup.return_value = {
            'verdict': 'CLEAN',
            'risk_score': 5,
            'dns': {'a_records': ['93.184.216.34', '93.184.216.35']},
            'categories': []
        }
        mock_intel_class.return_value = mock_instance

        with patch('core.history.AnalysisHistory'):
            import importlib
            import secops
            importlib.reload(secops)
            try:
                secops.main()
            except SystemExit:
                pass

        captured = capsys.readouterr()
        assert 'CLEAN' in captured.out
        assert '5/100' in captured.out
        assert '93.184.216.34' in captured.out
