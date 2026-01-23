#!/usr/bin/env python3
"""
Unit tests for Interactive Investigation Mode
Tests menus, prompts, and user interactions
"""

import pytest
import sys
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from io import StringIO

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.interactive import InteractiveInvestigation, ProgressBar
from core.reporter import Colors


class TestProgressBar:
    """Test ProgressBar functionality"""

    def test_progress_bar_creation(self):
        """Test creating a progress bar"""
        bar = ProgressBar(total=100, width=40)
        assert bar.total == 100
        assert bar.width == 40
        assert bar.current == 0

    def test_progress_bar_update(self):
        """Test updating progress bar"""
        bar = ProgressBar(total=100)
        bar.update(50)
        assert bar.current == 50

    def test_progress_bar_max(self):
        """Test that progress doesn't exceed total"""
        bar = ProgressBar(total=100)
        bar.update(150)  # Exceeds total
        assert bar.current == 100

    def test_progress_bar_complete(self):
        """Test completing progress bar"""
        bar = ProgressBar(total=100)
        bar.complete()
        assert bar.current == 100


class TestInvestigationTypes:
    """Test investigation type definitions"""

    def test_investigation_types_exist(self):
        """Test that all investigation types are defined"""
        investigation = InteractiveInvestigation()
        types = investigation.INVESTIGATION_TYPES

        assert len(types) >= 6

    def test_investigation_type_structure(self):
        """Test investigation type structure"""
        investigation = InteractiveInvestigation()

        for inv_type in investigation.INVESTIGATION_TYPES:
            assert 'id' in inv_type
            assert 'name' in inv_type
            assert 'description' in inv_type
            assert 'input_prompt' in inv_type
            assert 'file_required' in inv_type

    def test_email_investigation_type(self):
        """Test email investigation type"""
        investigation = InteractiveInvestigation()

        email_type = next(
            (t for t in investigation.INVESTIGATION_TYPES if t['id'] == 'email'),
            None
        )

        assert email_type is not None
        assert email_type['workflow'] == 'phishing-email'
        assert email_type['file_required'] == True

    def test_indicator_investigation_type(self):
        """Test indicator investigation type (no workflow)"""
        investigation = InteractiveInvestigation()

        indicator_type = next(
            (t for t in investigation.INVESTIGATION_TYPES if t['id'] == 'indicator'),
            None
        )

        assert indicator_type is not None
        assert indicator_type['workflow'] is None
        assert indicator_type['file_required'] == False


class TestInteractiveInvestigationInit:
    """Test InteractiveInvestigation initialization"""

    def test_investigation_creation(self):
        """Test creating an investigation instance"""
        investigation = InteractiveInvestigation()
        assert investigation is not None
        assert investigation.analyzer is not None
        assert investigation.reporter is not None


class TestVerdictColors:
    """Test verdict color mapping"""

    def test_get_verdict_color(self):
        """Test getting colors for verdicts"""
        investigation = InteractiveInvestigation()
        Colors.enable()  # Re-enable after Reporter init disables them

        # Test each verdict
        malicious_color = investigation._get_verdict_color('MALICIOUS')
        assert malicious_color != ''  # Should have a color

        clean_color = investigation._get_verdict_color('CLEAN')
        assert clean_color != ''

        unknown_color = investigation._get_verdict_color('UNKNOWN')
        # Unknown might have dim color or empty

    def test_unknown_verdict_color(self):
        """Test color for unknown verdict"""
        investigation = InteractiveInvestigation()
        color = investigation._get_verdict_color('NONEXISTENT')
        # Should return empty string for unknown
        assert color == ''


class TestScoreDisplay:
    """Test score display functions"""

    def test_score_bar(self):
        """Test score bar generation"""
        investigation = InteractiveInvestigation()

        bar = investigation._score_bar(50)
        assert '[' in bar
        assert ']' in bar
        assert '█' in bar or '░' in bar

    def test_score_label_high(self):
        """Test high risk label"""
        investigation = InteractiveInvestigation()
        label = investigation._score_label(80)
        assert 'HIGH' in label.upper()

    def test_score_label_medium(self):
        """Test medium risk label"""
        investigation = InteractiveInvestigation()
        label = investigation._score_label(50)
        assert 'MEDIUM' in label.upper()

    def test_score_label_low(self):
        """Test low risk label"""
        investigation = InteractiveInvestigation()
        label = investigation._score_label(20)
        assert 'LOW' in label.upper()

    def test_score_label_minimal(self):
        """Test minimal risk label"""
        investigation = InteractiveInvestigation()
        label = investigation._score_label(5)
        assert 'MINIMAL' in label.upper()


class TestSeverityIcons:
    """Test severity icon display"""

    def test_severity_icon_critical(self):
        """Test critical severity icon"""
        investigation = InteractiveInvestigation()
        icon = investigation._severity_icon('critical')
        assert '[!' in icon or '!' in icon

    def test_severity_icon_high(self):
        """Test high severity icon"""
        investigation = InteractiveInvestigation()
        icon = investigation._severity_icon('high')
        assert '[!' in icon or '!' in icon

    def test_severity_icon_medium(self):
        """Test medium severity icon"""
        investigation = InteractiveInvestigation()
        icon = investigation._severity_icon('medium')
        assert '*' in icon

    def test_severity_icon_unknown(self):
        """Test unknown severity icon"""
        investigation = InteractiveInvestigation()
        icon = investigation._severity_icon('nonexistent')
        assert '?' in icon


class TestExportIOCs:
    """Test IOC export functionality"""

    def test_export_iocs(self):
        """Test exporting IOCs to file"""
        investigation = InteractiveInvestigation()

        # Create mock analysis result
        mock_result = {
            'type': 'analyze',
            'result': {
                'iocs': {
                    'hashes': ['abc123', 'def456'],
                    'domains': ['evil.com'],
                    'ips': ['1.2.3.4'],
                    'urls': [],
                    'emails': []
                },
                'scorer': MagicMock()
            }
        }

        # Create temp file for export
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            temp_path = f.name

        try:
            # Mock input to return temp path
            with patch('builtins.input', return_value=temp_path):
                investigation._export_iocs(mock_result)

            # Verify file was created and has content
            with open(temp_path, 'r') as f:
                content = f.read()

            assert 'abc123' in content
            assert 'evil.com' in content
            assert '1.2.3.4' in content

        finally:
            os.unlink(temp_path)


class TestMenuSelection:
    """Test menu selection logic"""

    def test_select_investigation_exit(self):
        """Test selecting exit option"""
        investigation = InteractiveInvestigation()

        with patch('builtins.input', return_value='0'):
            result = investigation._select_investigation_type()
            assert result is None

    def test_select_investigation_valid(self):
        """Test selecting valid option"""
        investigation = InteractiveInvestigation()

        with patch('builtins.input', return_value='1'):
            result = investigation._select_investigation_type()
            assert result is not None
            assert result['id'] == 'email'

    def test_select_investigation_invalid(self):
        """Test invalid selection followed by exit"""
        investigation = InteractiveInvestigation()

        # First return invalid, then exit
        inputs = iter(['99', '0'])
        with patch('builtins.input', lambda _: next(inputs)):
            result = investigation._select_investigation_type()
            assert result is None


class TestInputValidation:
    """Test input validation"""

    def test_get_input_file_exists(self):
        """Test getting input for existing file"""
        investigation = InteractiveInvestigation()

        inv_type = {
            'input_prompt': 'Enter file:',
            'file_required': True
        }

        # Create temp file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        try:
            with patch('builtins.input', return_value=temp_path):
                result = investigation._get_input(inv_type)
                assert result is not None
                assert Path(result).exists()
        finally:
            os.unlink(temp_path)

    def test_get_input_file_not_exists(self):
        """Test getting input for non-existent file (should keep prompting)"""
        investigation = InteractiveInvestigation()

        inv_type = {
            'input_prompt': 'Enter file:',
            'file_required': True
        }

        # Create temp file for second input
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        try:
            # First input is invalid, second is valid
            inputs = iter(['/nonexistent/path', temp_path])
            with patch('builtins.input', lambda _: next(inputs)):
                result = investigation._get_input(inv_type)
                assert result is not None
        finally:
            os.unlink(temp_path)

    def test_get_input_no_file_required(self):
        """Test getting input when file is not required"""
        investigation = InteractiveInvestigation()

        inv_type = {
            'input_prompt': 'Enter indicator:',
            'file_required': False
        }

        with patch('builtins.input', return_value='malicious.com'):
            result = investigation._get_input(inv_type)
            assert result == 'malicious.com'

    def test_get_input_quoted_path(self):
        """Test handling quoted paths"""
        investigation = InteractiveInvestigation()

        inv_type = {
            'input_prompt': 'Enter indicator:',
            'file_required': False
        }

        with patch('builtins.input', return_value='"malicious.com"'):
            result = investigation._get_input(inv_type)
            assert result == 'malicious.com'


class TestPostAnalysisMenu:
    """Test post-analysis menu"""

    def test_post_analysis_exit(self):
        """Test selecting exit from post-analysis menu"""
        investigation = InteractiveInvestigation()

        mock_result = {
            'type': 'analyze',
            'result': {
                'iocs': {},
                'scorer': MagicMock()
            }
        }

        with patch('builtins.input', return_value='4'):
            result = investigation._post_analysis_menu(mock_result)
            assert result == False

    def test_post_analysis_new_investigation(self):
        """Test selecting new investigation"""
        investigation = InteractiveInvestigation()

        mock_result = {
            'type': 'analyze',
            'result': {
                'iocs': {},
                'scorer': MagicMock()
            }
        }

        with patch('builtins.input', return_value='3'):
            result = investigation._post_analysis_menu(mock_result)
            assert result == True


class TestRunAnalysis:
    """Test analysis execution"""

    def test_run_analysis_with_analyzer(self):
        """Test running analysis with analyzer (not workflow)"""
        investigation = InteractiveInvestigation()

        inv_type = {
            'id': 'indicator',
            'workflow': None
        }

        # Mock the analyzer
        mock_result = {
            'input': 'example.com',
            'type': 'domain',
            'scorer': MagicMock(),
            'iocs': {},
            'tool_results': {}
        }
        investigation.analyzer.analyze = MagicMock(return_value=mock_result)

        result = investigation._run_analysis(inv_type, 'example.com')

        assert result is not None
        assert result['type'] == 'analyze'

    def test_run_analysis_with_workflow(self):
        """Test running analysis with workflow"""
        investigation = InteractiveInvestigation()

        inv_type = {
            'id': 'iocs',
            'workflow': 'ioc-hunt'
        }

        # Create temp IOC file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('example.com\n')
            temp_path = f.name

        try:
            result = investigation._run_analysis(inv_type, temp_path)
            # May succeed or fail depending on tool availability
            # Just verify it doesn't crash
        finally:
            os.unlink(temp_path)


class TestPrintFunctions:
    """Test print functions don't crash"""

    def test_print_header(self):
        """Test printing header"""
        investigation = InteractiveInvestigation()
        # Should not raise
        investigation._print_header()

    def test_print_goodbye(self):
        """Test printing goodbye"""
        investigation = InteractiveInvestigation()
        # Should not raise
        investigation._print_goodbye()
