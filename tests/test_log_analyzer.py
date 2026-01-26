#!/usr/bin/env python3
"""
Unit tests for Log Analyzer
"""

import pytest
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from logAnalysis.analyzer import (
    ApacheLogParser,
    SyslogParser,
    ThreatDetector,
    LogAnalyzer,
    format_output_json,
    format_output_csv,
    format_output_text,
)


class TestApacheLogParser:
    """Test Apache/Nginx log parsing"""

    def test_parse_valid_log_line(self):
        """Test parsing valid Apache log line"""
        parser = ApacheLogParser()
        line = (
            '192.0.2.1 - - [18/Nov/2025:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "http://example.com" "Mozilla/5.0"'
        )

        result = parser.parse_line(line)

        assert result is not None
        assert result["source_ip"] == "192.0.2.1"
        assert result["method"] == "GET"
        assert result["path"] == "/index.html"
        assert result["status"] == 200
        assert result["log_type"] == "apache"

    def test_parse_post_request(self):
        """Test parsing POST request"""
        parser = ApacheLogParser()
        line = '198.51.100.25 - - [18/Nov/2025:10:15:00 +0000] "POST /login.php HTTP/1.1" 302 512 "-" "curl/7.68.0"'

        result = parser.parse_line(line)

        assert result["method"] == "POST"
        assert result["path"] == "/login.php"
        assert result["status"] == 302

    def test_parse_with_attack_pattern(self):
        """Test parsing log with SQL injection pattern"""
        parser = ApacheLogParser()
        line = '203.0.113.100 - - [18/Nov/2025:11:00:00 +0000] "GET /search.php?q=1\'+OR+1=1-- HTTP/1.1" 200 5678 "-" "sqlmap/1.0"'

        result = parser.parse_line(line)

        assert result is not None
        assert "OR" in result["path"]
        assert "sqlmap" in result["user_agent"]

    def test_parse_invalid_line(self):
        """Test parsing invalid log line"""
        parser = ApacheLogParser()
        line = "This is not a valid log line"

        result = parser.parse_line(line)

        assert result is None

    def test_parse_404_error(self):
        """Test parsing 404 error"""
        parser = ApacheLogParser()
        line = '192.0.2.50 - - [18/Nov/2025:12:00:00 +0000] "GET /admin/config.php HTTP/1.1" 404 196 "-" "nikto/2.1.6"'

        result = parser.parse_line(line)

        assert result["status"] == 404
        assert "nikto" in result["user_agent"]


class TestSyslogParser:
    """Test Syslog parsing"""

    def test_parse_valid_syslog_line(self):
        """Test parsing valid syslog line"""
        parser = SyslogParser()
        line = "Nov 18 10:00:00 server1 sshd[12345]: Failed password for invalid user admin from 203.0.113.100 port 22 ssh2"

        result = parser.parse_line(line)

        assert result is not None
        assert result["host"] == "server1"
        assert result["process"] == "sshd"
        assert result["pid"] == "12345"
        assert "Failed password" in result["message"]
        assert result["log_type"] == "syslog"

    def test_parse_auth_failure(self):
        """Test parsing authentication failure"""
        parser = SyslogParser()
        line = "Nov 18 10:05:00 server1 sshd[12346]: authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.100"

        result = parser.parse_line(line)

        assert result is not None
        assert "authentication failure" in result["message"]
        assert result["process"] == "sshd"

    def test_parse_without_pid(self):
        """Test parsing syslog line without PID"""
        parser = SyslogParser()
        line = "Nov 18 10:10:00 server1 kernel: Out of memory: Kill process 1234"

        result = parser.parse_line(line)

        assert result is not None
        assert result["process"] == "kernel"
        assert result["pid"] is None

    def test_parse_invalid_syslog(self):
        """Test parsing invalid syslog line"""
        parser = SyslogParser()
        line = "This is not a valid syslog line"

        result = parser.parse_line(line)

        assert result is None


class TestThreatDetector:
    """Test threat detection"""

    def test_detect_sql_injection_union(self):
        """Test SQL injection detection - UNION SELECT"""
        detector = ThreatDetector()

        assert detector.detect_sql_injection("search.php?q=' UNION SELECT * FROM users--") is True
        assert detector.detect_sql_injection("search.php?q=test") is False

    def test_detect_sql_injection_or_equals(self):
        """Test SQL injection detection - OR 1=1"""
        detector = ThreatDetector()

        assert detector.detect_sql_injection("login.php?user=admin' OR 1=1--") is True
        assert detector.detect_sql_injection("profile.php?id=123") is False

    def test_detect_sql_injection_drop_table(self):
        """Test SQL injection detection - DROP TABLE"""
        detector = ThreatDetector()

        assert detector.detect_sql_injection("'; DROP TABLE users; --") is True

    def test_detect_xss_script_tag(self):
        """Test XSS detection - script tag"""
        detector = ThreatDetector()

        assert detector.detect_xss("<script>alert('XSS')</script>") is True
        assert detector.detect_xss("<div>Normal content</div>") is False

    def test_detect_xss_javascript(self):
        """Test XSS detection - javascript: protocol"""
        detector = ThreatDetector()

        assert detector.detect_xss("javascript:alert(1)") is True

    def test_detect_xss_event_handler(self):
        """Test XSS detection - event handlers"""
        detector = ThreatDetector()

        assert detector.detect_xss("<img src=x onerror=alert(1)>") is True
        assert detector.detect_xss("<body onload=alert(1)>") is True

    def test_detect_xss_iframe(self):
        """Test XSS detection - iframe"""
        detector = ThreatDetector()

        assert detector.detect_xss('<iframe src="http://evil.com"></iframe>') is True

    def test_detect_path_traversal_dotdot(self):
        """Test path traversal detection - ../"""
        detector = ThreatDetector()

        assert detector.detect_path_traversal("../../etc/passwd") is True
        assert detector.detect_path_traversal("/var/www/html/page.html") is False

    def test_detect_path_traversal_windows(self):
        """Test path traversal detection - Windows paths"""
        detector = ThreatDetector()

        assert detector.detect_path_traversal("..\\..\\windows\\system32") is True
        assert detector.detect_path_traversal("c:\\windows\\system32\\config") is True

    def test_detect_path_traversal_etc_passwd(self):
        """Test path traversal detection - /etc/passwd"""
        detector = ThreatDetector()

        assert detector.detect_path_traversal("/etc/passwd") is True
        assert detector.detect_path_traversal("/etc/shadow") is True

    def test_detect_brute_force_failed_password(self):
        """Test brute force detection - failed password"""
        detector = ThreatDetector()

        assert detector.detect_brute_force("Failed password for user from 203.0.113.100") is True
        assert detector.detect_brute_force("Successful login for user") is False

    def test_detect_brute_force_auth_failure(self):
        """Test brute force detection - authentication failure"""
        detector = ThreatDetector()

        assert detector.detect_brute_force("authentication failure for user admin") is True

    def test_detect_brute_force_invalid_user(self):
        """Test brute force detection - invalid user"""
        detector = ThreatDetector()

        assert detector.detect_brute_force("Invalid user admin from 203.0.113.100") is True

    def test_analyze_web_log_sql_injection(self):
        """Test web log analysis for SQL injection"""
        detector = ThreatDetector()

        entry = {
            "path": "/search?q=' UNION SELECT password FROM users--",
            "user_agent": "Mozilla/5.0",
            "source_ip": "203.0.113.100",
            "status": 200,
            "timestamp": datetime.now(),
        }

        alerts = detector.analyze_web_log(entry)

        assert len(alerts) > 0
        assert any(alert["type"] == "sql_injection" for alert in alerts)
        assert any(alert["severity"] == "high" for alert in alerts)

    def test_analyze_web_log_xss(self):
        """Test web log analysis for XSS"""
        detector = ThreatDetector()

        entry = {
            "path": "/comment?text=<script>alert('XSS')</script>",
            "user_agent": "Mozilla/5.0",
            "source_ip": "198.51.100.25",
            "status": 200,
            "timestamp": datetime.now(),
        }

        alerts = detector.analyze_web_log(entry)

        assert len(alerts) > 0
        assert any(alert["type"] == "xss" for alert in alerts)

    def test_analyze_web_log_path_traversal(self):
        """Test web log analysis for path traversal"""
        detector = ThreatDetector()

        entry = {
            "path": "/../../../etc/passwd",
            "user_agent": "curl/7.68.0",
            "source_ip": "192.0.2.50",
            "status": 403,
            "timestamp": datetime.now(),
        }

        alerts = detector.analyze_web_log(entry)

        assert len(alerts) > 0
        assert any(alert["type"] == "path_traversal" for alert in alerts)

    def test_analyze_web_log_scanner_detection(self):
        """Test web log analysis for security scanners"""
        detector = ThreatDetector()

        entry = {
            "path": "/admin/",
            "user_agent": "sqlmap/1.4.7",
            "source_ip": "203.0.113.100",
            "status": 404,
            "timestamp": datetime.now(),
        }

        alerts = detector.analyze_web_log(entry)

        assert len(alerts) > 0
        assert any(alert["type"] == "scanner_detected" for alert in alerts)
        assert any(alert["type"] == "404_scan" for alert in alerts)

    def test_analyze_web_log_clean(self):
        """Test web log analysis with clean request"""
        detector = ThreatDetector()

        entry = {
            "path": "/index.html",
            "user_agent": "Mozilla/5.0",
            "source_ip": "8.8.8.8",
            "status": 200,
            "timestamp": datetime.now(),
        }

        alerts = detector.analyze_web_log(entry)

        # Should not have high-severity alerts
        assert not any(alert["severity"] == "high" for alert in alerts)

    def test_analyze_auth_log_brute_force(self):
        """Test auth log analysis for brute force"""
        detector = ThreatDetector()

        entry = {
            "message": "Failed password for invalid user admin from 203.0.113.100 port 22 ssh2",
            "host": "server1",
            "timestamp": datetime.now(),
        }

        alerts = detector.analyze_auth_log(entry)

        assert len(alerts) > 0
        assert alerts[0]["type"] == "brute_force_attempt"

    def test_analyze_auth_log_clean(self):
        """Test auth log analysis with normal message"""
        detector = ThreatDetector()

        entry = {"message": "Session opened for user john", "host": "server1", "timestamp": datetime.now()}

        alerts = detector.analyze_auth_log(entry)

        assert len(alerts) == 0


class TestLogAnalyzer:
    """Test main log analyzer"""

    def test_init(self):
        """Test analyzer initialization"""
        analyzer = LogAnalyzer(verbose=False)

        assert analyzer.verbose is False
        assert analyzer.detector is not None
        assert "apache" in analyzer.parsers
        assert "syslog" in analyzer.parsers

    def test_detect_format_apache(self):
        """Test Apache log format detection"""
        analyzer = LogAnalyzer()

        lines = ['192.0.2.1 - - [18/Nov/2025:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"']

        format_type = analyzer.detect_format(lines)
        assert format_type == "apache"

    def test_detect_format_syslog(self):
        """Test Syslog format detection"""
        analyzer = LogAnalyzer()

        lines = ["Nov 18 10:00:00 server1 sshd[12345]: Failed password for user admin"]

        format_type = analyzer.detect_format(lines)
        assert format_type == "syslog"

    def test_detect_format_unknown(self):
        """Test unknown format detection"""
        analyzer = LogAnalyzer()

        lines = ["This is not a recognized log format", "Random text here"]

        format_type = analyzer.detect_format(lines)
        assert format_type == "unknown"

    def test_analyze_file_not_found(self):
        """Test analyzing nonexistent file"""
        analyzer = LogAnalyzer()

        result = analyzer.analyze_file("/nonexistent/file.log")

        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_analyze_apache_log_file(self):
        """Test analyzing Apache log file"""
        analyzer = LogAnalyzer()

        test_file = Path(__file__).parent / "test_data" / "log_samples" / "apache_attacks.log"

        if not test_file.exists():
            pytest.skip("Test log file not found")

        result = analyzer.analyze_file(str(test_file), log_type="apache")

        assert "error" not in result
        assert "metadata" in result
        assert "alerts" in result
        assert result["metadata"]["log_type"] == "apache"
        assert result["metadata"]["total_entries"] > 0

    def test_analyze_auth_log_file(self):
        """Test analyzing authentication log file"""
        analyzer = LogAnalyzer()

        test_file = Path(__file__).parent / "test_data" / "log_samples" / "auth_brute_force.log"

        if not test_file.exists():
            pytest.skip("Test log file not found")

        result = analyzer.analyze_file(str(test_file), log_type="syslog")

        assert "error" not in result
        assert "metadata" in result
        assert result["metadata"]["log_type"] == "syslog"

    def test_count_by_type(self):
        """Test alert counting by type"""
        analyzer = LogAnalyzer()

        alerts = [
            {"type": "sql_injection", "severity": "high"},
            {"type": "sql_injection", "severity": "high"},
            {"type": "xss", "severity": "medium"},
            {"type": "path_traversal", "severity": "high"},
        ]

        result = analyzer._count_by_type(alerts)

        assert result["sql_injection"] == 2
        assert result["xss"] == 1
        assert result["path_traversal"] == 1

    def test_count_by_severity(self):
        """Test alert counting by severity"""
        analyzer = LogAnalyzer()

        alerts = [
            {"type": "sql_injection", "severity": "high"},
            {"type": "xss", "severity": "medium"},
            {"type": "path_traversal", "severity": "high"},
            {"type": "404_scan", "severity": "low"},
        ]

        result = analyzer._count_by_severity(alerts)

        assert result["high"] == 2
        assert result["medium"] == 1
        assert result["low"] == 1

    def test_generate_statistics_web_logs(self):
        """Test statistics generation for web logs"""
        analyzer = LogAnalyzer()

        entries = [
            {"source_ip": "192.0.2.1", "path": "/index.html", "status": 200, "user_agent": "Mozilla/5.0"},
            {"source_ip": "192.0.2.1", "path": "/about.html", "status": 200, "user_agent": "Mozilla/5.0"},
            {"source_ip": "198.51.100.25", "path": "/index.html", "status": 404, "user_agent": "curl/7.68.0"},
        ]

        stats = analyzer._generate_statistics(entries, "apache")

        assert "top_ips" in stats
        assert "top_paths" in stats
        assert "status_codes" in stats
        assert stats["total_requests"] == 3

    def test_generate_statistics_syslog(self):
        """Test statistics generation for syslog"""
        analyzer = LogAnalyzer()

        entries = [
            {"host": "server1", "process": "sshd"},
            {"host": "server1", "process": "sshd"},
            {"host": "server2", "process": "kernel"},
        ]

        stats = analyzer._generate_statistics(entries, "syslog")

        assert "top_hosts" in stats
        assert "top_processes" in stats
        assert stats["total_events"] == 3


class TestFormatOutput:
    """Test output formatting"""

    def test_format_output_json(self):
        """Test JSON output formatting"""
        results = {"metadata": {"log_file": "test.log", "total_entries": 10}, "alerts": []}

        output = format_output_json(results)

        assert "test.log" in output
        assert "total_entries" in output
        # Should be valid JSON
        import json

        parsed = json.loads(output)
        assert parsed["metadata"]["total_entries"] == 10

    def test_format_output_csv(self):
        """Test CSV output formatting"""
        results = {
            "alerts": [
                {
                    "type": "sql_injection",
                    "severity": "high",
                    "description": "SQL injection attempt",
                    "source_ip": "203.0.113.100",
                    "timestamp": "2025-11-18T10:00:00",
                }
            ]
        }

        output = format_output_csv(results)

        lines = output.split("\n")
        assert "Type,Severity,Description" in lines[0]
        assert "sql_injection" in lines[1]
        assert "high" in lines[1]

    def test_format_output_text(self):
        """Test text output formatting"""
        results = {
            "metadata": {
                "log_file": "test.log",
                "log_type": "apache",
                "total_entries": 100,
                "total_alerts": 5,
                "analysis_date": "2025-11-18T10:00:00",
            },
            "summary": {"alerts_by_type": {"sql_injection": 3, "xss": 2}, "alerts_by_severity": {"high": 3, "medium": 2}},
            "statistics": {"total_requests": 100},
            "alerts": [],
        }

        output = format_output_text(results)

        assert "LOG ANALYSIS REPORT" in output
        assert "test.log" in output
        assert "sql_injection: 3" in output
        assert "high: 3" in output


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
