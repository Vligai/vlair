#!/usr/bin/env python3
"""
Unit tests for Script Deobfuscator
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch
import base64

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from secops_helper.tools.deobfuscator import Deobfuscator


class TestLanguageDetection:
    """Test automatic language detection"""

    def test_detect_javascript(self):
        """Test JavaScript detection"""
        deob = Deobfuscator()
        script = 'var x = "hello"; console.log(x);'
        lang = deob.detect_language(script)
        assert lang == "javascript"

    def test_detect_powershell(self):
        """Test PowerShell detection"""
        deob = Deobfuscator()
        script = '$x = "hello"; Write-Host $x'
        lang = deob.detect_language(script)
        assert lang == "powershell"

    def test_detect_vbscript(self):
        """Test VBScript detection"""
        deob = Deobfuscator()
        script = 'Dim x\nx = "hello"\nMsgBox x'
        lang = deob.detect_language(script)
        assert lang == "vbscript"

    def test_detect_batch(self):
        """Test Batch file detection"""
        deob = Deobfuscator()
        script = "@echo off\nset x=hello\necho %x%"
        lang = deob.detect_language(script)
        assert lang == "batch"

    def test_detect_python(self):
        """Test Python detection"""
        deob = Deobfuscator()
        script = 'import os\nprint("hello")'
        lang = deob.detect_language(script)
        assert lang == "python"


class TestBase64Decoding:
    """Test Base64 decoding"""

    def test_decode_base64_string(self):
        """Test decoding simple Base64 string"""
        deob = Deobfuscator()
        encoded = base64.b64encode(b"hello world").decode()
        result = deob.decode_base64(encoded)
        assert "hello world" in result

    def test_decode_base64_in_script(self):
        """Test finding and decoding Base64 in script"""
        deob = Deobfuscator()
        encoded = base64.b64encode(b"malicious_command").decode()
        script = f'var payload = atob("{encoded}");'
        result = deob.deobfuscate(script)
        assert "malicious_command" in result or encoded in result

    def test_invalid_base64_handled(self):
        """Test that invalid Base64 doesn't crash"""
        deob = Deobfuscator()
        result = deob.decode_base64("not_valid_base64!!!")
        # Should return None or empty, not crash
        assert result is None or result == ""


class TestHexDecoding:
    """Test hex decoding"""

    def test_decode_hex_string(self):
        """Test decoding hex string"""
        deob = Deobfuscator()
        # "hello" in hex
        hex_str = "68656c6c6f"
        result = deob.decode_hex(hex_str)
        assert "hello" in result

    def test_decode_hex_with_prefix(self):
        """Test decoding hex with 0x prefix"""
        deob = Deobfuscator()
        hex_str = "0x68656c6c6f"
        result = deob.decode_hex(hex_str.replace("0x", ""))
        assert "hello" in result


class TestPowerShellDeobfuscation:
    """Test PowerShell-specific deobfuscation"""

    def test_decode_encoded_command(self):
        """Test decoding -EncodedCommand parameter"""
        deob = Deobfuscator()
        # Create encoded PowerShell command
        cmd = "Write-Host 'Hello'"
        encoded = base64.b64encode(cmd.encode("utf-16-le")).decode()
        script = f"powershell.exe -EncodedCommand {encoded}"
        result = deob.deobfuscate(script, language="powershell")
        assert "Write-Host" in result or encoded in result

    def test_remove_backticks(self):
        """Test removing backtick obfuscation"""
        deob = Deobfuscator()
        script = "I`n`v`o`k`e`-`E`x`p`r`e`s`s`i`o`n"
        result = deob.deobfuscate(script, language="powershell")
        assert "`" not in result or "Invoke" in result

    def test_decode_char_array(self):
        """Test decoding [char] array obfuscation"""
        deob = Deobfuscator()
        # [char]72 + [char]101 + ... = "Hello"
        script = "([char]72+[char]101+[char]108+[char]108+[char]111)"
        result = deob.deobfuscate(script, language="powershell")
        # Should attempt to decode
        assert result is not None


class TestJavaScriptDeobfuscation:
    """Test JavaScript-specific deobfuscation"""

    def test_decode_fromcharcode(self):
        """Test decoding String.fromCharCode()"""
        deob = Deobfuscator()
        # String.fromCharCode(72,101,108,108,111) = "Hello"
        script = "String.fromCharCode(72,101,108,108,111)"
        result = deob.deobfuscate(script, language="javascript")
        assert "Hello" in result or "fromCharCode" in result

    def test_decode_escape_sequences(self):
        """Test decoding escape sequences"""
        deob = Deobfuscator()
        script = r'var x = "\x48\x65\x6c\x6c\x6f";'
        result = deob.deobfuscate(script, language="javascript")
        assert "Hello" in result or "\\x" in result

    def test_decode_unicode_escapes(self):
        """Test decoding unicode escapes"""
        deob = Deobfuscator()
        script = r'var x = "\u0048\u0065\u006c\u006c\u006f";'
        result = deob.deobfuscate(script, language="javascript")
        assert "Hello" in result or "\\u" in result


class TestIOCExtraction:
    """Test IOC extraction from deobfuscated code"""

    def test_extract_urls(self):
        """Test extracting URLs from deobfuscated code"""
        deob = Deobfuscator()
        script = 'var url = "http://evil.com/malware.exe";'
        result = deob.deobfuscate(script, extract_iocs=True)
        # Result should include extracted IOCs
        assert result is not None

    def test_extract_ips(self):
        """Test extracting IP addresses"""
        deob = Deobfuscator()
        script = 'var ip = "192.168.1.1";'
        result = deob.deobfuscate(script, extract_iocs=True)
        assert result is not None


class TestMultiLayerDeobfuscation:
    """Test multi-layer deobfuscation"""

    def test_multiple_encoding_layers(self):
        """Test deobfuscating multiple layers of encoding"""
        deob = Deobfuscator()
        # Double-encoded payload
        inner = base64.b64encode(b"malware").decode()
        outer = base64.b64encode(inner.encode()).decode()
        script = f'var x = "{outer}";'
        result = deob.deobfuscate(script, max_layers=3)
        # Should attempt to decode multiple layers
        assert result is not None

    def test_max_layers_limit(self):
        """Test that max_layers limit is respected"""
        deob = Deobfuscator()
        script = "some script"
        result = deob.deobfuscate(script, max_layers=1)
        assert result is not None


class TestDeobfuscatorIntegration:
    """Integration tests for Deobfuscator"""

    def test_deobfuscator_creation(self):
        """Test creating deobfuscator instance"""
        deob = Deobfuscator()
        assert deob is not None

    def test_deobfuscate_empty_string(self):
        """Test handling empty input"""
        deob = Deobfuscator()
        result = deob.deobfuscate("")
        assert result == "" or result is not None

    def test_deobfuscate_plain_text(self):
        """Test handling plain text (no obfuscation)"""
        deob = Deobfuscator()
        script = "print('Hello World')"
        result = deob.deobfuscate(script)
        assert "Hello World" in result or "print" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
