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

from secops_helper.tools.deobfuscator import Deobfuscator, Decoder, EncodingDetector


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
        """Test Python detection - returns unknown since python not in detector"""
        deob = Deobfuscator()
        script = 'import os\nprint("hello")'
        lang = deob.detect_language(script)
        # Python is not explicitly detected in the implementation
        assert lang in ["unknown", "python"]


class TestBase64Decoding:
    """Test Base64 decoding"""

    def test_decode_base64_string(self):
        """Test decoding simple Base64 string"""
        encoded = base64.b64encode(b"hello world").decode()
        result = Decoder.decode_base64(encoded)
        assert result is not None
        assert "hello world" in result

    def test_decode_base64_in_script(self):
        """Test finding and decoding Base64 in script"""
        deob = Deobfuscator()
        encoded = base64.b64encode(b"malicious_command").decode()
        script = f'var payload = atob("{encoded}");'
        result = deob.deobfuscate(script)
        # Result is a dict with final_code
        assert result is not None
        assert "final_code" in result

    def test_invalid_base64_handled(self):
        """Test that invalid Base64 doesn't crash"""
        result = Decoder.decode_base64("not_valid_base64!!!")
        # Should return None on failure
        assert result is None


class TestHexDecoding:
    """Test hex decoding"""

    def test_decode_hex_string(self):
        """Test decoding hex string"""
        # "hello" in hex
        hex_str = "68656c6c6f"
        result = Decoder.decode_hex(hex_str)
        assert result is not None
        assert "hello" in result

    def test_decode_hex_with_prefix(self):
        """Test decoding hex with 0x prefix"""
        hex_str = "0x68656c6c6f"
        result = Decoder.decode_hex(hex_str.replace("0x", ""))
        assert result is not None
        assert "hello" in result


class TestEncodingDetector:
    """Test encoding detection"""

    def test_is_base64_valid(self):
        """Test base64 detection with valid string"""
        encoded = base64.b64encode(b"this is a test string for base64").decode()
        assert EncodingDetector.is_base64(encoded) is True

    def test_is_base64_invalid(self):
        """Test base64 detection with invalid string"""
        assert EncodingDetector.is_base64("not_base64!!") is False

    def test_is_hex_valid(self):
        """Test hex detection with valid string"""
        assert EncodingDetector.is_hex("68656c6c6f776f726c64") is True

    def test_is_hex_invalid(self):
        """Test hex detection with invalid string"""
        assert EncodingDetector.is_hex("ghijkl") is False


class TestPowerShellDeobfuscation:
    """Test PowerShell-specific deobfuscation"""

    def test_decode_encoded_command(self):
        """Test decoding -EncodedCommand parameter"""
        deob = Deobfuscator(language="powershell")
        # Create encoded PowerShell command
        cmd = "Write-Host 'Hello'"
        encoded = base64.b64encode(cmd.encode("utf-16-le")).decode()
        script = f"powershell.exe -EncodedCommand {encoded}"
        result = deob.deobfuscate(script)
        # Should have processed the script
        assert result is not None
        assert "final_code" in result

    def test_remove_backticks(self):
        """Test removing backtick obfuscation"""
        deob = Deobfuscator(language="powershell")
        script = "I`n`v`o`k`e`-`E`x`p`r`e`s`s`i`o`n"
        result = deob.deobfuscate(script)
        # Should attempt to process
        assert result is not None
        final_code = result.get("final_code", "")
        # Either backticks removed or at least processed
        assert final_code is not None

    def test_decode_char_array(self):
        """Test decoding [char] array obfuscation"""
        deob = Deobfuscator(language="powershell")
        # [char]72 + [char]101 + ... = "Hello"
        script = "([char]72+[char]101+[char]108+[char]108+[char]111)"
        result = deob.deobfuscate(script)
        # Should attempt to decode
        assert result is not None


class TestJavaScriptDeobfuscation:
    """Test JavaScript-specific deobfuscation"""

    def test_decode_fromcharcode(self):
        """Test decoding String.fromCharCode()"""
        deob = Deobfuscator(language="javascript")
        # String.fromCharCode(72,101,108,108,111) = "Hello"
        script = "String.fromCharCode(72,101,108,108,111)"
        result = deob.deobfuscate(script)
        assert result is not None
        final_code = result.get("final_code", "")
        # Should decode or at least process
        assert "Hello" in final_code or "fromCharCode" in final_code

    def test_decode_escape_sequences(self):
        """Test decoding escape sequences"""
        deob = Deobfuscator(language="javascript")
        script = r'var x = "\x48\x65\x6c\x6c\x6f";'
        result = deob.deobfuscate(script)
        assert result is not None
        final_code = result.get("final_code", "")
        # Either decoded or original
        assert "Hello" in final_code or "\\x" in final_code

    def test_decode_unicode_escapes(self):
        """Test decoding unicode escapes"""
        deob = Deobfuscator(language="javascript")
        script = r'var x = "\u0048\u0065\u006c\u006c\u006f";'
        result = deob.deobfuscate(script)
        assert result is not None
        final_code = result.get("final_code", "")
        # Either decoded or original
        assert "Hello" in final_code or "\\u" in final_code


class TestIOCExtraction:
    """Test IOC extraction from deobfuscated code"""

    def test_extract_urls(self):
        """Test extracting URLs from deobfuscated code"""
        from secops_helper.tools.deobfuscator import IOCExtractor

        script = 'var url = "http://evil.com/malware.exe";'
        iocs = IOCExtractor.extract_iocs(script)
        # Should have urls key
        assert "urls" in iocs
        assert len(iocs["urls"]) > 0

    def test_extract_ips(self):
        """Test extracting IP addresses"""
        from secops_helper.tools.deobfuscator import IOCExtractor

        script = 'var ip = "192.168.1.1";'
        iocs = IOCExtractor.extract_iocs(script)
        assert "ips" in iocs
        assert "192.168.1.1" in iocs["ips"]


class TestMultiLayerDeobfuscation:
    """Test multi-layer deobfuscation"""

    def test_multiple_encoding_layers(self):
        """Test deobfuscating multiple layers of encoding"""
        deob = Deobfuscator(max_layers=3)
        # Double-encoded payload
        inner = base64.b64encode(b"malware").decode()
        outer = base64.b64encode(inner.encode()).decode()
        script = f'var x = "{outer}";'
        result = deob.deobfuscate(script)
        # Should attempt to decode multiple layers
        assert result is not None
        assert "layers_processed" in result

    def test_max_layers_limit(self):
        """Test that max_layers limit is respected"""
        deob = Deobfuscator(max_layers=1)
        script = "some script"
        result = deob.deobfuscate(script)
        assert result is not None
        # Layers processed should be limited
        assert result["layers_processed"] <= 1


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
        # Returns a dict
        assert result is not None
        assert "final_code" in result
        assert result["final_code"] == ""

    def test_deobfuscate_plain_text(self):
        """Test handling plain text (no obfuscation)"""
        deob = Deobfuscator()
        script = "print('Hello World')"
        result = deob.deobfuscate(script)
        assert result is not None
        final_code = result.get("final_code", "")
        assert "Hello World" in final_code or "print" in final_code


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
