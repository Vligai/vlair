#!/usr/bin/env python3
"""
Deobfuscator - Malicious Script Deobfuscation Tool

Analyze and deobfuscate malicious scripts (JavaScript, PowerShell, VBScript, Batch)
by detecting and reversing common obfuscation techniques.
"""

import sys
import json
import argparse
import base64
import re
import binascii
import urllib.parse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple


class EncodingDetector:
    """Detect various encoding schemes"""

    @staticmethod
    def is_base64(data: str) -> bool:
        """Check if string is likely base64 encoded"""
        # Remove whitespace
        data = data.strip()

        # Check length (base64 is always multiple of 4)
        if len(data) % 4 != 0:
            return False

        # Check character set
        base64_pattern = r"^[A-Za-z0-9+/]*={0,2}$"
        if not re.match(base64_pattern, data):
            return False

        # Must be at least some length to be meaningful
        if len(data) < 16:
            return False

        return True

    @staticmethod
    def is_hex(data: str) -> bool:
        """Check if string is hex encoded"""
        data = data.strip().replace(" ", "").replace("0x", "")

        if len(data) < 10 or len(data) % 2 != 0:
            return False

        hex_pattern = r"^[0-9A-Fa-f]+$"
        return bool(re.match(hex_pattern, data))

    @staticmethod
    def is_url_encoded(data: str) -> bool:
        """Check if string is URL encoded"""
        # Look for %XX patterns
        url_pattern = r"%[0-9A-Fa-f]{2}"
        matches = re.findall(url_pattern, data)
        return len(matches) >= 3  # At least 3 encoded characters


class Decoder:
    """Decode various encoding schemes"""

    @staticmethod
    def decode_base64(data: str) -> Optional[str]:
        """Decode base64 string"""
        try:
            # Remove whitespace
            data = data.strip().replace("\n", "").replace("\r", "").replace(" ", "")

            # Validate base64 format first
            if len(data) < 4:
                return None

            # Check character set (base64 should only have these chars)
            if not re.match(r"^[A-Za-z0-9+/]*={0,2}$", data):
                return None

            # Length should be multiple of 4
            if len(data) % 4 != 0:
                return None

            # Try standard base64
            decoded = base64.b64decode(data, validate=True)

            # Verify result is mostly printable text
            try:
                text = decoded.decode("utf-8")
                # Check if result contains mostly printable characters
                printable_count = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
                if len(text) > 0 and printable_count / len(text) < 0.7:
                    return None
                return text
            except UnicodeDecodeError:
                return None

        except Exception:
            try:
                # Try URL-safe base64
                decoded = base64.urlsafe_b64decode(data)
                text = decoded.decode("utf-8")
                # Check if result contains mostly printable characters
                printable_count = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
                if len(text) > 0 and printable_count / len(text) < 0.7:
                    return None
                return text
            except Exception:
                return None

    @staticmethod
    def decode_hex(data: str) -> Optional[str]:
        """Decode hex string"""
        try:
            data = data.strip().replace(" ", "").replace("0x", "").replace("\\x", "")
            decoded = binascii.unhexlify(data)
            return decoded.decode("utf-8", errors="ignore")
        except Exception:
            return None

    @staticmethod
    def decode_url(data: str) -> Optional[str]:
        """Decode URL encoded string"""
        try:
            return urllib.parse.unquote(data)
        except Exception:
            return None

    @staticmethod
    def decode_rot13(data: str) -> str:
        """Decode ROT13"""
        import codecs

        return codecs.decode(data, "rot_13")


class PowerShellDeobfuscator:
    """PowerShell-specific deobfuscation"""

    @staticmethod
    def remove_backticks(code: str) -> str:
        """Remove PowerShell backtick obfuscation"""
        # Remove backticks that aren't at end of line (line continuation)
        return re.sub(r"`([^\\r\\n])", r"\1", code)

    @staticmethod
    def decode_encoded_command(code: str) -> Optional[str]:
        """Decode PowerShell -EncodedCommand"""
        patterns = [
            r"-[Ee]ncodedcommand\s+([A-Za-z0-9+/=]+)",
            r"-[Ee]nc\s+([A-Za-z0-9+/=]+)",
            r"-[Ee]\s+([A-Za-z0-9+/=]+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, code)
            if match:
                encoded = match.group(1)
                try:
                    # PowerShell uses UTF-16LE encoding
                    decoded = base64.b64decode(encoded)
                    return decoded.decode("utf-16le", errors="ignore")
                except Exception:
                    pass

        return None

    @staticmethod
    def resolve_string_formatting(code: str) -> str:
        """Resolve PowerShell string formatting (-f operator)"""
        # Simple resolution - just remove formatting for visibility
        code = re.sub(r'"{[0-9]}"', '"%s"', code)
        return code

    @staticmethod
    def expand_compressed(code: str) -> Optional[str]:
        """Expand compressed PowerShell payloads"""
        # Look for Gzip/Deflate compression patterns
        compression_pattern = r'FromBase64String\(["\']([A-Za-z0-9+/=]+)["\']\)'
        match = re.search(compression_pattern, code)

        if match:
            try:
                import gzip
                import io

                b64_data = match.group(1)
                compressed = base64.b64decode(b64_data)

                # Try gzip decompression
                try:
                    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as f:
                        decompressed = f.read()
                        return decompressed.decode("utf-8", errors="ignore")
                except Exception:
                    pass
            except Exception:
                pass

        return None


class JavaScriptDeobfuscator:
    """JavaScript-specific deobfuscation"""

    @staticmethod
    def decode_escape_sequences(code: str) -> str:
        """Decode JavaScript escape sequences"""
        # Decode hex escape sequences
        code = re.sub(r"\\x([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), code)

        # Decode unicode escape sequences
        code = re.sub(r"\\u([0-9A-Fa-f]{4})", lambda m: chr(int(m.group(1), 16)), code)

        return code

    @staticmethod
    def resolve_string_concat(code: str) -> str:
        """Resolve simple string concatenation"""
        # Match adjacent string literals and combine them
        # This is a simple implementation
        code = re.sub(r'""\s*\+\s*""', '""', code)
        code = re.sub(r"''\s*\+\s*''", "''", code)

        return code

    @staticmethod
    def decode_charcode(code: str) -> str:
        """Decode String.fromCharCode()"""

        def replace_charcode(match):
            codes = match.group(1)
            try:
                nums = [int(x.strip()) for x in codes.split(",")]
                return '"' + "".join(chr(n) for n in nums if 0 <= n <= 127) + '"'
            except Exception:
                return match.group(0)

        code = re.sub(r"String\.fromCharCode\(([0-9,\s]+)\)", replace_charcode, code)
        return code


class Deobfuscator:
    """Main deobfuscation engine"""

    def __init__(self, language="auto", max_layers=10, verbose=False):
        self.language = language
        self.max_layers = max_layers
        self.verbose = verbose
        self.detector = EncodingDetector()
        self.decoder = Decoder()
        self.ps_deobf = PowerShellDeobfuscator()
        self.js_deobf = JavaScriptDeobfuscator()

    def detect_language(self, code: str) -> str:
        """Auto-detect script language"""
        code_lower = code.lower()[:500]  # Check first 500 chars

        # Batch indicators - check first (more specific patterns)
        # @echo off is very specific to batch
        # %variable% syntax is batch-specific
        if "@echo" in code_lower or re.search(r"%\w+%", code):
            return "batch"

        # PowerShell indicators - check before others
        # PowerShell uses $ for variables and has specific cmdlets
        ps_indicators = [
            "powershell",
            "-encodedcommand",
            "invoke-expression",
            "$_",
            "param(",
            "write-host",
            "get-",
            "set-",
            "new-object",
        ]
        if any(ind in code_lower for ind in ps_indicators):
            return "powershell"

        # Check for PowerShell variable syntax: $varname (but not in batch context)
        if re.search(r"\$[a-zA-Z_]\w*\s*=", code):
            return "powershell"

        # JavaScript indicators
        js_indicators = ["function", "var ", "let ", "const ", "eval(", "document."]
        if any(ind in code_lower for ind in js_indicators):
            return "javascript"

        # VBScript indicators - use more specific patterns to avoid false positives
        vb_indicators = ["dim ", "wscript.", "createobject", "msgbox"]
        if any(ind in code_lower for ind in vb_indicators):
            return "vbscript"

        return "unknown"

    def deobfuscate(self, code: str) -> Dict:
        """Perform multi-layer deobfuscation"""
        if self.language == "auto":
            detected_lang = self.detect_language(code)
            if self.verbose:
                print(f"Detected language: {detected_lang}", file=sys.stderr)
        else:
            detected_lang = self.language

        layers = []
        current_code = code
        layer_num = 0

        while layer_num < self.max_layers:
            layer_num += 1

            if self.verbose:
                print(f"Processing layer {layer_num}...", file=sys.stderr)

            techniques_applied = []
            new_code = current_code

            # Try various deobfuscation techniques
            new_code, layer_techniques = self.apply_deobfuscation(new_code, detected_lang)

            techniques_applied.extend(layer_techniques)

            # If no changes, we're done
            if new_code == current_code or not techniques_applied:
                break

            # Record layer
            layers.append(
                {
                    "layer": layer_num,
                    "techniques": techniques_applied,
                    "size_before": len(current_code),
                    "size_after": len(new_code),
                }
            )

            current_code = new_code

        result = {
            "original_code": code,
            "final_code": current_code,
            "language": detected_lang,
            "layers_processed": layer_num - 1 if layers else 0,
            "layers": layers,
            "fully_deobfuscated": len(layers) == 0
            or layers[-1]["size_before"] == layers[-1]["size_after"],
        }

        return result

    def apply_deobfuscation(self, code: str, language: str) -> Tuple[str, List[str]]:
        """Apply deobfuscation techniques"""
        techniques = []
        original = code

        # Check for base64
        if self.detector.is_base64(code):
            decoded = self.decoder.decode_base64(code)
            if decoded and decoded != code and len(decoded) < len(code) * 2:
                code = decoded
                techniques.append("base64_decoding")

        # Check for hex
        if self.detector.is_hex(code):
            decoded = self.decoder.decode_hex(code)
            if decoded and decoded != code:
                code = decoded
                techniques.append("hex_decoding")

        # Check for URL encoding
        if self.detector.is_url_encoded(code):
            decoded = self.decoder.decode_url(code)
            if decoded and decoded != code:
                code = decoded
                techniques.append("url_decoding")

        # Language-specific deobfuscation
        if language == "powershell":
            # PowerShell encoded command
            ps_decoded = self.ps_deobf.decode_encoded_command(code)
            if ps_decoded:
                code = ps_decoded
                techniques.append("powershell_encoded_command")

            # Remove backticks
            code_no_backticks = self.ps_deobf.remove_backticks(code)
            if code_no_backticks != code:
                code = code_no_backticks
                techniques.append("powershell_backtick_removal")

            # Expand compressed
            ps_decompressed = self.ps_deobf.expand_compressed(code)
            if ps_decompressed:
                code = ps_decompressed
                techniques.append("powershell_decompression")

        elif language == "javascript":
            # Decode escape sequences
            code_unescaped = self.js_deobf.decode_escape_sequences(code)
            if code_unescaped != code:
                code = code_unescaped
                techniques.append("javascript_escape_sequences")

            # Decode fromCharCode
            code_charcode = self.js_deobf.decode_charcode(code)
            if code_charcode != code:
                code = code_charcode
                techniques.append("javascript_char_code")

        # If still looks like base64 after language processing, try again
        if not techniques and len(code) > 50:
            # Look for base64 chunks within the code
            b64_pattern = r"[A-Za-z0-9+/]{30,}={0,2}"
            matches = re.findall(b64_pattern, code)

            for match in matches:
                if self.detector.is_base64(match):
                    decoded = self.decoder.decode_base64(match)
                    if decoded and decoded != match:
                        code = code.replace(match, decoded)
                        techniques.append("embedded_base64_decoding")
                        break

        return code, techniques


class IOCExtractor:
    """Extract IOCs from deobfuscated code"""

    @staticmethod
    def extract_iocs(code: str) -> Dict:
        """Extract common IOCs"""
        iocs = {"urls": [], "ips": [], "domains": [], "file_paths": [], "registry_keys": []}

        # URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        iocs["urls"] = list(set(re.findall(url_pattern, code, re.IGNORECASE)))

        # IP addresses
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        iocs["ips"] = list(set(re.findall(ip_pattern, code)))

        # Domains (simplified)
        domain_pattern = (
            r"[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(?:\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+\.[a-zA-Z]{2,6}"
        )
        potential_domains = re.findall(domain_pattern, code)
        # Filter out common false positives
        iocs["domains"] = [
            d for d in set(potential_domains) if not d.endswith((".dll", ".exe", ".js"))
        ]

        # Windows file paths
        path_pattern = r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*'
        iocs["file_paths"] = list(set(re.findall(path_pattern, code)))

        # Registry keys
        reg_pattern = r'HK[A-Z_]+\\[^\\s<>"]+'
        iocs["registry_keys"] = list(set(re.findall(reg_pattern, code)))

        return iocs


def format_output_json(result: Dict) -> str:
    """Format output as JSON"""
    return json.dumps(result, indent=2)


def format_output_text(result: Dict) -> str:
    """Format output as human-readable text"""
    lines = []
    lines.append("=" * 80)
    lines.append("Deobfuscation Analysis Report")
    lines.append("=" * 80)
    lines.append("")

    lines.append(f"Language: {result['language']}")
    lines.append(f"Layers Processed: {result['layers_processed']}")
    lines.append(
        f"Fully Deobfuscated: {'Yes' if result['fully_deobfuscated'] else 'Possibly more layers'}"
    )
    lines.append("")

    # Show techniques used
    if result["layers"]:
        lines.append("Obfuscation Techniques Detected:")
        for layer in result["layers"]:
            lines.append(f"  Layer {layer['layer']}: {', '.join(layer['techniques'])}")
        lines.append("")

    # Show deobfuscated code (truncated if too long)
    lines.append("Deobfuscated Code:")
    lines.append("-" * 80)
    final_code = result["final_code"]
    if len(final_code) > 2000:
        lines.append(final_code[:2000])
        lines.append(f"\n... (truncated, {len(final_code)} total characters)")
    else:
        lines.append(final_code)
    lines.append("-" * 80)
    lines.append("")

    # Show IOCs if extracted
    if "iocs" in result and any(result["iocs"].values()):
        lines.append("Extracted IOCs:")
        for ioc_type, ioc_list in result["iocs"].items():
            if ioc_list:
                lines.append(f"  {ioc_type.upper()}:")
                for ioc in ioc_list[:10]:  # Limit to 10 per type
                    lines.append(f"    - {ioc}")
        lines.append("")

    lines.append("=" * 80)
    return "\n".join(lines)


def parse_args():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description="Deobfuscator - Malicious Script Deobfuscation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Deobfuscate a JavaScript file
  python deobfuscator.py malware.js

  # Deobfuscate PowerShell script
  python deobfuscator.py script.ps1

  # Specify language manually
  python deobfuscator.py --language powershell encoded.txt

  # Extract IOCs
  python deobfuscator.py malware.js --extract-iocs

  # Output to file
  python deobfuscator.py malware.js --output deobfuscated.json

  # Quick base64 decode
  python deobfuscator.py --decode-base64 "SGVsbG8gV29ybGQ="

  # Decode hex string
  python deobfuscator.py --decode-hex "48656c6c6f"
        """,
    )

    parser.add_argument("input_file", nargs="?", help="Script file to deobfuscate")
    parser.add_argument(
        "--language",
        "-l",
        choices=["auto", "powershell", "javascript", "vbscript", "batch"],
        default="auto",
        help="Script language (default: auto)",
    )
    parser.add_argument("--max-layers", type=int, default=10, help="Maximum deobfuscation layers")
    parser.add_argument(
        "--extract-iocs", action="store_true", help="Extract IOCs from deobfuscated code"
    )
    parser.add_argument(
        "--format", "-f", choices=["json", "txt"], default="txt", help="Output format"
    )
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    # Quick decode options
    parser.add_argument("--decode-base64", help="Decode base64 string directly")
    parser.add_argument("--decode-hex", help="Decode hex string directly")
    parser.add_argument("--decode-url", help="Decode URL-encoded string directly")

    return parser.parse_args()


def main():
    """Main entry point"""
    args = parse_args()

    # Quick decode options
    if args.decode_base64:
        decoder = Decoder()
        result = decoder.decode_base64(args.decode_base64)
        if result:
            print(result)
        else:
            print("Failed to decode base64", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    if args.decode_hex:
        decoder = Decoder()
        result = decoder.decode_hex(args.decode_hex)
        if result:
            print(result)
        else:
            print("Failed to decode hex", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    if args.decode_url:
        decoder = Decoder()
        result = decoder.decode_url(args.decode_url)
        if result:
            print(result)
        else:
            print("Failed to decode URL", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    # Regular deobfuscation
    if not args.input_file:
        print("Error: No input file specified. Use --help for usage.", file=sys.stderr)
        sys.exit(1)

    input_path = Path(args.input_file)
    if not input_path.exists():
        print(f"Error: File not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    # Read input file
    with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
        code = f.read()

    if args.verbose:
        print(f"Loaded {len(code)} characters from {input_path}", file=sys.stderr)

    # Deobfuscate
    deobf = Deobfuscator(language=args.language, max_layers=args.max_layers, verbose=args.verbose)

    result = deobf.deobfuscate(code)

    # Extract IOCs if requested
    if args.extract_iocs:
        extractor = IOCExtractor()
        result["iocs"] = extractor.extract_iocs(result["final_code"])

    # Add metadata
    result["metadata"] = {
        "tool": "deobfuscator",
        "version": "1.0.0",
        "analysis_date": datetime.utcnow().isoformat() + "Z",
        "input_file": str(input_path),
    }

    # Format output
    if args.format == "json":
        output = format_output_json(result)
    else:
        output = format_output_text(result)

    # Write output
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Results written to {args.output}", file=sys.stderr)
    else:
        print(output)

    sys.exit(0)


if __name__ == "__main__":
    main()
