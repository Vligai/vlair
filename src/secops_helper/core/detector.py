#!/usr/bin/env python3
"""
Input Type Detector - Auto-detect what the user is analyzing
Part of SecOps Helper Operationalization (Phase 5)
"""

import os
import re
from pathlib import Path
from typing import Optional, Dict, Any


class InputType:
    """Enum-like class for input types"""

    EMAIL = "email"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    PCAP = "pcap"
    LOG = "log"
    SCRIPT = "script"
    FILE = "file"
    IOC_LIST = "ioc_list"
    UNKNOWN = "unknown"


class InputDetector:
    """
    Detect the type of input provided by the user.
    Supports files, hashes, IPs, domains, URLs, and more.
    """

    def detect_simple(self, input_value: str) -> Dict[str, Any]:
        """
        Simple detection returning backwards-compatible format.
        Returns dict with 'type' and optional 'subtype'.
        """
        result = self.detect(input_value)

        # Map specific hash types to generic "hash" with subtype
        type_mapping = {
            InputType.HASH_MD5: ("hash", "md5"),
            InputType.HASH_SHA1: ("hash", "sha1"),
            InputType.HASH_SHA256: ("hash", "sha256"),
            InputType.IP: ("ip", None),
            InputType.DOMAIN: ("domain", None),
            InputType.URL: ("url", None),
            InputType.EMAIL: ("email", None),
            InputType.FILE: ("file", None),
            InputType.UNKNOWN: ("unknown", None),
        }

        mapped = type_mapping.get(result["type"], (result["type"], None))
        simple_result = {
            "type": mapped[0],
            "value": result["value"],
            "confidence": result["confidence"],
        }
        if mapped[1]:
            simple_result["subtype"] = mapped[1]

        return simple_result

    # Hash patterns
    MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
    SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
    SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")

    # Network patterns
    IPV4_PATTERN = re.compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )
    IPV6_PATTERN = re.compile(
        r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|"
        r"^(?:[0-9a-fA-F]{1,4}:){1,7}:$|"
        r"^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$"
    )
    URL_PATTERN = re.compile(r'^https?://[^\s<>"{}|\\^`\[\]]+$', re.IGNORECASE)
    DOMAIN_PATTERN = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )

    # File extensions
    EMAIL_EXTENSIONS = {".eml", ".msg"}
    PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
    LOG_EXTENSIONS = {".log"}
    SCRIPT_EXTENSIONS = {".js", ".ps1", ".vbs", ".bat", ".cmd", ".py", ".sh"}

    # Log file patterns (content-based detection)
    LOG_PATTERNS = [
        re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} - -"),  # Apache/Nginx
        re.compile(r"^<\d+>"),  # Syslog
        re.compile(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"),  # Syslog date
        re.compile(r"^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}"),  # ISO datetime
    ]

    def detect(self, input_value: str) -> Dict[str, Any]:
        """
        Detect the type of input.

        Args:
            input_value: The input string (could be file path, hash, IP, etc.)

        Returns:
            Dict with 'type', 'value', 'confidence', and 'metadata'
        """
        input_value = input_value.strip()

        # Check if it's a file path first
        if self._is_file(input_value):
            return self._detect_file_type(input_value)

        # Check for hash patterns
        if self.MD5_PATTERN.match(input_value):
            return self._result(InputType.HASH_MD5, input_value, "high", {"length": 32})
        if self.SHA1_PATTERN.match(input_value):
            return self._result(InputType.HASH_SHA1, input_value, "high", {"length": 40})
        if self.SHA256_PATTERN.match(input_value):
            return self._result(InputType.HASH_SHA256, input_value, "high", {"length": 64})

        # Check for URL (before domain, as URLs contain domains)
        if self.URL_PATTERN.match(input_value):
            return self._result(
                InputType.URL, input_value, "high", {"scheme": input_value.split("://")[0]}
            )

        # Check for IP address
        if self.IPV4_PATTERN.match(input_value):
            return self._result(InputType.IP, input_value, "high", {"version": 4})
        if self.IPV6_PATTERN.match(input_value):
            return self._result(InputType.IP, input_value, "high", {"version": 6})

        # Check for domain
        if self.DOMAIN_PATTERN.match(input_value):
            # Additional validation - not just numbers
            if not all(part.isdigit() for part in input_value.split(".")):
                return self._result(InputType.DOMAIN, input_value, "medium", {})

        return self._result(InputType.UNKNOWN, input_value, "low", {})

    def _is_file(self, path: str) -> bool:
        """Check if the input is an existing file."""
        try:
            return Path(path).is_file()
        except (OSError, ValueError):
            return False

    def _detect_file_type(self, file_path: str) -> Dict[str, Any]:
        """Detect the type of file based on extension and content."""
        path = Path(file_path)
        ext = path.suffix.lower()

        # Check by extension first
        if ext in self.EMAIL_EXTENSIONS:
            return self._result(
                InputType.EMAIL, file_path, "high", {"filename": path.name, "extension": ext}
            )

        if ext in self.PCAP_EXTENSIONS:
            return self._result(
                InputType.PCAP, file_path, "high", {"filename": path.name, "extension": ext}
            )

        if ext in self.LOG_EXTENSIONS:
            return self._result(
                InputType.LOG, file_path, "high", {"filename": path.name, "extension": ext}
            )

        if ext in self.SCRIPT_EXTENSIONS:
            return self._result(
                InputType.SCRIPT,
                file_path,
                "high",
                {
                    "filename": path.name,
                    "extension": ext,
                    "language": self._detect_script_language(ext),
                },
            )

        # Try content-based detection for text files
        if self._is_text_file(file_path):
            content_type = self._detect_by_content(file_path)
            if content_type:
                return content_type

        # Check for IOC list (text file with one IOC per line)
        if ext in {".txt", ".csv", ".ioc", ".iocs"}:
            if self._looks_like_ioc_list(file_path):
                return self._result(
                    InputType.IOC_LIST, file_path, "medium", {"filename": path.name}
                )

        # Default to generic file
        return self._result(
            InputType.FILE,
            file_path,
            "low",
            {"filename": path.name, "extension": ext, "size": path.stat().st_size},
        )

    def _detect_script_language(self, ext: str) -> str:
        """Map extension to script language."""
        mapping = {
            ".js": "javascript",
            ".ps1": "powershell",
            ".vbs": "vbscript",
            ".bat": "batch",
            ".cmd": "batch",
            ".py": "python",
            ".sh": "bash",
        }
        return mapping.get(ext, "unknown")

    def _is_text_file(self, file_path: str, sample_size: int = 8192) -> bool:
        """Check if file appears to be text (not binary)."""
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(sample_size)
                # Check for null bytes (binary indicator)
                if b"\x00" in chunk:
                    return False
                # Try to decode as UTF-8
                try:
                    chunk.decode("utf-8")
                    return True
                except UnicodeDecodeError:
                    return False
        except Exception:
            return False

    def _detect_by_content(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Detect file type by examining content."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                # Read first few lines
                lines = []
                for _ in range(10):
                    line = f.readline()
                    if not line:
                        break
                    lines.append(line)

                content = "".join(lines)

                # Check for log patterns
                for pattern in self.LOG_PATTERNS:
                    if pattern.search(content):
                        return self._result(
                            InputType.LOG,
                            file_path,
                            "medium",
                            {"filename": Path(file_path).name, "detected_by": "content"},
                        )

                # Check for email headers
                if "From:" in content and ("To:" in content or "Subject:" in content):
                    return self._result(
                        InputType.EMAIL,
                        file_path,
                        "medium",
                        {"filename": Path(file_path).name, "detected_by": "content"},
                    )

        except Exception:
            pass

        return None

    def _looks_like_ioc_list(self, file_path: str) -> bool:
        """Check if file looks like a list of IOCs."""
        try:
            ioc_count = 0
            line_count = 0

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    line_count += 1
                    if line_count > 100:  # Sample first 100 lines
                        break

                    # Check if line looks like an IOC
                    if (
                        self.MD5_PATTERN.match(line)
                        or self.SHA1_PATTERN.match(line)
                        or self.SHA256_PATTERN.match(line)
                        or self.IPV4_PATTERN.match(line)
                        or self.DOMAIN_PATTERN.match(line)
                        or self.URL_PATTERN.match(line)
                    ):
                        ioc_count += 1

            # If more than 50% of lines look like IOCs, it's probably an IOC list
            return line_count > 0 and (ioc_count / line_count) > 0.5

        except Exception:
            return False

    def _result(
        self, input_type: str, value: str, confidence: str, metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a detection result."""
        return {"type": input_type, "value": value, "confidence": confidence, "metadata": metadata}

    def get_recommended_tools(self, detection: Dict[str, Any]) -> list:
        """
        Get the recommended tools to run based on detected input type.

        Args:
            detection: Result from detect()

        Returns:
            List of tool names to run in order
        """
        input_type = detection["type"]

        tool_mapping = {
            InputType.EMAIL: ["eml", "ioc"],  # Parse email, extract IOCs
            InputType.HASH_MD5: ["hash"],
            InputType.HASH_SHA1: ["hash"],
            InputType.HASH_SHA256: ["hash"],
            InputType.IP: ["intel"],
            InputType.DOMAIN: ["intel"],
            InputType.URL: ["url"],
            InputType.PCAP: ["pcap", "ioc"],
            InputType.LOG: ["log"],
            InputType.SCRIPT: ["deobfuscate", "ioc"],
            InputType.FILE: ["hash", "yara"],  # Hash lookup + YARA scan
            InputType.IOC_LIST: ["ioc"],  # Process IOC list
            InputType.UNKNOWN: [],
        }

        return tool_mapping.get(input_type, [])


def main():
    """CLI for testing the detector."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python detector.py <input>")
        print("\nExamples:")
        print("  python detector.py suspicious.eml")
        print("  python detector.py 44d88612fea8a8f36de82e1278abb02f")
        print("  python detector.py malicious.com")
        print("  python detector.py 192.168.1.1")
        sys.exit(1)

    detector = InputDetector()
    result = detector.detect(sys.argv[1])

    print(f"Input: {result['value']}")
    print(f"Type: {result['type']}")
    print(f"Confidence: {result['confidence']}")
    print(f"Metadata: {result['metadata']}")
    print(f"Recommended tools: {detector.get_recommended_tools(result)}")


class Detector:
    """
    Backwards-compatible detector class.
    Wraps InputDetector with simplified interface expected by tests.
    """

    def __init__(self):
        self._detector = InputDetector()

    def detect(self, input_value: str) -> Dict[str, Any]:
        """Detect input type with simplified output format."""
        return self._detector.detect_simple(input_value)


if __name__ == "__main__":
    main()
