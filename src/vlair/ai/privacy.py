"""
vlair AI Privacy — Data sanitization before sending to cloud AI providers.

Removes sensitive fields (file contents, raw bytes, internal IPs) while keeping
information that is genuinely useful for threat analysis (hashes, verdicts,
defanged IOCs, detection counts, metadata).
"""

import copy
import json
import re
from typing import Any

# RFC-1918 private ranges (simple string-prefix matching is fast enough here)
_PRIVATE_IP_PREFIXES = (
    "10.",
    "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "127.",
    "::1",
    "fc00::", "fd",
)

# Top-level keys that should be stripped from results before sending to AI
_SENSITIVE_KEYS = {
    "file_contents",
    "raw_bytes",
    "raw_content",
    "raw_data",
    "binary_content",
    "decoded_bytes",
    "attachment_data",
    "pcap_raw",
    "memory_dump",
    "full_log_content",
}


def _is_private_ip(value: str) -> bool:
    """Return True if value looks like a private / loopback IP address."""
    s = str(value).strip()
    return any(s.startswith(prefix) for prefix in _PRIVATE_IP_PREFIXES)


def _sanitize_value(value: Any, send_file_contents: bool = False) -> Any:
    """Recursively sanitize a value, redacting sensitive content."""
    if isinstance(value, dict):
        return _sanitize_dict(value, send_file_contents)
    if isinstance(value, list):
        sanitized = [_sanitize_value(v, send_file_contents) for v in value]
        # Filter out private IPs from lists of strings
        if all(isinstance(v, str) for v in value):
            sanitized = [v for v in sanitized if not (isinstance(v, str) and _is_private_ip(v))]
        return sanitized
    return value


def _sanitize_dict(d: dict, send_file_contents: bool = False) -> dict:
    """Recursively sanitize a dict, removing sensitive keys."""
    result = {}
    for key, value in d.items():
        # Drop entire sensitive keys unless caller explicitly wants file contents
        if key in _SENSITIVE_KEYS and not send_file_contents:
            result[key] = "[REDACTED]"
            continue

        # Redact internal IP addresses in specific fields
        if key in ("source_ip", "src_ip", "client_ip", "internal_ip"):
            if isinstance(value, str) and _is_private_ip(value):
                result[key] = "[INTERNAL IP REDACTED]"
                continue
            if isinstance(value, list):
                result[key] = [v for v in value if not (isinstance(v, str) and _is_private_ip(v))]
                continue

        result[key] = _sanitize_value(value, send_file_contents)

    return result


def sanitize_tool_result(tool_result: dict, send_file_contents: bool = False) -> dict:
    """
    Return a sanitized deep copy of tool_result, safe to send to a cloud AI provider.

    Removes or redacts:
    - File contents / raw bytes (unless send_file_contents=True)
    - Internal / RFC-1918 IP addresses
    - Other sensitive fields listed in _SENSITIVE_KEYS

    Keeps:
    - Hashes (MD5, SHA1, SHA256)
    - Verdicts, detections, risk scores
    - Defanged IOCs (domains, URLs)
    - Metadata, timestamps, analysis counts
    """
    return _sanitize_dict(copy.deepcopy(tool_result), send_file_contents)


def get_dry_run_summary(ioc_value: str, ioc_type: str, tool_result: dict) -> str:
    """
    Return a human-readable description of what WOULD be sent to the AI provider.

    Useful for the --dry-run flag so analysts can audit data before it leaves
    the local network.
    """
    sanitized = sanitize_tool_result(tool_result)
    raw_json = json.dumps(sanitized, indent=2, default=str)
    byte_size = len(raw_json.encode("utf-8"))

    lines = [
        "DRY RUN — The following would be sent to the AI provider:",
        f"  IOC:       {ioc_value}",
        f"  Type:      {ioc_type}",
        f"  Data size: {byte_size} bytes (sanitized)",
        "",
        "  NOT sent: file contents, raw bytes, internal IP addresses",
        "",
        "Data preview (sanitized, first 500 chars):",
    ]

    preview = raw_json[:500]
    lines.append(preview)
    if len(raw_json) > 500:
        lines.append("  [... truncated ...]")

    return "\n".join(lines)
