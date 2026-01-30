"""
Data Sanitization for AI Analysis

Ensures sensitive data is not sent to cloud AI providers.
Implements privacy controls as specified in FR-9.
"""

import re
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass


@dataclass
class PrivacyConfig:
    """Privacy configuration for AI data transmission"""
    send_file_contents: bool = False
    send_internal_ips: bool = False
    sanitize_usernames: bool = True
    sanitize_hostnames: bool = True
    sanitize_paths: bool = True
    allowed_domains: Optional[Set[str]] = None  # If set, only allow these domains


class DataSanitizer:
    """Sanitizes data before sending to AI providers"""

    # Private IP ranges (RFC 1918 + loopback)
    PRIVATE_IP_PATTERNS = [
        r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        r'172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}',
        r'192\.168\.\d{1,3}\.\d{1,3}',
        r'127\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        r'169\.254\.\d{1,3}\.\d{1,3}',  # Link-local
    ]

    # Username patterns in various contexts
    USERNAME_PATTERNS = [
        r'C:\\Users\\([^\\]+)',  # Windows path
        r'/home/([^/]+)',  # Linux path
        r'/Users/([^/]+)',  # macOS path
        r'(?:user|username|login)[=:]\s*([^\s,;]+)',  # Generic user fields
    ]

    # Hostname patterns
    HOSTNAME_PATTERNS = [
        r'\\\\([^\\]+)\\',  # UNC path
        r'(?:host|hostname|server)[=:]\s*([^\s,;]+)',  # Generic host fields
    ]

    # Sensitive file patterns to never include
    SENSITIVE_FILE_PATTERNS = [
        r'\.env$',
        r'\.pem$',
        r'\.key$',
        r'credentials',
        r'password',
        r'secret',
        r'token',
        r'api_key',
    ]

    def __init__(self, config: Optional[PrivacyConfig] = None):
        """
        Initialize the data sanitizer.

        Args:
            config: Privacy configuration (defaults to most restrictive)
        """
        self.config = config or PrivacyConfig()

    def sanitize(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize a data dictionary for AI transmission.

        Args:
            data: Raw data dictionary

        Returns:
            Sanitized data dictionary safe for AI transmission
        """
        return self._sanitize_value(data)

    def _sanitize_value(self, value: Any) -> Any:
        """Recursively sanitize a value"""
        if isinstance(value, dict):
            return {k: self._sanitize_value(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self._sanitize_value(v) for v in value]
        elif isinstance(value, str):
            return self._sanitize_string(value)
        else:
            return value

    def _sanitize_string(self, text: str) -> str:
        """Sanitize a string value"""
        result = text

        # Remove internal IPs if configured
        if not self.config.send_internal_ips:
            for pattern in self.PRIVATE_IP_PATTERNS:
                result = re.sub(pattern, '[INTERNAL_IP]', result)

        # Sanitize usernames if configured
        if self.config.sanitize_usernames:
            for pattern in self.USERNAME_PATTERNS:
                result = re.sub(pattern, lambda m: m.group(0).replace(
                    m.group(1) if m.groups() else '', '[USER]'
                ), result, flags=re.IGNORECASE)

        # Sanitize hostnames if configured
        if self.config.sanitize_hostnames:
            for pattern in self.HOSTNAME_PATTERNS:
                result = re.sub(pattern, lambda m: m.group(0).replace(
                    m.group(1) if m.groups() else '', '[HOST]'
                ), result, flags=re.IGNORECASE)

        # Sanitize file paths if configured
        if self.config.sanitize_paths:
            # Windows paths
            result = re.sub(
                r'C:\\Users\\[^\\]+\\',
                r'C:\\Users\\[USER]\\',
                result
            )
            # Unix paths
            result = re.sub(
                r'/home/[^/]+/',
                '/home/[USER]/',
                result
            )
            result = re.sub(
                r'/Users/[^/]+/',
                '/Users/[USER]/',
                result
            )

        return result

    def get_transmission_preview(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a preview of what would be sent to the AI provider.

        Args:
            data: Raw data dictionary

        Returns:
            Dictionary with 'sanitized' data and 'removed' items list
        """
        sanitized = self.sanitize(data)
        removed = self._identify_removed(data, sanitized)

        return {
            'will_send': sanitized,
            'removed_or_sanitized': removed,
            'privacy_config': {
                'send_file_contents': self.config.send_file_contents,
                'send_internal_ips': self.config.send_internal_ips,
                'sanitize_usernames': self.config.sanitize_usernames,
                'sanitize_hostnames': self.config.sanitize_hostnames,
                'sanitize_paths': self.config.sanitize_paths,
            }
        }

    def _identify_removed(
        self,
        original: Any,
        sanitized: Any,
        path: str = ""
    ) -> List[str]:
        """Identify what was removed or sanitized"""
        removed = []

        if isinstance(original, dict) and isinstance(sanitized, dict):
            for key in original:
                new_path = f"{path}.{key}" if path else key
                if key not in sanitized:
                    removed.append(f"{new_path}: [REMOVED]")
                else:
                    removed.extend(self._identify_removed(
                        original[key],
                        sanitized[key],
                        new_path
                    ))
        elif isinstance(original, list) and isinstance(sanitized, list):
            for i, (orig, san) in enumerate(zip(original, sanitized)):
                removed.extend(self._identify_removed(
                    orig, san, f"{path}[{i}]"
                ))
        elif isinstance(original, str) and isinstance(sanitized, str):
            if original != sanitized:
                removed.append(f"{path}: sanitized")

        return removed

    def is_sensitive_file(self, filename: str) -> bool:
        """
        Check if a filename matches sensitive file patterns.

        Args:
            filename: Filename to check

        Returns:
            True if file should not be transmitted
        """
        filename_lower = filename.lower()
        for pattern in self.SENSITIVE_FILE_PATTERNS:
            if re.search(pattern, filename_lower):
                return True
        return False

    def defang_ioc(self, ioc: str, ioc_type: str) -> str:
        """
        Defang an IOC for safe transmission and display.

        Args:
            ioc: The IOC value
            ioc_type: Type of IOC (ip, domain, url, email)

        Returns:
            Defanged IOC string
        """
        if ioc_type == 'ip':
            return ioc.replace('.', '[.]')
        elif ioc_type == 'domain':
            return ioc.replace('.', '[.]')
        elif ioc_type == 'url':
            result = ioc.replace('http://', 'hxxp://')
            result = result.replace('https://', 'hxxps://')
            result = result.replace('.', '[.]')
            return result
        elif ioc_type == 'email':
            return ioc.replace('@', '[@]').replace('.', '[.]')
        return ioc

    def refang_ioc(self, ioc: str) -> str:
        """
        Refang a defanged IOC back to its original form.

        Args:
            ioc: Defanged IOC string

        Returns:
            Original IOC value
        """
        result = ioc.replace('[.]', '.')
        result = result.replace('[@]', '@')
        result = result.replace('hxxp://', 'http://')
        result = result.replace('hxxps://', 'https://')
        return result
