#!/usr/bin/env python3
"""
CrowdStrike Falcon EDR Connector

Implements the EDRConnector interface against the CrowdStrike Falcon
REST API using OAuth2 client-credentials authentication.

Required environment variables
-------------------------------
CROWDSTRIKE_CLIENT_ID       OAuth2 client ID (API client)
CROWDSTRIKE_CLIENT_SECRET   OAuth2 client secret
CROWDSTRIKE_BASE_URL        Base URL (default: https://api.crowdstrike.com)

Optional
--------
CROWDSTRIKE_MEMBER_CID      MSSP child CID to target (Flight Control)

API scopes required on the API client
--------------------------------------
Devices: Read                   get_host_details
Devices: Write                  isolate_host
Sample Uploads: Read/Write      get_file_sample
IOC Management: Read            search_ioc
Incidents: Read                 get_processes (via process timeline)
"""

import os
import time
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

from .base import EDRConnector, Host, Process

# ---------------------------------------------------------------------------
# OAuth2 token manager
# ---------------------------------------------------------------------------

_TOKEN_LOCK = threading.Lock()


class _TokenManager:
    """Thread-safe OAuth2 client-credentials token cache."""

    def __init__(self, client_id: str, client_secret: str, base_url: str) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._base_url = base_url.rstrip("/")
        self._token: Optional[str] = None
        self._expires_at: float = 0.0

    def get_token(self) -> str:
        with _TOKEN_LOCK:
            if self._token and time.time() < self._expires_at - 30:
                return self._token
            self._refresh()
            return self._token  # type: ignore[return-value]

    def _refresh(self) -> None:
        resp = requests.post(
            f"{self._base_url}/oauth2/token",
            data={
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "grant_type": "client_credentials",
            },
            timeout=15,
        )
        resp.raise_for_status()
        body = resp.json()
        self._token = body["access_token"]
        self._expires_at = time.time() + int(body.get("expires_in", 1800))


# ---------------------------------------------------------------------------
# CrowdStrike Falcon connector
# ---------------------------------------------------------------------------


class CrowdStrikeConnector(EDRConnector):
    """
    CrowdStrike Falcon EDR connector.

    Reads credentials from environment variables; all args can also be
    supplied explicitly for testing.

    Usage::

        connector = CrowdStrikeConnector()
        host = connector.get_host_details("WORKSTATION-01")
        hits  = connector.search_ioc("sha256", "abc123...")
    """

    DEFAULT_BASE_URL = "https://api.crowdstrike.com"

    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        base_url: Optional[str] = None,
        member_cid: Optional[str] = None,
    ) -> None:
        self._client_id = client_id or os.getenv("CROWDSTRIKE_CLIENT_ID", "")
        self._client_secret = client_secret or os.getenv("CROWDSTRIKE_CLIENT_SECRET", "")
        self._base_url = (
            base_url or os.getenv("CROWDSTRIKE_BASE_URL", self.DEFAULT_BASE_URL)
        ).rstrip("/")
        self._member_cid = member_cid or os.getenv("CROWDSTRIKE_MEMBER_CID", "")

        if not self._client_id or not self._client_secret:
            raise EnvironmentError(
                "CROWDSTRIKE_CLIENT_ID and CROWDSTRIKE_CLIENT_SECRET must be set. "
                "Create an API client at https://falcon.crowdstrike.com/support/api-clients-and-keys"
            )

        self._tokens = _TokenManager(self._client_id, self._client_secret, self._base_url)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _headers(self) -> Dict[str, str]:
        h = {
            "Authorization": f"Bearer {self._tokens.get_token()}",
            "Content-Type": "application/json",
        }
        if self._member_cid:
            h["X-CS-USERUUID"] = self._member_cid  # Flight Control CID routing
        return h

    def _get(self, path: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        resp = requests.get(
            f"{self._base_url}{path}",
            headers=self._headers(),
            params=params or {},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, body: Any) -> Dict[str, Any]:
        resp = requests.post(
            f"{self._base_url}{path}",
            headers=self._headers(),
            json=body,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _parse_host(raw: Dict[str, Any]) -> Host:
        """Convert a Falcon device resource dict to a vlair Host DTO."""
        last_seen_str = raw.get("last_seen")
        last_seen = None
        if last_seen_str:
            try:
                last_seen = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00"))
            except ValueError:
                pass

        return Host(
            hostname=raw.get("hostname", ""),
            ip_address=raw.get("local_ip"),
            mac_address=raw.get("mac_address"),
            os_type=raw.get("platform_name"),
            os_version=raw.get("os_version"),
            domain=raw.get("machine_domain"),
            last_seen=last_seen,
            is_online=raw.get("status", "").lower() == "normal",
            is_isolated=raw.get("status", "").lower() == "contained",
            agent_version=raw.get("agent_version"),
            tags=raw.get("tags", []),
            owner=raw.get("modified_by"),
        )

    # ------------------------------------------------------------------
    # EDRConnector interface
    # ------------------------------------------------------------------

    def get_host_details(self, hostname: str) -> Optional[Host]:
        """Look up a host by hostname (case-insensitive prefix match)."""
        try:
            # Step 1: resolve hostname → device ID(s)
            query = self._get(
                "/devices/queries/devices/v1",
                params={"filter": f"hostname:'{hostname}'", "limit": 1},
            )
            ids = query.get("resources", [])
            if not ids:
                return None

            # Step 2: get full device entity
            entities = self._get(
                "/devices/entities/devices/v2",
                params={"ids": ids},
            )
            resources = entities.get("resources", [])
            if not resources:
                return None

            return self._parse_host(resources[0])
        except requests.HTTPError as exc:
            raise RuntimeError(f"CrowdStrike API error: {exc}") from exc

    def isolate_host(self, hostname: str, reason: str) -> bool:
        """
        Network-contain (isolate) a host.

        The host must be reachable by the Falcon sensor for containment to
        take effect.  Returns True when the action was accepted by the API.
        """
        try:
            query = self._get(
                "/devices/queries/devices/v1",
                params={"filter": f"hostname:'{hostname}'", "limit": 1},
            )
            ids = query.get("resources", [])
            if not ids:
                return False

            self._post(
                "/devices/entities/devices-actions/v2",
                body={
                    "action_parameters": [{"name": "comment", "value": reason}],
                    "ids": ids,
                },
            )
            # POST /devices/entities/devices-actions/v2 uses query param for action
            resp = requests.post(
                f"{self._base_url}/devices/entities/devices-actions/v2",
                headers=self._headers(),
                params={"action_name": "contain"},
                json={"action_parameters": [{"name": "comment", "value": reason}], "ids": ids},
                timeout=30,
            )
            resp.raise_for_status()
            return True
        except Exception:
            return False

    def get_file_sample(self, hostname: str, file_path: str) -> Optional[bytes]:
        """
        Retrieve a file sample from a host via Falcon Sample Uploads.

        Note: The file must have been submitted to Falcon's sandbox first or
        be available in the Sample Uploads store.  This method looks up the
        sample by its SHA-256 path reference; it does NOT trigger a live
        collection from the endpoint.
        """
        try:
            resp = requests.get(
                f"{self._base_url}/samples/entities/samples/v3",
                headers={**self._headers(), "Accept": "application/octet-stream"},
                params={"ids": file_path},
                timeout=60,
            )
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.content
        except Exception:
            return None

    def search_ioc(
        self,
        ioc_type: str,
        ioc_value: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """
        Search for IOC matches across the environment using Custom IOC API.

        *ioc_type* is normalised to Falcon's type vocabulary:
          hash → sha256 (preferred) or md5
          ip   → ipv4 / ipv6
          domain → domain
        """
        _TYPE_MAP = {
            "hash": "sha256",
            "hash_sha256": "sha256",
            "hash_md5": "md5",
            "hash_sha1": "sha256",  # Falcon doesn't index SHA-1; treat as unknown
            "ip": "ipv4",
            "domain": "domain",
            "ipv4": "ipv4",
            "ipv6": "ipv6",
        }
        falcon_type = _TYPE_MAP.get(ioc_type.lower(), ioc_type.lower())

        try:
            # Query processes that have touched this IOC
            body: Dict[str, Any] = {"type": falcon_type, "value": ioc_value, "limit": 500}
            if start_time:
                body["from_timestamp"] = start_time.isoformat()
            if end_time:
                body["to_timestamp"] = end_time.isoformat()

            resp = self._post("/iocs/entities/processes/v1", body=body)
            resources = resp.get("resources", [])

            results = []
            for r in resources:
                results.append(
                    {
                        "device_id": r.get("device_id", ""),
                        "process_id": r.get("process_id", ""),
                        "command_line": r.get("command_line", ""),
                        "file_path": r.get("file_path", ""),
                        "timestamp": r.get("start", ""),
                        "ioc_type": falcon_type,
                        "ioc_value": ioc_value,
                        "connector": "crowdstrike",
                    }
                )
            return results
        except requests.HTTPError:
            return []

    def get_processes(
        self,
        hostname: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[Process]:
        """Get recent process executions on a host via the Falcon timeline."""
        try:
            query = self._get(
                "/devices/queries/devices/v1",
                params={"filter": f"hostname:'{hostname}'", "limit": 1},
            )
            ids = query.get("resources", [])
            if not ids:
                return []

            params: Dict[str, Any] = {"id": ids[0], "types": ["ProcessRollup2"], "limit": 200}
            if start_time:
                params["start"] = start_time.isoformat()
            if end_time:
                params["end"] = end_time.isoformat()

            resp = self._get("/incidents/combined/crowdscores/v1", params=params)
            resources = resp.get("resources", [])

            processes = []
            for r in resources:
                ts_str = r.get("timestamp")
                ts = None
                if ts_str:
                    try:
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    except ValueError:
                        pass

                processes.append(
                    Process(
                        pid=int(r.get("pid", 0)),
                        name=r.get("file_name", ""),
                        command_line=r.get("command_line"),
                        executable_path=r.get("file_path"),
                        parent_pid=int(r.get("parent_pid", 0)) or None,
                        user=r.get("user_name"),
                        start_time=ts,
                        hash_sha256=r.get("sha256"),
                        is_suspicious=bool(r.get("severity", 0)),
                    )
                )
            return processes
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    @classmethod
    def is_configured(cls) -> bool:
        """Return True if the required env vars are set."""
        return bool(os.getenv("CROWDSTRIKE_CLIENT_ID") and os.getenv("CROWDSTRIKE_CLIENT_SECRET"))
