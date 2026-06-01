#!/usr/bin/env python3
"""
Splunk SIEM Connector

Implements the SIEMConnector interface against the Splunk REST API using
token-based authentication (Splunk HEC/management token).

Required environment variables
-------------------------------
SPLUNK_HOST         Hostname or IP of the Splunk search head (default: localhost)
SPLUNK_PORT         Management API port (default: 8089)
SPLUNK_TOKEN        Splunk authentication token (Bearer token or session token)

Optional
--------
SPLUNK_VERIFY_SSL   Set to "false" to disable SSL certificate verification
                    (useful for self-signed certs in lab environments)
SPLUNK_APP          Splunk app context for searches (default: search)
SPLUNK_OWNER        Namespace owner (default: nobody)

Authentication
--------------
The connector expects a Splunk token created via:
  Settings → Tokens → New Token
with appropriate role permissions.  A username/password flow is intentionally
not supported to avoid credential exposure in environment variables.

API endpoints used
------------------
POST /services/search/jobs          Create search job
GET  /services/search/jobs/{sid}    Poll job status
GET  /services/search/jobs/{sid}/results  Fetch results (JSON output)
DELETE /services/search/jobs/{sid}  Clean up completed job
"""

import os
import time
import urllib.parse
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
import urllib3

from .base import SIEMConnector, URLClickEvent

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_DEFAULT_POLL_INTERVAL = 2.0  # seconds between status polls
_MAX_POLL_SECONDS = 120  # give up after 2 minutes


class SplunkConnector(SIEMConnector):
    """
    Splunk Enterprise / Splunk Cloud SIEM connector.

    Reads configuration from environment variables; all parameters can also
    be supplied explicitly for testing.

    Usage::

        connector = SplunkConnector()
        events = connector.get_events_by_host("WORKSTATION-01")
        clicks = connector.get_url_clicks(domain="evil.example.com")
    """

    DEFAULT_HOST = "localhost"
    DEFAULT_PORT = 8089
    DEFAULT_APP = "search"
    DEFAULT_OWNER = "nobody"

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        token: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        app: Optional[str] = None,
        owner: Optional[str] = None,
    ) -> None:
        self._host = host or os.getenv("SPLUNK_HOST", self.DEFAULT_HOST)
        self._port = port or int(os.getenv("SPLUNK_PORT", str(self.DEFAULT_PORT)))
        self._token = token or os.getenv("SPLUNK_TOKEN", "")
        self._app = app or os.getenv("SPLUNK_APP", self.DEFAULT_APP)
        self._owner = owner or os.getenv("SPLUNK_OWNER", self.DEFAULT_OWNER)

        if verify_ssl is None:
            env_val = os.getenv("SPLUNK_VERIFY_SSL", "true").lower()
            self._verify_ssl = env_val not in ("false", "0", "no")
        else:
            self._verify_ssl = verify_ssl

        if not self._token:
            raise EnvironmentError("SPLUNK_TOKEN must be set. " "Create a token at Settings → Tokens in the Splunk Web UI.")

        if not self._verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self._base_url = f"https://{self._host}:{self._port}"
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/x-www-form-urlencoded",
            }
        )
        self._session.verify = self._verify_ssl

    # ------------------------------------------------------------------
    # Internal search helpers
    # ------------------------------------------------------------------

    def _create_job(
        self,
        query: str,
        earliest: Optional[str] = None,
        latest: Optional[str] = None,
    ) -> str:
        """Submit a search job and return the search ID (sid)."""
        data: Dict[str, Any] = {
            "search": query if query.lstrip().startswith("|") else f"search {query}",
            "output_mode": "json",
        }
        if earliest:
            data["earliest_time"] = earliest
        if latest:
            data["latest_time"] = latest

        url = f"{self._base_url}/servicesNS/{self._owner}/{self._app}/search/jobs"
        resp = self._session.post(url, data=urllib.parse.urlencode(data), timeout=30)
        resp.raise_for_status()
        return resp.json()["sid"]

    def _poll_job(self, sid: str) -> None:
        """Block until the search job is done or the timeout is reached."""
        url = f"{self._base_url}/services/search/jobs/{sid}"
        deadline = time.time() + _MAX_POLL_SECONDS
        while time.time() < deadline:
            resp = self._session.get(url, params={"output_mode": "json"}, timeout=15)
            resp.raise_for_status()
            entry = resp.json().get("entry", [{}])[0]
            state = entry.get("content", {}).get("dispatchState", "")
            if state in ("DONE", "FAILED"):
                return
            time.sleep(_DEFAULT_POLL_INTERVAL)
        raise TimeoutError(f"Splunk search job {sid} did not complete within {_MAX_POLL_SECONDS}s")

    def _fetch_results(self, sid: str, count: int = 1000) -> List[Dict[str, Any]]:
        """Fetch search results as a list of raw event dicts."""
        url = f"{self._base_url}/services/search/jobs/{sid}/results"
        resp = self._session.get(
            url,
            params={"output_mode": "json", "count": count},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json().get("results", [])

    def _cleanup_job(self, sid: str) -> None:
        """Delete a completed job to free Splunk resources (best-effort)."""
        try:
            self._session.delete(
                f"{self._base_url}/services/search/jobs/{sid}",
                timeout=10,
            )
        except Exception:
            pass

    def _run_search(
        self,
        query: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """End-to-end: create job → poll → fetch → cleanup."""
        earliest = start_time.strftime("%Y-%m-%dT%H:%M:%S") if start_time else None
        latest = end_time.strftime("%Y-%m-%dT%H:%M:%S") if end_time else None
        sid = self._create_job(query, earliest=earliest, latest=latest)
        try:
            self._poll_job(sid)
            return self._fetch_results(sid, count=limit)
        finally:
            self._cleanup_job(sid)

    # ------------------------------------------------------------------
    # SIEMConnector interface
    # ------------------------------------------------------------------

    def search(
        self,
        query: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Execute a raw SPL query and return results."""
        try:
            return self._run_search(query, start_time=start_time, end_time=end_time, limit=limit)
        except requests.HTTPError as exc:
            raise RuntimeError(f"Splunk API error: {exc}") from exc

    def get_events_by_host(
        self,
        hostname: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_types: Optional[List[str]] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """
        Search all indexes for events referencing *hostname*.

        Event types (Splunk sourcetypes) can optionally be filtered.
        """
        hn = hostname.replace("'", "\\'")
        spl = f'index=* (host="{hn}" OR src_host="{hn}" OR dest_host="{hn}" OR ComputerName="{hn}")'
        if event_types:
            type_filter = " OR ".join(f'sourcetype="{t}"' for t in event_types)
            spl += f" ({type_filter})"
        spl += " | head {limit}".format(limit=limit)
        try:
            return self._run_search(spl, start_time=start_time, end_time=end_time, limit=limit)
        except Exception:
            return []

    def get_events_by_user(
        self,
        username: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_types: Optional[List[str]] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Search all indexes for events referencing *username*."""
        user = username.replace("'", "\\'")
        spl = f'index=* (user="{user}" OR src_user="{user}" OR User="{user}" OR AccountName="{user}")'
        if event_types:
            type_filter = " OR ".join(f'sourcetype="{t}"' for t in event_types)
            spl += f" ({type_filter})"
        spl += " | head {limit}".format(limit=limit)
        try:
            return self._run_search(spl, start_time=start_time, end_time=end_time, limit=limit)
        except Exception:
            return []

    def get_url_clicks(
        self,
        url: Optional[str] = None,
        domain: Optional[str] = None,
        user: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[URLClickEvent]:
        """
        Retrieve URL click events from proxy/web-gateway logs in Splunk.

        The query targets common proxy sourcetypes (Squid, Blue Coat,
        Zscaler, Palo Alto, generic ``proxy``).  Results are normalised into
        URLClickEvent DTOs.
        """
        filters: List[str] = []
        if url:
            safe_url = url.replace('"', '\\"')
            filters.append(f'url="{safe_url}"')
        if domain:
            safe_domain = domain.replace('"', '\\"')
            filters.append(f'(url="*{safe_domain}*" OR domain="{safe_domain}")')
        if user:
            safe_user = user.replace('"', '\\"')
            filters.append(f'(user="{safe_user}" OR src_user="{safe_user}")')

        where_clause = " AND ".join(filters) if filters else "*"
        spl = (
            f"index=proxy OR index=web_gateway OR index=firewall "
            f'sourcetype IN ("squid", "bluecoat", "zscaler", "pan:traffic", "proxy") '
            f"{where_clause} "
            f"| rename _time as ts, src_ip as source_ip, "
            f"  user AS click_user, http_status AS status_code, "
            f"  bytes AS bytes_transferred "
            f"| table ts click_user url source_ip host user_agent referrer "
            f"  status_code bytes_transferred action threat_category "
            f"| head {limit}"
        )
        try:
            raw_events = self._run_search(spl, start_time=start_time, end_time=end_time, limit=limit)
        except Exception:
            return []

        events: List[URLClickEvent] = []
        for i, r in enumerate(raw_events):
            ts = None
            ts_str = r.get("ts") or r.get("_time")
            if ts_str:
                try:
                    ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
                except ValueError:
                    pass
            if ts is None:
                ts = datetime.utcnow()

            action = str(r.get("action", "")).lower()
            was_blocked = action in ("blocked", "denied", "drop")

            status_raw = r.get("status_code")
            try:
                status_code = int(status_raw) if status_raw else None
            except (ValueError, TypeError):
                status_code = None

            bytes_raw = r.get("bytes_transferred")
            try:
                bytes_transferred = int(bytes_raw) if bytes_raw else None
            except (ValueError, TypeError):
                bytes_transferred = None

            events.append(
                URLClickEvent(
                    event_id=f"splunk-{i}",
                    timestamp=ts,
                    user=str(r.get("click_user", r.get("user", "unknown"))),
                    url=str(r.get("url", "")),
                    source_ip=r.get("source_ip") or None,
                    hostname=r.get("host") or None,
                    user_agent=r.get("user_agent") or None,
                    referrer=r.get("referrer") or None,
                    response_code=status_code,
                    bytes_transferred=bytes_transferred,
                    was_blocked=was_blocked,
                    threat_category=r.get("threat_category") or None,
                )
            )
        return events

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    @classmethod
    def is_configured(cls) -> bool:
        """Return True if the required env vars are set."""
        return bool(os.getenv("SPLUNK_TOKEN"))
