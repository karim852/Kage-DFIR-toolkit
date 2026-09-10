"""Indicator enrichment against VirusTotal and AbuseIPDB.

Constraints taken into account:
  * Free VirusTotal allows 4 requests per minute, so calls are serialised
    and spaced out.
  * Free AbuseIPDB allows 1000 requests per day with no aggressive per-minute
    limit.
  * A disk cache avoids burning the quota twice on the same host.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Callable

import httpx

VT_URL = "https://www.virustotal.com/api/v3"
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"


class Enricher:
    def __init__(
        self,
        vt_key: str = "",
        abuse_key: str = "",
        cache_path: Path | None = None,
        vt_interval: float = 15.5,
    ) -> None:
        self.vt_key = vt_key
        self.abuse_key = abuse_key
        self.vt_interval = vt_interval
        self.cache_path = cache_path
        self.cache: dict[str, dict] = {}
        self._last_vt = 0.0
        if cache_path and cache_path.exists():
            try:
                self.cache = json.loads(cache_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self.cache = {}

    # -- helpers ----------------------------------------------------------
    def _save(self) -> None:
        if not self.cache_path:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self.cache), encoding="utf-8")
        except OSError:
            pass

    async def _vt_throttle(self) -> None:
        wait = self.vt_interval - (time.monotonic() - self._last_vt)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_vt = time.monotonic()

    # -- calls ------------------------------------------------------------
    async def _virustotal(self, client: httpx.AsyncClient, kind: str, value: str) -> dict | None:
        if not self.vt_key:
            return None
        endpoint = {
            "ip": f"{VT_URL}/ip_addresses/{value}",
            "domain": f"{VT_URL}/domains/{value}",
            "sha256": f"{VT_URL}/files/{value}",
            "sha1": f"{VT_URL}/files/{value}",
            "md5": f"{VT_URL}/files/{value}",
        }.get(kind)
        if not endpoint:
            return None

        await self._vt_throttle()
        try:
            response = await client.get(endpoint, headers={"x-apikey": self.vt_key})
        except httpx.HTTPError as exc:
            return {"error": f"VirusTotal unreachable: {exc.__class__.__name__}"}

        if response.status_code == 404:
            return {"found": False}
        if response.status_code == 401:
            return {"error": "VirusTotal key rejected"}
        if response.status_code == 429:
            return {"error": "VirusTotal quota reached"}
        if response.status_code >= 400:
            return {"error": f"VirusTotal HTTP {response.status_code}"}

        attributes = response.json().get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        return {
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation"),
            "label": (attributes.get("popular_threat_classification") or {}).get(
                "suggested_threat_label"
            ),
            "country": attributes.get("country"),
            "as_owner": attributes.get("as_owner"),
            "names": (attributes.get("names") or [])[:3],
        }

    async def _abuseipdb(self, client: httpx.AsyncClient, value: str) -> dict | None:
        if not self.abuse_key:
            return None
        try:
            response = await client.get(
                ABUSE_URL,
                headers={"Key": self.abuse_key, "Accept": "application/json"},
                params={"ipAddress": value, "maxAgeInDays": 90, "verbose": ""},
            )
        except httpx.HTTPError as exc:
            return {"error": f"AbuseIPDB unreachable: {exc.__class__.__name__}"}

        if response.status_code == 401:
            return {"error": "AbuseIPDB key rejected"}
        if response.status_code == 429:
            return {"error": "AbuseIPDB quota reached"}
        if response.status_code >= 400:
            return {"error": f"AbuseIPDB HTTP {response.status_code}"}

        data = response.json().get("data", {})
        return {
            "score": data.get("abuseConfidenceScore", 0),
            "reports": data.get("totalReports", 0),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage": data.get("usageType"),
            "tor": data.get("isTor", False),
            "last_report": data.get("lastReportedAt"),
        }

    # -- orchestration ----------------------------------------------------
    async def enrich(
        self,
        iocs: list[dict],
        limit: int = 25,
        on_progress: Callable[[int, int, dict], None] | None = None,
    ) -> list[dict]:
        selection = iocs[:limit]
        if not selection:
            return []

        async with httpx.AsyncClient(timeout=25.0) as client:
            for index, ioc in enumerate(selection, start=1):
                key = f"{ioc['type']}:{ioc['value']}"
                if key in self.cache:
                    ioc["enrichment"] = self.cache[key]
                else:
                    result: dict = {}
                    vt = await self._virustotal(client, ioc["type"], ioc["value"])
                    if vt is not None:
                        result["virustotal"] = vt
                    if ioc["type"] == "ip":
                        abuse = await self._abuseipdb(client, ioc["value"])
                        if abuse is not None:
                            result["abuseipdb"] = abuse
                    result["checked_at"] = time.time()
                    self.cache[key] = result
                    ioc["enrichment"] = result
                ioc["threat"] = threat_level(ioc)
                if on_progress:
                    on_progress(index, len(selection), ioc)
        self._save()
        return selection


def threat_level(ioc: dict) -> str:
    """Short, readable verdict derived from both sources."""
    data = ioc.get("enrichment") or {}
    vt = data.get("virustotal") or {}
    abuse = data.get("abuseipdb") or {}

    malicious = vt.get("malicious", 0) or 0
    suspicious = vt.get("suspicious", 0) or 0
    score = abuse.get("score", 0) or 0

    if malicious >= 5 or score >= 75:
        return "malicious"
    if malicious >= 1 or suspicious >= 3 or score >= 25:
        return "suspicious"
    if vt.get("found") is False and not abuse:
        return "unknown"
    if not vt and not abuse:
        return "unchecked"
    return "clean"
