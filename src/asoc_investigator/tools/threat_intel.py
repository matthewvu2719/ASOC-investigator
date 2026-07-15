"""Threat intelligence lookup tool — real VirusTotal + AlienVault OTX
integration, with a deterministic mock fallback when neither API key is
configured (see docs/ARCHITECTURE.md "Tools").

Folds in geolocation: VirusTotal's IP report already returns country/ASN,
so there is no separate geolocation provider or tool — the standalone
geolocate_ip tool was removed once this started returning real data. See
docs/ARCHITECTURE.md "The masking boundary" for why this is a plain
function-backed tool rather than an MCP server: the mask/unmask wrapper in
tools/base.py needs to own the moment real values exist.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import urllib.parse
from typing import Any

import httpx
from pydantic import BaseModel, Field

from .base import ToolSpec

_VT_BASE = "https://www.virustotal.com/api/v3"
_OTX_BASE = "https://otx.alienvault.com/api/v1"

_IP_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)


class ThreatIntelArgs(BaseModel):
    indicator: str = Field(
        ...,
        description=(
            "The masked token for an IP address, domain, URL, or file hash "
            "to check reputation for (e.g. IP_A3F9, DOMAIN_1FA9, "
            "SHA256_29E4). Pass the exact token as it appeared in the log "
            "or a prior tool result — never a real value."
        ),
    )


def _classify(value: str) -> str:
    if _URL_RE.match(value):
        return "url"
    if _IP_RE.match(value):
        return "ip"
    if _HASH_RE.match(value):
        return "hash"
    return "domain"


# --- VirusTotal -------------------------------------------------------


def _vt_path(kind: str, value: str) -> str | None:
    if kind == "ip":
        return f"/ip_addresses/{value}"
    if kind == "domain":
        return f"/domains/{value}"
    if kind == "hash":
        return f"/files/{value}"
    if kind == "url":
        url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        return f"/urls/{url_id}"
    return None


def _query_virustotal(indicator: str, kind: str, api_key: str) -> dict[str, Any]:
    path = _vt_path(kind, indicator)
    if path is None:
        return {"virustotal": {"error": f"unsupported indicator type: {kind}"}}

    try:
        resp = httpx.get(f"{_VT_BASE}{path}", headers={"x-apikey": api_key}, timeout=10.0)
    except httpx.HTTPError as exc:
        return {"virustotal": {"error": f"request failed: {exc}"}}

    if resp.status_code == 404:
        return {"virustotal": {"error": "no existing VirusTotal report for this indicator"}}
    if resp.status_code == 429:
        return {"virustotal": {"error": "rate limited (free tier: 4/min, 500/day)"}}
    if resp.status_code != 200:
        return {"virustotal": {"error": f"unexpected status {resp.status_code}"}}

    attrs = resp.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) or 1

    categories = attrs.get("categories")
    result: dict[str, Any] = {
        "verdict": "malicious" if malicious > 0 else "suspicious" if suspicious > 0 else "benign",
        "detections": f"{malicious}/{total}",
        "categories": list(categories.values()) if isinstance(categories, dict) else [],
    }

    # Geolocation folded in here — VT already returns it for IPs. See the
    # module docstring for why there's no separate geolocation tool.
    if kind == "ip":
        result["country"] = attrs.get("country")
        result["asn"] = attrs.get("asn")
        result["as_owner"] = attrs.get("as_owner")

    return {"virustotal": result}


# --- AlienVault OTX -----------------------------------------------------


def _otx_path(kind: str, value: str) -> str | None:
    section = {"ip": "IPv4", "domain": "domain", "hash": "file", "url": "url"}.get(kind)
    if section is None:
        return None
    if kind == "url":
        value = urllib.parse.quote(value, safe="")
    return f"/indicators/{section}/{value}/general"


def _query_otx(indicator: str, kind: str, api_key: str) -> dict[str, Any]:
    path = _otx_path(kind, indicator)
    if path is None:
        return {"alienvault_otx": {"error": f"unsupported indicator type: {kind}"}}

    try:
        resp = httpx.get(f"{_OTX_BASE}{path}", headers={"X-OTX-API-KEY": api_key}, timeout=10.0)
    except httpx.HTTPError as exc:
        return {"alienvault_otx": {"error": f"request failed: {exc}"}}

    if resp.status_code != 200:
        return {"alienvault_otx": {"error": f"unexpected status {resp.status_code}"}}

    pulse_info = resp.json().get("pulse_info", {})
    pulses = pulse_info.get("pulses", [])
    tags = sorted({tag for p in pulses for tag in p.get("tags", [])})

    return {
        "alienvault_otx": {
            "pulse_count": pulse_info.get("count", 0),
            # Named campaigns/threat reports this indicator was tagged in —
            # this is what gives the judge's "grounding" check something
            # more specific to cite than a bare detection ratio.
            "pulse_names": [p.get("name") for p in pulses[:5]],
            "tags": tags[:10],
        }
    }


# --- Mock fallback (no API keys configured) ------------------------------


def _mock_lookup(indicator: str) -> dict[str, Any]:
    """Deterministic mock, shaped like the real responses above. Used
    automatically when neither VIRUSTOTAL_API_KEY nor OTX_API_KEY is set —
    e.g. in scripts/smoke_test_tools.py, which deliberately runs with no
    API keys."""
    digest = hashlib.sha256(indicator.encode()).hexdigest()
    score = int(digest[:2], 16)
    malicious = score > 180 or any(
        hint in indicator.lower() for hint in ("c2", "evil", "malicious", "bad")
    )
    kind = _classify(indicator)

    vt: dict[str, Any] = {
        "verdict": "malicious" if malicious else "benign",
        "detections": f"{score % 30 + 1}/90" if malicious else "0/90",
        "categories": ["c2", "malware"] if malicious else [],
    }
    if kind == "ip":
        countries = ["US", "RU", "CN", "NL", "DE", "BR", "VN", "IR"]
        vt["country"] = countries[int(digest[2:4], 16) % len(countries)]
        vt["asn"] = int(digest[4:8], 16) % 65535
        vt["as_owner"] = "mock-isp (swap for VirusTotal)"

    otx = {
        "pulse_count": (score % 5) if malicious else 0,
        "pulse_names": [f"mock-campaign-{score % 5}"] if malicious else [],
        "tags": ["c2", "botnet"] if malicious else [],
    }
    return {
        "virustotal": vt,
        "alienvault_otx": otx,
        "source": "mock (set VIRUSTOTAL_API_KEY / OTX_API_KEY for real data)",
    }


def _lookup(indicator: str) -> dict[str, Any]:
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY")
    otx_key = os.environ.get("OTX_API_KEY")

    if not vt_key and not otx_key:
        return {"indicator": indicator, **_mock_lookup(indicator)}

    kind = _classify(indicator)
    result: dict[str, Any] = {"indicator": indicator, "indicator_type": kind}
    if vt_key:
        result.update(_query_virustotal(indicator, kind, vt_key))
    if otx_key:
        result.update(_query_otx(indicator, kind, otx_key))
    return result


SPEC = ToolSpec(
    name="threat_intel_lookup",
    description=(
        "Check reputation for an IP address, domain, URL, or file hash "
        "against VirusTotal (verdict, detection count, categories, and — "
        "for IPs — country/ASN) and AlienVault OTX (named campaign/threat "
        "pulses the indicator is tagged in). One call covers reputation, "
        "geolocation, and campaign context together."
    ),
    args_schema=ThreatIntelArgs,
    masked_args=("indicator",),
    impl=_lookup,
)
