"""File detonation / sandbox analysis tool — real Hybrid Analysis (Falcon
Sandbox) integration, with a deterministic mock fallback when
HYBRID_ANALYSIS_API_KEY isn't set (see docs/ARCHITECTURE.md "Tools
reference").

Unlike threat_intel.py, this is a genuine submit-then-poll flow — a real
sandbox has to actually run the file, which takes time. `file_reference`
resolves to one of two things after unmasking:

  - a real absolute file path on the machine this process is running on.
    The CLI passes the local file's path through masking as ordinary text
    (it matches the FILE_PATH pattern and gets tokenized like anything
    else), so by the time this tool unmasks the token it's holding a real,
    readable path. The API layer does the same thing artificially: it
    saves the uploaded bytes to a temp file server-side and puts that
    path in the same spot the CLI would have put a real one — see
    `api/app.py::_resolve_input`. Either way, this tool never knows or
    cares whether the path is "real" from the user's machine or a
    server-side temp copy; it just reads bytes from it.
  - a bare hash (the investigator citing a hash token seen earlier rather
    than a file path). Hash-only lookup against Hybrid Analysis's
    existing-report search — no bytes to submit if nothing's found.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel, Field

from .base import ToolSpec

_HA_BASE = "https://www.hybrid-analysis.com/api/v2"
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")

# Windows 10 64-bit — a reasonable default target for generic Windows
# malware. Hybrid Analysis supports many others (macOS, Linux, Android,
# other Windows versions); hardcoded here rather than exposed as a tool
# argument to keep the LLM-facing schema simple for a v1.
_DEFAULT_ENVIRONMENT_ID = "160"

_POLL_INTERVAL_SECONDS = 10
_POLL_TIMEOUT_SECONDS = 240  # bounded wait — a tool call can't hang the
# investigation forever. Real detonation can legitimately take longer than
# this; if it does, the result is a "still pending" note with a job_id
# rather than a verdict, not a crash.


class SandboxArgs(BaseModel):
    file_reference: str = Field(
        ...,
        description=(
            "The masked token for a file path or hash to detonate in the "
            "sandbox (e.g. PATH_CF10 or SHA256_29E4). Pass the exact token "
            "— never a real path or hash."
        ),
    )


def _classify(value: str) -> str:
    return "hash" if _HASH_RE.match(value) else "path"


def _headers(api_key: str) -> dict[str, str]:
    return {"api-key": api_key, "User-Agent": "asoc-investigator"}


def _format_summary(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "verdict": summary.get("verdict_human", "unknown"),
        "threat_score": summary.get("threat_score"),
        "behaviors": summary.get("classification_tags") or summary.get("tags") or [],
        "sandbox": "Hybrid Analysis",
        "environment": summary.get("environment_description"),
    }


def _search_by_hash(file_hash: str, api_key: str) -> dict[str, Any] | None:
    """Existing-report lookup — cheap, and avoids burning submission quota
    re-detonating something already analyzed. Returns None on any failure
    or miss; callers fall through to submission (or, for a bare-hash
    reference with no bytes available, report that nothing was found)."""
    try:
        resp = httpx.get(
            f"{_HA_BASE}/search/hash",
            headers=_headers(api_key),
            params={"hash": file_hash},
            timeout=15.0,
        )
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:
        return None
    results = resp.json()
    return results[0] if results else None


def _submit_file(path: Path, api_key: str) -> str | None:
    with open(path, "rb") as f:
        try:
            resp = httpx.post(
                f"{_HA_BASE}/submit/file",
                headers=_headers(api_key),
                files={"file": (path.name, f)},
                data={"environment_id": _DEFAULT_ENVIRONMENT_ID},
                timeout=60.0,
            )
        except httpx.HTTPError:
            return None
    if resp.status_code not in (200, 201):
        return None
    return resp.json().get("job_id")


def _poll_and_get_summary(job_id: str, api_key: str) -> dict[str, Any]:
    deadline = time.monotonic() + _POLL_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        try:
            state_resp = httpx.get(
                f"{_HA_BASE}/report/{job_id}/state", headers=_headers(api_key), timeout=15.0
            )
        except httpx.HTTPError as exc:
            return {"error": f"state check failed: {exc}"}

        state_data = state_resp.json() if state_resp.status_code == 200 else {}
        state = state_data.get("state") or state_data.get("status")

        if state == "SUCCESS":
            summary_resp = httpx.get(
                f"{_HA_BASE}/report/{job_id}/summary", headers=_headers(api_key), timeout=15.0
            )
            if summary_resp.status_code != 200:
                return {"error": f"summary fetch failed: HTTP {summary_resp.status_code}"}
            return _format_summary(summary_resp.json())
        if state == "ERROR":
            return {"error": "sandbox analysis failed", "job_id": job_id}

        time.sleep(_POLL_INTERVAL_SECONDS)

    return {
        "status": "pending",
        "job_id": job_id,
        "note": (
            f"Still running after {_POLL_TIMEOUT_SECONDS}s — Hybrid Analysis "
            "detonation can take longer than this tool call waits. Mention "
            "this in the report as pending rather than guessing a verdict; "
            f"job {job_id} can be checked again later."
        ),
    }


def _detonate_real(file_reference: str, api_key: str) -> dict[str, Any]:
    kind = _classify(file_reference)

    if kind == "hash":
        existing = _search_by_hash(file_reference, api_key)
        if existing:
            return {"file_reference": file_reference, **_format_summary(existing)}
        return {
            "file_reference": file_reference,
            "error": (
                "No existing Hybrid Analysis report for this hash, and no "
                "file bytes are available to submit for fresh analysis "
                "(only a hash was provided, not a file)."
            ),
        }

    path = Path(file_reference)
    if not path.is_file():
        return {
            "file_reference": file_reference,
            "error": f"file not found on disk at the resolved path: {file_reference}",
        }

    sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    existing = _search_by_hash(sha256, api_key)
    if existing:
        return {"file_reference": file_reference, **_format_summary(existing)}

    job_id = _submit_file(path, api_key)
    if job_id is None:
        return {"file_reference": file_reference, "error": "submission to Hybrid Analysis failed"}

    return {"file_reference": file_reference, **_poll_and_get_summary(job_id, api_key)}


def _detonate_mock(file_reference: str) -> dict[str, Any]:
    """Deterministic mock, shaped like the real response above. Used when
    HYBRID_ANALYSIS_API_KEY isn't set — e.g. scripts/smoke_test_tools.py,
    which deliberately runs with no API keys."""
    digest = hashlib.sha256(file_reference.encode()).hexdigest()
    score = int(digest[:2], 16)
    if score > 150:
        verdict, behaviors = "malicious", ["persistence_via_registry_run_key", "outbound_c2_beacon"]
    elif score > 90:
        verdict, behaviors = "suspicious", ["unusual_network_connection"]
    else:
        verdict, behaviors = "benign", ["network_connection"]
    return {
        "file_reference": file_reference,
        "verdict": verdict,
        "threat_score": score % 100,
        "behaviors": behaviors,
        "sandbox": "mock-sandbox (set HYBRID_ANALYSIS_API_KEY for real detonation)",
    }


def _detonate(file_reference: str) -> dict[str, Any]:
    api_key = os.environ.get("HYBRID_ANALYSIS_API_KEY")
    if not api_key:
        return _detonate_mock(file_reference)
    return _detonate_real(file_reference, api_key)


SPEC = ToolSpec(
    name="detonate_file",
    description=(
        "Submit a file (by path or hash) for sandbox detonation via Hybrid "
        "Analysis. Returns verdict, a threat score, and observed behaviors "
        "(e.g. persistence, C2 beaconing). Checks for an existing report by "
        "hash before submitting fresh; a first-time submission can take a "
        "couple of minutes to complete."
    ),
    args_schema=SandboxArgs,
    masked_args=("file_reference",),
    impl=_detonate,
)
