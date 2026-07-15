"""File detonation / sandbox analysis tool (mocked — see
docs/ARCHITECTURE.md).

Used when the investigation input is a file rather than a log excerpt. To
wire a real provider (Hybrid Analysis, CAPE, ...): replace the body of
`_detonate` with a real submission + polling flow reading
HYBRID_ANALYSIS_API_KEY from env, keep the same return shape. A real
integration also needs to handle file upload and async result polling —
this mock returns synchronously.
"""

from __future__ import annotations

import hashlib
from typing import Any

from pydantic import BaseModel, Field

from .base import ToolSpec


class SandboxArgs(BaseModel):
    file_reference: str = Field(
        ...,
        description=(
            "The masked token for a file path or hash to detonate in the "
            "sandbox (e.g. PATH_CF10 or SHA256_29E4). Pass the exact token "
            "— never a real path or hash."
        ),
    )


def _detonate(file_reference: str) -> dict[str, Any]:
    """Deterministic mock, shaped like a Hybrid Analysis / CAPE report."""
    digest = hashlib.sha256(file_reference.encode()).hexdigest()
    score = int(digest[:2], 16)
    if score > 150:
        verdict = "malicious"
        behaviors = ["persistence_via_registry_run_key", "outbound_c2_beacon"]
    elif score > 90:
        verdict = "suspicious"
        behaviors = ["unusual_network_connection"]
    else:
        verdict = "benign"
        behaviors = ["network_connection"]
    return {
        "file_reference": file_reference,
        "verdict": verdict,
        "threat_score": score % 100,
        "behaviors": behaviors,
        "sandbox": "mock-sandbox (swap for Hybrid Analysis / CAPE)",
    }


SPEC = ToolSpec(
    name="detonate_file",
    description=(
        "Submit a file (by path or hash) for sandbox detonation. Returns "
        "verdict, a threat score, and observed behaviors (e.g. "
        "persistence, C2 beaconing)."
    ),
    args_schema=SandboxArgs,
    masked_args=("file_reference",),
    impl=_detonate,
)
