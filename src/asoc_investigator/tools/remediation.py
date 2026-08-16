"""Remediation-agent tool — proposes a containment action.

Deliberately MOCK: it does not call any real firewall/EDR API. It records
a proposed action and returns confirmation that it requires human approval
before anything would actually execute. This is the one tool in the
project whose real-world equivalent is genuinely high-blast-radius (it
would take an action on a live environment, not just look something up),
so the scope here is "recommend, don't auto-execute" rather than a live
integration — see docs/AGENT_ARCHITECTURE.md.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .base import ToolSpec


class FirewallBlockArgs(BaseModel):
    indicator: str = Field(
        ...,
        description=(
            "The masked token for the IP or domain to propose blocking "
            "(e.g. IP_A3F9). Pass the exact token, never a real value."
        ),
    )
    reason: str = Field(..., description="Why this action is recommended, citing specific evidence.")


def _propose_block(indicator: str, reason: str) -> dict[str, Any]:
    return {
        "action": "block_at_firewall",
        "target": indicator,
        "status": "proposed_pending_human_approval",
        "reason": reason,
        "note": (
            "MOCK ACTION — no real firewall/EDR integration exists. This is "
            "not executed automatically; a human analyst must approve it "
            "before anything would actually be blocked."
        ),
    }


SPEC = ToolSpec(
    name="propose_firewall_block",
    description=(
        "Propose blocking an IP or domain at the perimeter firewall. This "
        "is a MOCK action, not a live integration — it never actually "
        "blocks anything; it records the proposal and confirms it requires "
        "human approval."
    ),
    args_schema=FirewallBlockArgs,
    masked_args=("indicator",),
    impl=_propose_block,
)
