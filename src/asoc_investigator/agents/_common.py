"""Shared helpers for the specialist ReAct agents' revision-continuation
pattern.

Every specialist (investigator, correlation, remediation) is invoked
directly by the supervisor when the judge names it as a revision target.
On that pass it should continue its OWN prior conversation and address the
feedback, not start over from the masked input again — see
docs/ARCHITECTURE.md "Agents" for why the from-scratch version was a real
bug in an earlier iteration of this project (silently re-burning
rate-limited API calls, no guarantee the new draft kept what the old one
got right). This module factors that pattern out so all three agents share
one implementation instead of three copies drifting apart.
"""

from __future__ import annotations

from asoc_investigator.state import InvestigationState


def is_own_revision_pass(state: InvestigationState, messages_key: str) -> bool:
    """True when this agent has prior conversation state AND the judge's
    most recent verdict was needs_revision — i.e. the supervisor routed
    back to this specific agent to redo its part."""
    verdicts = state.get("judge_verdicts", [])
    return bool(state.get(messages_key)) and bool(verdicts) and verdicts[-1]["verdict"] == "needs_revision"


def build_revision_turn(state: InvestigationState) -> dict:
    feedback = state["judge_verdicts"][-1]["feedback"]
    return {
        "role": "user",
        "content": (
            "REVISION FEEDBACK FROM REVIEWER:\n"
            f"{feedback}\n\n"
            "Address this directly in an updated report. You already have your "
            "prior tool results and draft above in this conversation — edit and "
            "improve on that, don't start over from nothing, and don't re-call "
            "a tool you already have a result for unless you have a specific "
            "reason to believe it's stale or you need new information."
        ),
    }


def mark_completed(state: InvestigationState, agent_name: str) -> list[str]:
    """Append `agent_name` to agents_completed, deduping while preserving
    order — an agent re-run as an explicit revision target shouldn't appear
    twice."""
    return list(dict.fromkeys([*state.get("agents_completed", []), agent_name]))
