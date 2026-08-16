"""Combines the specialist agents' individual reports into one document —
what the judge evaluates, and what finalize unmasks for the analyst.

Not stored in state: each specialist writes its own report field
(investigator_report, correlation_report, remediation_report), and this
combines whichever of those exist at call time. Computing it on demand
avoids a fourth "combined draft" field that could go stale relative to the
per-agent fields it's derived from.
"""

from __future__ import annotations

from asoc_investigator.state import InvestigationState

_SECTIONS: tuple[tuple[str, str], ...] = (
    ("investigator_report", "Investigation"),
    ("correlation_report", "Correlation"),
    ("remediation_report", "Remediation Recommendation"),
)


def combine_report(state: InvestigationState) -> str:
    sections = [
        f"## {title}\n\n{state[key]}" for key, title in _SECTIONS if state.get(key)
    ]
    return "\n\n".join(sections) if sections else "(no findings yet)"
