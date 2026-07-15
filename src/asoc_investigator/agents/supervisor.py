"""Supervisor routing logic.

Deliberately not an LLM call — it's a thin, deterministic router over the
judge's verdicts and the iteration budget. See docs/ARCHITECTURE.md
"Judge loop and output states".
"""

from __future__ import annotations

from asoc_investigator.graph.state import DEFAULT_MAX_ITERATIONS, InvestigationState


def route_after_judge(state: InvestigationState) -> str:
    """Conditional edge after the judge node: loop back to the investigator
    with feedback, or finalize."""
    verdicts = state.get("judge_verdicts", [])
    max_iterations = state.get("max_iterations", DEFAULT_MAX_ITERATIONS)

    if not verdicts:
        # Shouldn't happen (judge always appends), but fail toward doing
        # more work rather than finalizing on nothing.
        return "investigator"

    if verdicts[-1]["verdict"] == "satisfied":
        return "finalize"

    if state.get("iteration", 0) >= max_iterations:
        # Budget exhausted without a "satisfied" verdict — finalize anyway,
        # flagged for human review. See finalize_node in graph/build.py.
        return "finalize"

    return "investigator"
