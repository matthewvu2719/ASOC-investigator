"""Shared state threaded through the LangGraph StateGraph.

See docs/ARCHITECTURE.md "Pipeline" for the node sequence this state flows
through.
"""

from __future__ import annotations

from typing import Any, Literal, TypedDict

from asoc_investigator.masking import MaskingEngine
from asoc_investigator.rag import IncidentHit

DEFAULT_MAX_ITERATIONS = 3


class JudgeVerdict(TypedDict):
    verdict: Literal["satisfied", "needs_revision"]
    confidence: float
    feedback: str


class InvestigationState(TypedDict, total=False):
    # --- Input ---
    raw_input: str
    input_kind: Literal["log", "file"]

    # --- Masking ---
    # The MaskingEngine instance is carried in-process only — it is never
    # serialized into a prompt. See docs/ARCHITECTURE.md "The masking
    # boundary".
    masking_engine: MaskingEngine
    masked_input: str

    # --- RAG ---
    prior_incidents: list[IncidentHit]

    # --- Investigator (ReAct) ---
    draft_report: str
    investigator_messages: list[Any]

    # --- Judge loop ---
    judge_verdicts: list[JudgeVerdict]
    iteration: int
    max_iterations: int

    # --- Final output (unmasked) ---
    final_report: str
    confidence: float
    needs_review: bool
    review_note: str | None
