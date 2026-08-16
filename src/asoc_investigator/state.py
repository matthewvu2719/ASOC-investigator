"""Shared state threaded through the LangGraph StateGraph.

Lives at the top level (not inside graph/) deliberately — it's needed by
both graph/build.py and agents/*.py, and graph/build.py itself imports
agents/*. Putting this schema inside the graph package created a real
circular import (agents -> graph.state -> graph/__init__ -> graph/build ->
agents) that only "worked" because every real entry point happened to
import graph before agents; it broke the moment anything imported an
agents submodule directly (e.g. an isolated test), and — more importantly
— no pure-Python trick (deferred imports, TYPE_CHECKING guards) could fix
it without breaking LangGraph's own runtime introspection: LangGraph calls
typing.get_type_hints() on route_after_judge at graph-build time to infer
its schema, which requires InvestigationState to be a real, resolvable
name in that module's globals, not just present for a type checker. See
docs/ARCHITECTURE.md "Agents" for the full story.

See docs/ARCHITECTURE.md "Pipeline" for the node sequence this state flows
through.
"""

from __future__ import annotations

from typing import Any, Literal, TypedDict

from asoc_investigator.masking import MaskingEngine
from asoc_investigator.rag import IncidentHit

DEFAULT_MAX_ITERATIONS = 3

# Independent of DEFAULT_MAX_ITERATIONS (the judge's own revision-loop
# budget): this caps total specialist-agent dispatches per investigation.
# The supervisor is now an LLM making a genuine routing decision each time
# it runs, so — unlike the old deterministic router — it needs a hard
# ceiling of its own. Without this, a supervisor that keeps deciding
# "not ready for judge yet" could dispatch agents indefinitely, independent
# of whether the judge loop is even bounded. See agents/supervisor.py.
DEFAULT_MAX_AGENT_STEPS = 6

AgentName = Literal["investigator", "correlation", "remediation"]


class JudgeVerdict(TypedDict):
    verdict: Literal["satisfied", "needs_revision"]
    # Which specialist agent's output the feedback is about, so the
    # supervisor can route a revision directly to it instead of guessing
    # from prose. None when verdict is "satisfied" (or when the judge
    # genuinely can't attribute the issue to one agent).
    target_agent: AgentName | None
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

    # --- RAG (populated by the correlation agent, see agents/correlation.py) ---
    prior_incidents: list[IncidentHit]

    # --- Specialist agents (each a ReAct agent with its own conversation
    # memory, reused across revision passes — see agents/_common.py) ---
    investigator_report: str
    investigator_messages: list[Any]
    correlation_report: str
    correlation_messages: list[Any]
    remediation_report: str
    remediation_messages: list[Any]

    # --- Supervisor orchestration (see agents/supervisor.py) ---
    agents_completed: list[AgentName]
    agent_steps: int
    max_agent_steps: int
    supervisor_decision: AgentName | Literal["judge"]
    # Records which judge iteration a revision target has already been
    # dispatched for, so the supervisor doesn't re-dispatch the same
    # target forever while waiting for the judge to re-evaluate.
    revision_target_handled_at: int

    # --- Judge loop ---
    judge_verdicts: list[JudgeVerdict]
    iteration: int
    max_iterations: int

    # --- Final output (unmasked) ---
    final_report: str
    confidence: float
    needs_review: bool
    review_note: str | None
