"""Wires the full pipeline into a compiled LangGraph StateGraph.

Node sequence (see docs/ARCHITECTURE.md "Pipeline"):

    ingest_and_mask -> supervisor <-------------------+
                            |  (investigator/           |
                            |   correlation/             |
                            |   remediation, or judge)   |
                            v                            |
                    [specialist agent] -----------------+
                            :
                    supervisor decides "judge" ->  judge
                                                      |  (loop, max_iterations)
                                              +-------+-------+
                                              v               v
                                          supervisor       finalize
                                    (revision, targeted)

The supervisor is a genuine LLM router (agents/supervisor.py) — it decides
which specialist to dispatch next, or that there's enough for the judge to
review, and it's the one that routes a needs_revision verdict back to the
specific agent the judge named. Two independent loop budgets bound this:
`max_iterations` (judge revision passes) and `max_agent_steps` (total
specialist dispatches, since an LLM router could otherwise thrash).
"""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from asoc_investigator.agents import (
    build_correlation,
    build_investigator,
    build_judge,
    build_remediation,
    build_supervisor,
    route_after_judge,
    route_after_supervisor,
)
from asoc_investigator.masking import MaskingEngine
from asoc_investigator.rag import RAGStore
from asoc_investigator.report import combine_report
from asoc_investigator.state import (
    DEFAULT_MAX_AGENT_STEPS,
    DEFAULT_MAX_ITERATIONS,
    InvestigationState,
)


def _ingest_and_mask_node(state: InvestigationState) -> dict:
    engine = MaskingEngine()
    masked = engine.mask(state["raw_input"])
    return {
        "masking_engine": engine,
        "masked_input": masked,
        "iteration": 0,
        "judge_verdicts": [],
        "agents_completed": [],
        "agent_steps": 0,
    }


def _finalize_node(state: InvestigationState) -> dict:
    engine = state["masking_engine"]
    verdicts = state.get("judge_verdicts", [])
    last = verdicts[-1] if verdicts else None
    satisfied = last is not None and last["verdict"] == "satisfied"

    # Unmask happens exactly once, here — the only point where plaintext
    # PII is allowed to re-enter anything outside the tool-execution
    # boundary. See docs/ARCHITECTURE.md "The masking boundary".
    final_report = engine.unmask(combine_report(state))

    return {
        "final_report": final_report,
        "confidence": last["confidence"] if last else 0.0,
        "needs_review": not satisfied,
        "review_note": None if satisfied else (last["feedback"] if last else "Judge did not run."),
    }


def build_graph(
    investigator_model: str = "gpt-4.1",
    judge_model: str = "gpt-4.1",
    supervisor_model: str = "gpt-4.1",
    correlation_model: str = "gpt-4.1",
    remediation_model: str = "gpt-4.1",
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    max_agent_steps: int = DEFAULT_MAX_AGENT_STEPS,
    rag_store: RAGStore | None = None,
):
    """Compile the investigation graph. `rag_store` is injectable for
    testing; defaults to a store that no-ops without Supabase configured.

    All five agent roles are independent model parameters — all default to
    OpenAI right now (lower dev-loop friction than a free-tier Gemini
    judge/supervisor) — see agents/judge.py for the cross-provider
    rationale and how to swap a role back."""
    store = rag_store or RAGStore()

    supervisor_node = build_supervisor(supervisor_model)
    investigator_node = build_investigator(investigator_model)
    correlation_node = build_correlation(correlation_model, store)
    remediation_node = build_remediation(remediation_model)
    judge_node = build_judge(judge_model)

    graph = StateGraph(InvestigationState)
    graph.add_node("ingest_and_mask", _ingest_and_mask_node)
    graph.add_node("supervisor", supervisor_node)
    graph.add_node("investigator", investigator_node)
    graph.add_node("correlation", correlation_node)
    graph.add_node("remediation", remediation_node)
    graph.add_node("judge", judge_node)
    graph.add_node("finalize", _finalize_node)

    graph.add_edge(START, "ingest_and_mask")
    graph.add_edge("ingest_and_mask", "supervisor")
    graph.add_conditional_edges(
        "supervisor",
        route_after_supervisor,
        {
            "investigator": "investigator",
            "correlation": "correlation",
            "remediation": "remediation",
            "judge": "judge",
        },
    )
    graph.add_edge("investigator", "supervisor")
    graph.add_edge("correlation", "supervisor")
    graph.add_edge("remediation", "supervisor")
    graph.add_conditional_edges(
        "judge",
        route_after_judge,
        {"supervisor": "supervisor", "finalize": "finalize"},
    )
    graph.add_edge("finalize", END)

    return graph.compile()


def run_investigation(
    raw_input: str,
    input_kind: str = "log",
    investigator_model: str = "gpt-4.1",
    judge_model: str = "gpt-4.1",
    supervisor_model: str = "gpt-4.1",
    correlation_model: str = "gpt-4.1",
    remediation_model: str = "gpt-4.1",
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    max_agent_steps: int = DEFAULT_MAX_AGENT_STEPS,
    rag_store: RAGStore | None = None,
) -> InvestigationState:
    app = build_graph(
        investigator_model=investigator_model,
        judge_model=judge_model,
        supervisor_model=supervisor_model,
        correlation_model=correlation_model,
        remediation_model=remediation_model,
        max_iterations=max_iterations,
        max_agent_steps=max_agent_steps,
        rag_store=rag_store,
    )
    result = app.invoke(
        {
            "raw_input": raw_input,
            "input_kind": input_kind,
            "max_iterations": max_iterations,
            "max_agent_steps": max_agent_steps,
        }
    )
    return result
