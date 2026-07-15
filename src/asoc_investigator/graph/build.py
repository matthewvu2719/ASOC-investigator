"""Wires the full pipeline into a compiled LangGraph StateGraph.

Node sequence (see docs/ARCHITECTURE.md "Pipeline"):

    ingest_and_mask -> rag_retrieve -> investigator -> judge
                                              ^            |
                                              +-- loop <---+  (max_iterations)
                                                            |
                                                            v
                                                        finalize
"""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from asoc_investigator.agents import build_investigator, build_judge, route_after_judge
from asoc_investigator.graph.state import DEFAULT_MAX_ITERATIONS, InvestigationState
from asoc_investigator.masking import MaskingEngine
from asoc_investigator.rag import RAGStore

RAG_TOP_K = 3


def _ingest_and_mask_node(state: InvestigationState) -> dict:
    engine = MaskingEngine()
    masked = engine.mask(state["raw_input"])
    return {
        "masking_engine": engine,
        "masked_input": masked,
        "iteration": 0,
        "judge_verdicts": [],
    }


def _build_rag_retrieve_node(store: RAGStore):
    def rag_retrieve_node(state: InvestigationState) -> dict:
        hits = store.search(state["masked_input"], top_k=RAG_TOP_K)
        return {"prior_incidents": hits}

    return rag_retrieve_node


def _finalize_node(state: InvestigationState) -> dict:
    engine = state["masking_engine"]
    verdicts = state.get("judge_verdicts", [])
    last = verdicts[-1] if verdicts else None
    satisfied = last is not None and last["verdict"] == "satisfied"

    # Unmask happens exactly once, here — the only point where plaintext
    # PII is allowed to re-enter anything outside the tool-execution
    # boundary. See docs/ARCHITECTURE.md "The masking boundary".
    final_report = engine.unmask(state.get("draft_report", ""))

    return {
        "final_report": final_report,
        "confidence": last["confidence"] if last else 0.0,
        "needs_review": not satisfied,
        "review_note": None if satisfied else (last["feedback"] if last else "Judge did not run."),
    }


def build_graph(
    investigator_model: str = "gpt-4.1",
    judge_model: str = "gpt-4.1",
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    rag_store: RAGStore | None = None,
):
    """Compile the investigation graph. `rag_store` is injectable for
    testing; defaults to a store that no-ops without Supabase configured.

    Investigator and judge are both OpenAI by default right now (lower
    dev-loop friction than a free-tier Gemini judge) — see agents/judge.py
    for the cross-provider rationale and how to swap the judge back."""
    store = rag_store or RAGStore()

    investigator_node = build_investigator(investigator_model)
    judge_node = build_judge(judge_model)

    graph = StateGraph(InvestigationState)
    graph.add_node("ingest_and_mask", _ingest_and_mask_node)
    graph.add_node("rag_retrieve", _build_rag_retrieve_node(store))
    graph.add_node("investigator", investigator_node)
    graph.add_node("judge", judge_node)
    graph.add_node("finalize", _finalize_node)

    graph.add_edge(START, "ingest_and_mask")
    graph.add_edge("ingest_and_mask", "rag_retrieve")
    graph.add_edge("rag_retrieve", "investigator")
    graph.add_edge("investigator", "judge")
    graph.add_conditional_edges(
        "judge",
        route_after_judge,
        {"investigator": "investigator", "finalize": "finalize"},
    )
    graph.add_edge("finalize", END)

    return graph.compile()


def run_investigation(
    raw_input: str,
    input_kind: str = "log",
    investigator_model: str = "gpt-4.1",
    judge_model: str = "gpt-4.1",
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    rag_store: RAGStore | None = None,
) -> InvestigationState:
    app = build_graph(
        investigator_model=investigator_model,
        judge_model=judge_model,
        max_iterations=max_iterations,
        rag_store=rag_store,
    )
    result = app.invoke(
        {
            "raw_input": raw_input,
            "input_kind": input_kind,
            "max_iterations": max_iterations,
        }
    )
    return result
