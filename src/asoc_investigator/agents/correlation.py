"""ReAct correlation agent.

Widens the investigator's per-indicator findings into broader context:
prior similar incidents (RAG — this is where that eager pre-fetch used to
live as its own graph node, before it became something the supervisor
dispatches on demand) and MITRE ATT&CK technique mapping for any behaviors
the investigator's tools reported. See docs/ARCHITECTURE.md "Agents".
"""

from __future__ import annotations

from typing import Callable

from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from asoc_investigator.rag import IncidentHit, RAGStore
from asoc_investigator.state import InvestigationState
from asoc_investigator.tools.base import build_mask_aware_tool
from asoc_investigator.tools.correlation import (
    build_mitre_lookup_spec,
    build_search_prior_incidents_spec,
)

from ._common import build_revision_turn, is_own_revision_pass, mark_completed

CORRELATION_SYSTEM_PROMPT = """You are a correlation analyst reviewing another \
analyst's investigation of a MASKED security incident (every IP, domain, \
hostname, username, file path, and hash is a token like IP_A3F9 — you will \
never see real values, and must never try to guess them).

You're given the investigator's findings and a list of similar prior \
incidents already retrieved from the incident history (masked). Your job:

1. Assess how closely this incident matches any of the prior incidents — \
   same indicators, same pattern, or genuinely different despite surface \
   similarity.
2. Use search_prior_incidents if you need a MORE specific search than what \
   was already retrieved (e.g. for a particular behavior or indicator type \
   mentioned in the findings).
3. Use mitre_attack_lookup on any behavior/category tags the \
   investigator's sandbox/threat-intel findings mention (e.g. \
   persistence_via_registry_run_key, outbound_c2_beacon) to map them to \
   MITRE ATT&CK techniques and tactics.
4. Produce a short correlation report: prior-incident match assessment, \
   ATT&CK techniques identified (with IDs), and anything this context \
   changes about how the incident should be understood.

If you receive revision feedback from a prior review pass, address it \
directly — don't just restate your previous report."""

RAG_TOP_K = 3


def _format_prior(prior: list[IncidentHit]) -> str:
    if not prior:
        return "No similar prior incidents found in the initial retrieval."
    return "\n".join(f"- {h.masked_summary} (similarity {h.similarity:.2f})" for h in prior)


def _format_context(state: InvestigationState, prior: list[IncidentHit]) -> str:
    return (
        f"MASKED INPUT:\n{state.get('masked_input', '')}\n\n"
        f"INVESTIGATOR'S FINDINGS:\n{state.get('investigator_report') or '(none yet)'}\n\n"
        f"PRIOR INCIDENTS (initial retrieval):\n{_format_prior(prior)}"
    )


def build_correlation(
    model_name: str = "gpt-4.1", rag_store: RAGStore | None = None
) -> Callable[[InvestigationState], dict]:
    store = rag_store or RAGStore()
    llm = ChatOpenAI(model=model_name)

    def correlation_node(state: InvestigationState) -> dict:
        engine = state["masking_engine"]
        specs = [build_mitre_lookup_spec(), build_search_prior_incidents_spec(store)]
        tools = [build_mask_aware_tool(spec, engine) for spec in specs]
        agent = create_react_agent(llm, tools)

        if is_own_revision_pass(state, "correlation_messages"):
            messages = list(state["correlation_messages"]) + [build_revision_turn(state)]
            prior = state.get("prior_incidents", [])
        else:
            prior = store.search(state.get("masked_input", ""), top_k=RAG_TOP_K)
            messages = [
                {"role": "system", "content": CORRELATION_SYSTEM_PROMPT},
                {"role": "user", "content": _format_context(state, prior)},
            ]

        result = agent.invoke({"messages": messages})
        final_message = result["messages"][-1]
        report = (
            final_message.content
            if isinstance(final_message.content, str)
            else str(final_message.content)
        )

        return {
            "correlation_report": report,
            "correlation_messages": result["messages"],
            "prior_incidents": prior,
            "agents_completed": mark_completed(state, "correlation"),
        }

    return correlation_node
