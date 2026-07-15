"""ReAct investigator agent.

Bound to the mask-aware tools for one investigation. Never sees real PII —
only masked tokens — and is explicitly instructed not to try to work around
that. See docs/ARCHITECTURE.md "Agents".
"""

from __future__ import annotations

from typing import Callable

from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from asoc_investigator.graph.state import InvestigationState
from asoc_investigator.tools import build_tools

INVESTIGATOR_SYSTEM_PROMPT = """You are a security investigator. You are given \
a MASKED security log or file description — every IP, domain, hostname, \
username, email, file path, and hash has been replaced with a token like \
IP_A3F9, DOMAIN_1FA9, USER_D0F5, PATH_CF10, SHA256_29E4. You will never see \
the real values, and you must never try to guess, reconstruct, or ask for \
them — that is by design, not a limitation to work around.

Use the available tools to investigate: threat_intel_lookup (reputation, \
geolocation, and campaign/pulse context for an IP, domain, URL, or hash — \
one call covers all of that) and detonate_file. Always pass the exact \
masked token as the argument — the tools resolve it to the real value \
internally to do the actual lookup, and mask the result again before it \
reaches you.

You also have RAG context from prior investigations (already masked) — use \
it to check whether this matches a known pattern, but don't assume it's the \
same incident just because it's similar.

Produce a draft investigation report covering:
1. Summary of what happened, referencing the masked tokens involved.
2. Findings per indicator investigated, citing the specific tool result \
   that supports each claim.
3. Whether this matches any prior incident pattern, and how closely.
4. A clear verdict (malicious / suspicious / benign) and a specific, \
   actionable recommendation — not a hedge.
5. A confidence level (0-1) with a one-line justification.

If you receive revision feedback from a prior review pass, address it \
directly in this draft — don't just restate the previous report."""


def _format_rag_context(state: InvestigationState) -> str:
    prior = state.get("prior_incidents", [])
    if not prior:
        return "No similar prior incidents found."
    return "\n".join(f"- {h.masked_summary} (similarity {h.similarity:.2f})" for h in prior)


def _format_revision_note(state: InvestigationState) -> str:
    verdicts = state.get("judge_verdicts", [])
    if not verdicts or verdicts[-1]["verdict"] != "needs_revision":
        return ""
    return (
        "\n\nREVISION FEEDBACK FROM REVIEWER (address this directly, don't "
        f"just restate your previous draft):\n{verdicts[-1]['feedback']}"
    )


def build_investigator(model_name: str = "gpt-4.1") -> Callable[[InvestigationState], dict]:
    """`model_name` is an OpenAI model ID — verify it against your account's
    available models; defaults here are a reasonable starting point, not a
    guarantee of what's current on your plan."""
    llm = ChatOpenAI(model=model_name)

    def investigator_node(state: InvestigationState) -> dict:
        engine = state["masking_engine"]
        tools = build_tools(engine)
        agent = create_react_agent(llm, tools)

        user_content = (
            f"MASKED INPUT:\n{state['masked_input']}\n\n"
            f"PRIOR INCIDENT CONTEXT:\n{_format_rag_context(state)}"
            f"{_format_revision_note(state)}"
        )

        result = agent.invoke(
            {
                "messages": [
                    {"role": "system", "content": INVESTIGATOR_SYSTEM_PROMPT},
                    {"role": "user", "content": user_content},
                ]
            }
        )
        final_message = result["messages"][-1]
        draft = (
            final_message.content
            if isinstance(final_message.content, str)
            else str(final_message.content)
        )

        return {
            "draft_report": draft,
            "investigator_messages": result["messages"],
        }

    return investigator_node
