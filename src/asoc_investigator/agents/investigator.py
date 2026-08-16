"""ReAct investigator agent.

Bound to the mask-aware tools for one investigation. Never sees real PII —
only masked tokens — and is explicitly instructed not to try to work around
that. Dispatched by the supervisor — always first, since correlation and
remediation both depend on its findings. See docs/ARCHITECTURE.md "Agents".
"""

from __future__ import annotations

from typing import Callable

from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from asoc_investigator.state import InvestigationState
from asoc_investigator.tools import build_tools

from ._common import build_revision_turn, is_own_revision_pass, mark_completed

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

A separate correlation agent handles prior-incident pattern matching and \
MITRE ATT&CK mapping after you — focus on the indicators themselves, not \
on historical context.

Produce a draft investigation report covering:
1. Summary of what happened, referencing the masked tokens involved.
2. Findings per indicator investigated, citing the specific tool result \
   that supports each claim.
3. A clear verdict (malicious / suspicious / benign) and a specific, \
   actionable recommendation — not a hedge.
4. A confidence level (0-1) with a one-line justification.

If you receive revision feedback from a prior review pass, address it \
directly in this draft — don't just restate the previous report."""


def build_investigator(model_name: str = "gpt-4.1") -> Callable[[InvestigationState], dict]:
    """`model_name` is an OpenAI model ID — verify it against your account's
    available models; defaults here are a reasonable starting point, not a
    guarantee of what's current on your plan."""
    llm = ChatOpenAI(model=model_name)

    def investigator_node(state: InvestigationState) -> dict:
        engine = state["masking_engine"]
        tools = build_tools(engine)
        agent = create_react_agent(llm, tools)

        if is_own_revision_pass(state, "investigator_messages"):
            # Continue the SAME conversation — the model keeps its prior tool
            # results and draft, and only has to address what changed rather
            # than re-deriving everything from scratch. See
            # docs/ARCHITECTURE.md "Agents" for why the earlier from-scratch
            # version was a real bug, not just an inefficiency.
            messages = list(state["investigator_messages"]) + [build_revision_turn(state)]
        else:
            messages = [
                {"role": "system", "content": INVESTIGATOR_SYSTEM_PROMPT},
                {"role": "user", "content": f"MASKED INPUT:\n{state['masked_input']}"},
            ]

        result = agent.invoke({"messages": messages})
        final_message = result["messages"][-1]
        report = (
            final_message.content
            if isinstance(final_message.content, str)
            else str(final_message.content)
        )

        return {
            "investigator_report": report,
            "investigator_messages": result["messages"],
            "agents_completed": mark_completed(state, "investigator"),
        }

    return investigator_node
