"""ReAct remediation agent.

Proposes containment actions (e.g. blocking an indicator at the firewall)
based on the investigator's and correlation agent's findings. Its tool
call is MOCKED — nothing is actually blocked. This is deliberate:
remediation is the one place an autonomous agent could take a real,
high-blast-radius action on a live environment, and this project's scope
is "recommend, don't auto-execute" rather than a live approval workflow.
See docs/ARCHITECTURE.md "Agents" and docs/AGENT_ARCHITECTURE.md.
"""

from __future__ import annotations

from typing import Callable

from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from asoc_investigator.state import InvestigationState
from asoc_investigator.tools.base import build_mask_aware_tool
from asoc_investigator.tools.remediation import SPEC as REMEDIATION_SPEC

from ._common import build_revision_turn, is_own_revision_pass, mark_completed

REMEDIATION_SYSTEM_PROMPT = """You are a remediation analyst reviewing an \
investigation of a MASKED security incident (every IP, domain, hostname, \
username, file path, and hash is a token like IP_A3F9 — you will never see \
real values, and must never try to guess them).

You're given the investigator's and correlation analyst's findings. Decide \
whether containment action is actually warranted:

- If the verdict is benign or the evidence is weak/inconclusive, recommend \
  NO ACTION and say why — proposing a block on thin evidence is a defect, \
  not caution.
- If the evidence supports it (malicious verdict, corroborated by multiple \
  sources), use propose_firewall_block for the specific indicator(s) that \
  warrant it, with a clear reason citing the evidence.

propose_firewall_block is a MOCK tool — it does not actually block \
anything. It records a proposed action for human approval. Always state in \
your final report that any proposed action requires human sign-off before \
execution — you are not authorized to act autonomously.

Produce a short remediation report: recommended action (or explicitly "no \
action"), justification, and confirmation that any block is proposed, not \
executed.

If you receive revision feedback from a prior review pass, address it \
directly — don't just restate your previous report."""


def _format_context(state: InvestigationState) -> str:
    return (
        f"INVESTIGATOR'S FINDINGS:\n{state.get('investigator_report') or '(none yet)'}\n\n"
        f"CORRELATION FINDINGS:\n{state.get('correlation_report') or '(correlation agent did not run)'}"
    )


def build_remediation(model_name: str = "gpt-4.1") -> Callable[[InvestigationState], dict]:
    llm = ChatOpenAI(model=model_name)

    def remediation_node(state: InvestigationState) -> dict:
        engine = state["masking_engine"]
        tools = [build_mask_aware_tool(REMEDIATION_SPEC, engine)]
        agent = create_react_agent(llm, tools)

        if is_own_revision_pass(state, "remediation_messages"):
            messages = list(state["remediation_messages"]) + [build_revision_turn(state)]
        else:
            messages = [
                {"role": "system", "content": REMEDIATION_SYSTEM_PROMPT},
                {"role": "user", "content": _format_context(state)},
            ]

        result = agent.invoke({"messages": messages})
        final_message = result["messages"][-1]
        report = (
            final_message.content
            if isinstance(final_message.content, str)
            else str(final_message.content)
        )

        return {
            "remediation_report": report,
            "remediation_messages": result["messages"],
            "agents_completed": mark_completed(state, "remediation"),
        }

    return remediation_node
