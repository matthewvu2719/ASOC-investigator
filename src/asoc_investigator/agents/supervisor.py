"""Supervisor agent — orchestrates the specialist agents.

Unlike the old deterministic router, this is a genuine LLM decision: given
what's been produced so far (and, on a revision pass, the judge's
feedback), it decides which specialist agent acts next, or that there's
enough to send to the judge. This is what makes "supervisor agent"
accurate rather than aspirational — it routes with judgment, not a fixed
if/else. See docs/ARCHITECTURE.md "Agents" and docs/AGENT_ARCHITECTURE.md.

Two independent guardrails keep this bounded even though the routing
itself is now non-deterministic:
  - `max_agent_steps` caps total specialist dispatches per investigation,
    independent of the judge's own `max_iterations` loop budget — an LLM
    router that keeps deciding "not ready yet" must not be able to thrash
    forever.
  - A structural validation pass after the LLM call enforces the two
    invariants that actually matter (investigator must run before
    correlation/remediation; don't re-run an already-completed agent
    outside of an explicit revision target) rather than trusting the raw
    LLM output. LLM proposes, code enforces.
"""

from __future__ import annotations

from typing import Callable, Literal

from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from asoc_investigator.state import (
    DEFAULT_MAX_AGENT_STEPS,
    DEFAULT_MAX_ITERATIONS,
    AgentName,
    InvestigationState,
)

_AGENT_NAMES: tuple[AgentName, ...] = ("investigator", "correlation", "remediation")

SUPERVISOR_SYSTEM_PROMPT = """You are the orchestrator for a security investigation \
pipeline. You do not investigate anything yourself — you decide which \
specialist agent should act next, based on what has already been produced.

Specialists available:
- investigator: pulls indicators (IPs, domains, hashes, files) from the \
  masked input and checks them with threat-intel and sandbox tools. \
  Always run this first — nothing else has anything to work from before \
  it runs.
- correlation: checks prior similar incidents (RAG) and maps observed \
  behaviors to MITRE ATT&CK techniques. Valuable whenever the investigator \
  has flagged suspicious/malicious findings or an ambiguous signal worth \
  pattern-matching; skippable for a clearly benign, isolated finding.
- remediation: proposes containment actions (e.g. blocking an indicator at \
  the firewall). Only run this if the investigation (and correlation, if \
  it ran) point to a verdict that actually warrants action — not for \
  benign findings.

Once you believe there's enough evidence to write a final report, choose \
"judge" — a separate reviewer will evaluate what's been produced and may \
send it back to you with specific feedback about which agent's work needs \
improvement, in which case you should route directly back to that agent.

Only pick agents that haven't already produced a report this pass, unless \
you're specifically re-running one because of reviewer feedback."""


class SupervisorDecision(BaseModel):
    next_agent: Literal["investigator", "correlation", "remediation", "judge"] = Field(
        ...,
        description=(
            "Which specialist agent to invoke next, or 'judge' if enough "
            "work has been done to evaluate the findings so far."
        ),
    )
    reasoning: str = Field(..., description="One sentence: why this agent, or why ready for judge review.")


def _format_supervisor_context(state: InvestigationState) -> str:
    completed = state.get("agents_completed", [])
    lines = [f"Agents that have already produced a report this pass: {completed or 'none yet'}"]
    verdicts = state.get("judge_verdicts", [])
    if verdicts and verdicts[-1]["verdict"] == "needs_revision":
        v = verdicts[-1]
        lines.append(
            f"Reviewer feedback (needs_revision, targeting "
            f"{v.get('target_agent') or 'unspecified'}): {v['feedback']}"
        )
    return "\n".join(lines)


def _pending_revision_target(state: InvestigationState) -> AgentName | None:
    """A revision target the judge just named that hasn't been dispatched
    yet for this judge iteration. Returns None once it's been honored (or
    if there's nothing to honor), so the supervisor falls through to a
    normal LLM decision instead of re-dispatching the same target forever."""
    verdicts = state.get("judge_verdicts", [])
    if not verdicts or verdicts[-1]["verdict"] != "needs_revision":
        return None
    target = verdicts[-1].get("target_agent")
    if target not in _AGENT_NAMES:
        return None
    if state.get("revision_target_handled_at") == state.get("iteration", 0):
        return None
    return target


def build_supervisor(model_name: str = "gpt-4.1") -> Callable[[InvestigationState], dict]:
    """`model_name` is an OpenAI model ID — see agents/investigator.py for
    the same caveat about verifying it against your account."""
    llm = ChatOpenAI(model=model_name).with_structured_output(SupervisorDecision)

    def supervisor_node(state: InvestigationState) -> dict:
        agent_steps = state.get("agent_steps", 0)
        max_agent_steps = state.get("max_agent_steps", DEFAULT_MAX_AGENT_STEPS)

        if agent_steps >= max_agent_steps:
            # Budget exhausted — stop dispatching specialists regardless of
            # what an LLM call would otherwise decide, and let whatever
            # exists go to the judge (which has its own satisfied/exhausted
            # handling and will flag for human review if needed).
            return {"supervisor_decision": "judge"}

        target = _pending_revision_target(state)
        if target is not None:
            # Deterministic — a named revision target is honored directly,
            # no LLM call needed to "decide" what the judge already told us.
            return {
                "supervisor_decision": target,
                "agent_steps": agent_steps + 1,
                "revision_target_handled_at": state.get("iteration", 0),
            }

        completed = set(state.get("agents_completed", []))
        decision = llm.invoke(
            [
                {"role": "system", "content": SUPERVISOR_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"MASKED INPUT:\n{state.get('masked_input', '')}\n\n"
                        f"{_format_supervisor_context(state)}"
                    ),
                },
            ]
        )
        next_agent = decision.next_agent

        # Structural guardrails — don't just trust the LLM's routing choice.
        if next_agent != "judge" and next_agent in completed:
            next_agent = "judge"
        if next_agent in ("correlation", "remediation") and "investigator" not in completed:
            next_agent = "investigator"
        if next_agent == "judge" and "investigator" not in completed:
            next_agent = "investigator"

        if next_agent == "judge":
            return {"supervisor_decision": "judge"}
        return {"supervisor_decision": next_agent, "agent_steps": agent_steps + 1}

    return supervisor_node


def route_after_supervisor(state: InvestigationState) -> str:
    """Conditional edge after the supervisor node: dispatch to whichever
    specialist (or the judge) it decided on."""
    decision = state.get("supervisor_decision")
    if decision not in (*_AGENT_NAMES, "judge"):
        return "investigator"  # shouldn't happen; fail toward doing work
    return decision


def route_after_judge(state: InvestigationState) -> str:
    """Conditional edge after the judge node: loop back to the supervisor
    with feedback, or finalize."""
    verdicts = state.get("judge_verdicts", [])
    max_iterations = state.get("max_iterations", DEFAULT_MAX_ITERATIONS)

    if not verdicts:
        return "supervisor"
    if verdicts[-1]["verdict"] == "satisfied":
        return "finalize"
    if state.get("iteration", 0) >= max_iterations:
        # Budget exhausted without a "satisfied" verdict — finalize anyway,
        # flagged for human review. See finalize_node in graph/build.py.
        return "finalize"
    return "supervisor"
