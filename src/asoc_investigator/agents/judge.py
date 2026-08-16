"""LLM-as-judge evaluation node.

Runs as a separate model call with its own fresh context — not any
specialist agent's conversation — so it can't just rubber-stamp prior
reasoning. A single structured-output call, not an agent: no tools, no
loop, no autonomy over what to do next. Runs for up to `max_iterations`
passes; see `agents/supervisor.py:route_after_judge` for the loop-control
logic, and `route_after_supervisor` for how a needs_revision verdict gets
routed to the specific agent it names.

CURRENTLY same provider as the specialists (OpenAI) for lower dev-loop
friction — a free-tier Gemini key rate-limits exactly when you're iterating
fastest. A cross-provider judge (e.g. Gemini) is a genuinely stronger
independence check — same-family judges tend to share the author model's
blind spots and can be biased toward reasoning that resembles their own —
worth revisiting once the pipeline is stable. Swapping back is a one-line
change: `ChatOpenAI` -> `ChatGoogleGenerativeAI` (from `langchain_google_genai`,
already a project dependency) plus the default `model_name` below.
"""

from __future__ import annotations

from typing import Callable, Literal

from langchain_core.messages import ToolMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from asoc_investigator.report import combine_report
from asoc_investigator.state import InvestigationState

JUDGE_SYSTEM_PROMPT = """You are a security operations quality reviewer. You \
are evaluating a DRAFT investigation report assembled from up to three \
specialist agents (investigator, correlation, remediation) — you did not \
write it and were not part of producing it. Be skeptical; your job is to \
catch what the authors missed or overclaimed, not to be agreeable.

Score the draft against this rubric:
1. Grounding — every factual claim (verdict, indicator reputation, \
   geolocation, sandbox behaviors, ATT&CK technique matches, prior-incident \
   similarity) must match the RAW TOOL RESULTS shown below, not just sound \
   plausible. Cross-check specific numbers and verdicts against what the \
   tools actually returned — flag any claim that doesn't match the \
   evidence, not only claims that sound invented.
2. Completeness — does the investigation section address every indicator \
   that appears to have been investigated? An investigated-but-unmentioned \
   indicator is a defect.
3. Actionability — does the report end with a clear, specific \
   recommendation (e.g. "isolate host", "block IP at perimeter", "no \
   action needed"), not vague hedging like "further investigation may be \
   warranted"? If remediation proposed an action, is it clearly marked as \
   requiring human approval rather than something already done?
4. Calibration — is the stated confidence consistent with the evidence \
   quality? Overclaiming confidence on thin evidence is a defect; so is \
   underclaiming when the evidence is actually solid and consistent.

Return needs_revision if ANY of these fail. When you do, set target_agent \
to whichever specialist's section is actually deficient — "investigator" \
for indicator findings, "correlation" for prior-incident/ATT&CK claims, \
"remediation" for the recommended action — so the fix gets routed to the \
right place. Your feedback must be specific enough that a revision pass \
can act on it directly — name the missing indicator, quote the \
unsupported claim, or state what recommendation is missing. Do not just \
say "improve grounding" — say which sentence isn't grounded and why, and \
which section it's in."""


class JudgeVerdictModel(BaseModel):
    verdict: Literal["satisfied", "needs_revision"] = Field(
        ..., description="Whether the draft is ready to show a human analyst as-is."
    )
    target_agent: Literal["investigator", "correlation", "remediation"] | None = Field(
        default=None,
        description=(
            "If verdict is needs_revision, which specialist's section is "
            "actually deficient and should be redone: 'investigator', "
            "'correlation', or 'remediation'. Null if satisfied, or if the "
            "issue genuinely can't be attributed to one section."
        ),
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Your calibrated confidence in the investigation's conclusions, 0-1 — not a rubber-stamp of the authors' own stated confidence.",
    )
    feedback: str = Field(
        ...,
        description="Specific, actionable feedback. If satisfied, briefly justify why. If needs_revision, state exactly what's missing or unsupported in target_agent's section.",
    )


def _format_tool_evidence(state: InvestigationState) -> str:
    """Pull the actual tool_result messages out of every specialist's
    conversation. Without this, "grounding" can only be judged on whether a
    claim *sounds* specific — with it, the judge can actually check a claim
    against what a tool really returned. See docs/ARCHITECTURE.md "Agents"
    for why this was missing before."""
    messages = [
        *(state.get("investigator_messages") or []),
        *(state.get("correlation_messages") or []),
        *(state.get("remediation_messages") or []),
    ]
    tool_messages = [m for m in messages if isinstance(m, ToolMessage)]
    if not tool_messages:
        return "No tools were called."
    return "\n\n".join(
        f"[{i}] {m.name or 'unknown_tool'} returned:\n{m.content}"
        for i, m in enumerate(tool_messages, 1)
    )


def _format_context(state: InvestigationState) -> str:
    parts = [
        f"DRAFT REPORT:\n{combine_report(state)}",
        f"RAW TOOL RESULTS (verify the draft's claims against these):\n{_format_tool_evidence(state)}",
    ]
    prior = state.get("prior_incidents", [])
    if prior:
        summaries = "\n".join(f"- {h.masked_summary}" for h in prior)
        parts.append(f"PRIOR INCIDENT CONTEXT AVAILABLE TO THE AUTHORS:\n{summaries}")
    return "\n\n".join(parts)


def build_judge(model_name: str = "gpt-4.1") -> Callable[[InvestigationState], dict]:
    """`model_name` is an OpenAI model ID — verify it against your account's
    available models; defaults here are a reasonable starting point, not a
    guarantee of what's current on your plan."""
    llm = ChatOpenAI(model=model_name).with_structured_output(JudgeVerdictModel)

    def judge_node(state: InvestigationState) -> dict:
        verdict: JudgeVerdictModel = llm.invoke(
            [
                {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
                {"role": "user", "content": _format_context(state)},
            ]
        )

        verdicts = list(state.get("judge_verdicts", [])) + [verdict.model_dump()]
        return {
            "judge_verdicts": verdicts,
            "iteration": state.get("iteration", 0) + 1,
        }

    return judge_node
