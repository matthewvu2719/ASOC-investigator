"""LLM-as-judge evaluation node.

Runs as a separate model call with its own fresh context — not the
investigator's conversation — so it can't just rubber-stamp its own prior
reasoning. Runs for up to `max_iterations` passes; see
`agents/supervisor.py:route_after_judge` for the loop-control logic.

CURRENTLY same provider as the investigator (OpenAI) for lower dev-loop
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

from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from asoc_investigator.graph.state import InvestigationState

JUDGE_SYSTEM_PROMPT = """You are a security operations quality reviewer. You \
are evaluating a DRAFT investigation report written by a different agent — \
you did not write it and were not part of producing it. Be skeptical; your \
job is to catch what the author missed or overclaimed, not to be agreeable.

Score the draft against this rubric:
1. Grounding — every factual claim (verdict, indicator reputation, \
   geolocation, sandbox behaviors) must be traceable to a tool result or \
   prior-incident context shown below. Flag any claim that looks invented \
   or unsupported.
2. Completeness — does the report address every indicator that appears to \
   have been investigated? An investigated-but-unmentioned indicator is a \
   defect.
3. Actionability — does it end with a clear, specific recommendation (e.g. \
   "isolate host", "block IP at perimeter", "no action needed"), not vague \
   hedging like "further investigation may be warranted"?
4. Calibration — is the stated confidence consistent with the evidence \
   quality? Overclaiming confidence on thin evidence is a defect; so is \
   underclaiming when the evidence is actually solid and consistent.

Return needs_revision if ANY of these fail. Your feedback must be specific \
enough that a revision pass can act on it directly — name the missing \
indicator, quote the unsupported claim, or state what recommendation is \
missing. Do not just say "improve grounding" — say which sentence isn't \
grounded and why."""


class JudgeVerdictModel(BaseModel):
    verdict: Literal["satisfied", "needs_revision"] = Field(
        ..., description="Whether the draft is ready to show a human analyst as-is."
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Your calibrated confidence in the investigation's conclusions, 0-1 — not a rubber-stamp of the author's own stated confidence.",
    )
    feedback: str = Field(
        ...,
        description="Specific, actionable feedback. If satisfied, briefly justify why. If needs_revision, state exactly what's missing or unsupported.",
    )


def _format_context(state: InvestigationState) -> str:
    parts = [f"DRAFT REPORT:\n{state['draft_report']}"]
    prior = state.get("prior_incidents", [])
    if prior:
        summaries = "\n".join(f"- {h.masked_summary}" for h in prior)
        parts.append(f"PRIOR INCIDENT CONTEXT AVAILABLE TO THE AUTHOR:\n{summaries}")
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
