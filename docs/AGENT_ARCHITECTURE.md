# AI / Agent Architecture — Design Rationale

This is a companion to [ARCHITECTURE.md](ARCHITECTURE.md): that file is the
exhaustive reference (every module, every endpoint); this one is the
condensed "what did we build, and why is each choice the right one"
explainer for the AI/agents/workflow layer specifically.

---

## Workflow (the LangGraph pipeline)

```
input (log text | file)
  → ingest_and_mask   build a per-investigation MaskingEngine, mask the raw input
  → supervisor         LLM router: decide which specialist to dispatch, or "judge"
       → investigator     ReAct: threat-intel + sandbox tools           ─┐
       → correlation         ReAct: RAG search + MITRE ATT&CK mapping    ├─ back to supervisor
       → remediation            ReAct: mock containment proposal        ─┘  (repeat, bounded by
                                                                              max_agent_steps)
  → judge               single evaluator call — not an agent — scores the combined report
       satisfied?          → finalize
       needs_revision?     → back to supervisor, which routes directly to the named specialist
       budget exhausted?   → finalize anyway, flagged for human review
  → finalize             unmask — the only point real PII re-enters anything
```

One `InvestigationState` `TypedDict` (`src/asoc_investigator/state.py`)
threads through every node. See ARCHITECTURE.md §4 for the full node-by-node
state shape.

---

## The agents, and why this is genuinely multi-agent

Five roles. Four of them are real agents; the fifth is deliberately not
one:

- **Supervisor** (`agents/supervisor.py`) — an **LLM router**. Given what's
  already been produced (`agents_completed`) and, on a revision pass, the
  judge's feedback, it decides which specialist runs next or that there's
  enough for the judge to review. This is the piece that makes "multi-agent
  orchestration" an accurate claim rather than an aspirational one — it's a
  genuine decision (it can skip correlation for a clearly benign finding,
  or skip remediation when nothing warrants action), not a fixed sequence.
- **Investigator** (`agents/investigator.py`) — a **ReAct agent** bound to
  threat-intel and sandbox tools. Always dispatched first — correlation and
  remediation both depend on its findings.
- **Correlation** (`agents/correlation.py`) — a ReAct agent bound to
  prior-incident search (RAG) and a MITRE ATT&CK technique-mapping tool.
  Widens the investigator's findings into broader context.
- **Remediation** (`agents/remediation.py`) — a ReAct agent bound to a
  **mocked** firewall-block proposal tool. Decides whether containment is
  warranted and, if so, proposes a specific action — never executes one.
- **Judge** (`agents/judge.py`) — a **single structured-output LLM call**,
  not an agent: no tools, no loop, no autonomy over what happens next. Own
  fresh context (not any specialist's conversation), so it can't
  rubber-stamp prior reasoning. Scores the combined report and, on
  `needs_revision`, names which specialist's section is deficient
  (`target_agent`) so the fix routes to the right place.

**Why the supervisor is the load-bearing piece of this claim**: a system
where one agent just does everything in one long conversation, or where a
"judge" and "supervisor" are just prose labels on API calls that don't
actually decide anything, isn't multi-agent — it's one agent with
narrative labels stapled on. What makes this genuinely multi-agent is that
four separate LLM-driven components make **real, consequential decisions**
with different jobs and different (mostly non-overlapping) context: the
supervisor decides *what happens next*, three specialists each decide *how
to use their own tools*, and none of them can see or rubber-stamp another's
reasoning directly — everything that crosses between them goes through
explicit state (a report field, a tool-evidence list, a routing decision),
not a shared conversation.

**Why the judge stays honestly labeled as not an agent**: it's one
`llm.invoke()` call with structured output. Calling it an "agent" would be
overclaiming in exactly the way this project has tried to avoid throughout
— see the reasoning below on guardrails, which is really about *not*
trusting an LLM with more autonomy than a given role needs.

---

## Two guardrails that make an LLM router safe to trust

Promoting the supervisor from a deterministic function to an LLM call is a
genuine capability upgrade, but it also introduces a new failure mode: an
LLM deciding control flow can be wrong or indecisive in ways a pure
function can't. Two things bound that:

1. **A hard step budget, independent of the judge's own loop budget.** The
   judge has always had `max_iterations` (default 3) capping revision
   passes. The supervisor now has its own `max_agent_steps` (default 6)
   capping total specialist dispatches — a router that keeps deciding "not
   ready for judge yet" cannot dispatch agents indefinitely just because
   its own loop budget is separate from the judge's.
2. **A structural validation pass after every LLM routing decision.** The
   supervisor doesn't just trust whatever the LLM returns — code enforces
   the invariants that actually matter (investigator must run before
   correlation/remediation; don't re-run an already-completed agent unless
   a revision explicitly targets it) and silently corrects the decision if
   the LLM's choice would violate one. LLM proposes, code enforces.

This is the general pattern worth naming: giving an LLM a *decision* is
fine; giving it *unchecked control* over a loop or an action isn't. The
same principle shows up again in remediation (below).

---

## Why remediation stays mocked

`propose_firewall_block` never calls a real firewall or EDR API — every
proposal comes back explicitly marked `"proposed_pending_human_approval"`.
This is the one tool in the project whose real-world equivalent is
genuinely high-blast-radius: a threat-intel lookup or a sandbox detonation
can't hurt anything by being wrong, but an autonomous block action against
a live environment can. Unlike `threat_intel_lookup` and `detonate_file`
(real integrations with mock fallbacks when no key is configured), this
one has **no real-integration path at all**, by design — CrowdStrike's
Falcon platform does expose a real "contain host" API, so this could
technically be wired up, but doing so without a real human-approval gate
in front of it would be the wrong scope for this project. (There's also no
enforced approval gate yet — the report text says "requires approval," but
nothing downstream currently checks that before, say, displaying it. See
ARCHITECTURE.md §12 for that as an open gap, not a claim.)

---

## Tools and the masking boundary

Every specialist's tools go through the same mask-aware wrapper
(`build_mask_aware_tool` in `tools/base.py`) — the actual safety-critical
piece of this project, unaffected by which specialist is calling it:

- LLMs never see real IPs/hashes/paths/usernames — the wrapper unmasks
  only the declared input fields right before calling the real API, and
  re-masks the response before it re-enters any LLM context.
- The wrapper has a broad `try/except Exception` backstop around the
  underlying call, so an unanticipated failure degrades to a tool-error
  string instead of crashing the graph.
- New tools (`mitre_attack_lookup`, `search_prior_incidents`,
  `propose_firewall_block`) all go through this same wrapper even where
  their arguments aren't masked tokens (`masked_args=()`), purely to get
  the shared exception-handling backstop for free and stay consistent with
  every other tool in the project.
- VirusTotal was chosen over a separate geolocation provider specifically
  because its IP report already returns country/ASN — a `geolocate_ip`
  tool existed briefly and was removed once that became clear.

---

## RAG and MITRE ATT&CK — what "real" means for each

- **RAG** (`search_prior_incidents`, plus an eager lookup at the start of
  the correlation agent's turn): genuinely real — Supabase + pgvector,
  OpenAI embeddings, degrades to `[]` gracefully rather than crashing if
  unconfigured or a query fails.
- **MITRE ATT&CK mapping** (`mitre_attack_lookup`): real technique IDs and
  names, but a small curated local table keyed to the exact behavior-tag
  vocabulary this project's own tools produce (`outbound_c2_beacon`,
  `persistence_via_registry_run_key`, ...), not a live TAXII/STIX feed
  pull. Worth being precise about this distinction if asked: the data is
  real, the *mapping* is heuristic tag-matching, not authoritative
  attribution.

---

## What's actually validated vs. what isn't

Masking/unmasking, the tool boundary, the new tools' mock/real behavior,
and full graph compilation (all 5 nodes wired, conditional routing intact)
are exercised by real smoke tests (`scripts/`) — no live LLM calls in this
environment. The supervisor's actual routing *decisions* and the judge's
`target_agent` attribution haven't been observed against a live model
here — the code paths are implemented and structurally verified, but their
real-world judgment quality is untested without an API key. See
ARCHITECTURE.md §11 for the full real-vs-mocked breakdown.
