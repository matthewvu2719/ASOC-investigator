# ASOC Investigator — Architecture

## Goal

Given a security log excerpt or a suspicious file, produce an investigation
report that:

1. Checks for similar prior incidents (RAG over past investigations).
2. Enriches indicators (IPs, domains, hashes, files) via threat intel
   (which includes geolocation and campaign context) and sandbox tools.
3. Never exposes PII to the LLM in plaintext.
4. Self-evaluates its own output (LLM-as-judge) before it's shown to a human,
   for up to 3 revision loops.
5. Surfaces a confidence level, and flags the result for human review when
   the judge isn't satisfied after the loop budget.

## Pipeline

```
input (log text | file)
  -> normalize
  -> mask (PII -> reversible tokens, vault held in-process)
  -> RAG retrieve (similar past incidents, over masked corpus)
  -> supervisor
       -> investigator (ReAct agent, tool calls go through mask-aware executor)
       -> draft report (masked)
  -> judge (evaluates draft against rubric)
       -> satisfied?            -> finalize
       -> needs_revision?       -> back to investigator (max 3 loops total)
       -> max_iterations hit?   -> finalize with review flag
  -> unmask (vault resolves tokens back to real values; ONLY point where
     plaintext PII re-enters anything outside the tool-execution boundary)
  -> render (report + confidence + review flag)
```

State is a single `InvestigationState` TypedDict threaded through a LangGraph
`StateGraph`. See `src/asoc_investigator/graph/state.py`.

## The masking boundary — the load-bearing design decision

The LLM must never see real IPs, hostnames, usernames, emails, file paths,
or hashes tied to a real system[^hashes]. But the tools that do real work
(threat intel lookups, geolocation, sandbox detonation) need the *real*
values to call external APIs.

The resolution: **masking is entity-level and reversible, and unmasking only
happens inside the tool-execution layer — never in a prompt, never in a
response the LLM reads back.**

```
LLM turn:      "look up reputation for IP_A3F9"
                          |
                  ToolExecutor.run()
                          |
                 vault.unmask("IP_A3F9") -> "203.0.113.7"
                          |
                 call real threat-intel API with "203.0.113.7"
                          |
                 vault.mask(response, entities_found_in_response)
                          |
LLM sees:      "IP_A3F9 reputation: malicious, 14 detections. Known C2
                infrastructure. First seen 2024-11-02."
```

Concretely:

- `masking/engine.py` — `MaskingEngine` holds a per-investigation `vault`
  (dict: token -> real value, dict: real value -> token). `mask(text)` finds
  entities via regex and replaces them with deterministic tokens
  (`IP_A3F9`, `HASH_7C21`, `USER_4B10`, ...). Deterministic *within* an
  investigation so the LLM can still reason about "this IP appears in 3
  log lines" — but the vault itself is never serialized to the LLM or
  logged in plaintext anywhere the LLM's context could pick it up.
- `tools/base.py` — `MaskAwareTool` wraps every tool. Before calling the
  underlying implementation, it unmasks whichever input fields are declared
  as "needs real value" for that tool. After the call returns, it re-masks
  any known entities found in the result before the result becomes a
  `tool_result` block. This is why these are custom tools, not MCP or bash:
  the harness needs a typed hook into "before call" / "after call" to do
  this substitution, matching the tool-design guidance for promoting an
  action to a dedicated tool when the harness needs to intercept it.
- The vault is scoped to one investigation and discarded (or persisted
  encrypted, out of scope for v0.1) after unmask-at-finalize. It is not
  stored in the RAG corpus.

[^hashes]: File hashes are not strictly PII, but are treated the same way
here as internal-identifier hygiene — no reason to let them sit in
plaintext in the LLM's context either.

## RAG over prior incidents

Prior incident write-ups are stored **already masked** — they're the output
of this same pipeline, so no unmask step is needed at query time. This
means retrieval never touches the vault: embed the masked current-input
text, query Supabase/pgvector for nearest neighbors, return masked incident
summaries directly into context.

Store: Supabase Postgres + `pgvector` extension. One table (`incidents`)
holding masked summary text, embedding vector, indicator types, and
resolution/confidence metadata. See `rag/schema.sql`.

Embeddings: pluggable via the `Embedder` protocol (`rag/embeddings.py`).
Real embeddings (OpenAI `text-embedding-3-small`) kick in automatically
whenever `OPENAI_API_KEY` is set — which is already required for the
agents, so there's no separate provider to configure. The local,
dependency-free hashing embedder is only a fallback for running with zero
external services at all (e.g. `scripts/smoke_test_rag.py`, which
deliberately doesn't set any API key) — not semantically meaningful, fine
for wiring things up, not for real similarity search.

## Agents

Built with LangGraph, not a hand-rolled loop, per the user's chosen stack.
Investigator and judge are on independent model parameters — currently both
default to OpenAI (see the Judge bullet for why, and how to change it).

- **Supervisor** (`agents/supervisor.py`) — thin routing node, *not* an LLM
  call. Decides whether to hand off to the investigator, request another
  judge pass, or finalize, purely from the judge's last verdict and the
  iteration counter. Holds the "max 3 judge loops" budget.
- **Investigator** (`agents/investigator.py`) — a ReAct agent
  (`langgraph.prebuilt.create_react_agent`) on **OpenAI** (`ChatOpenAI`,
  default `gpt-4.1`) bound to the mask-aware tools: `threat_intel_lookup`
  (VirusTotal + AlienVault OTX — reputation, geolocation, and
  campaign/pulse context in one call) and `detonate_file`. Produces a draft
  report from tool results + RAG context.
- **Judge** (`agents/judge.py`) — a separate LLM call with its own fresh
  context, not the investigator's conversation, so it can't just
  rubber-stamp its own prior reasoning. **Currently OpenAI as well**
  (`ChatOpenAI`, default `gpt-4.1`) — a deliberate, temporary tradeoff:
  a cross-provider judge (e.g. Gemini) is a genuinely stronger independence
  check, since a same-family judge tends to share the author model's blind
  spots and can be biased toward reasoning that resembles its own, but a
  free-tier Gemini key rate-limits exactly when iterating fastest during
  development. Revisit once the pipeline is stable — swapping is one import
  + one default string in `agents/judge.py` (`langchain_google_genai` is
  already a project dependency). Scores the draft against a rubric
  (grounding — every claim traceable to a tool result or RAG hit;
  completeness; actionable recommendation; calibrated confidence) and
  returns structured output: `verdict` (`satisfied` / `needs_revision`),
  `feedback`, `confidence` (0-1).

Both model IDs are parameters (`build_graph(investigator_model=...,
judge_model=...)`, `--investigator-model` / `--judge-model` on the CLI) —
swap either independently of the other without touching agent code.

## Judge loop and output states

```
iteration = 0
loop:
  draft = investigator.run(state)
  verdict = judge.evaluate(draft)
  iteration += 1
  if verdict.verdict == "satisfied": break
  if iteration >= 3: break        # exhausted budget, not necessarily satisfied
  state.feedback = verdict.feedback   # fed back to investigator's next pass
```

Final display:

- Judge satisfied within budget -> show report + confidence, no flag.
- Budget exhausted without satisfaction -> show report + confidence
  **+ "needs human review"** note, and the judge's last feedback is
  attached so a reviewer knows what it flagged.

## Tools

There are only two tools now — `geolocate_ip` was removed once
`threat_intel_lookup` started returning real geolocation as part of the
VirusTotal response (see "The masking boundary" — no reason to keep a
second tool/provider for data the first call already returns).

- **`tools/threat_intel.py`** — real. Queries VirusTotal (reputation,
  detection count, categories, and — for IPs — country/ASN) and AlienVault
  OTX (named campaign/threat pulses) for the same indicator and merges the
  results. Falls back to a deterministic mock, shaped like the real
  responses, when neither `VIRUSTOTAL_API_KEY` nor `OTX_API_KEY` is set —
  e.g. `scripts/smoke_test_tools.py` deliberately runs with no keys.
- **`tools/sandbox.py`** — still mocked. Real detonation (Hybrid
  Analysis/CAPE) is a submit-then-poll flow, not a single request/response
  like the other two providers, so wiring it for real needs a poll loop
  added to the tool, not just a swapped function body.

## What's stubbed vs. real in v0.1

| Component | Status |
|---|---|
| PII masking/unmasking | Real, regex-based entity detection |
| Tool mask/unmask boundary | Real |
| LangGraph supervisor/investigator/judge wiring | Real |
| Judge loop (max 3) | Real |
| Threat intel (`threat_intel_lookup`) | Real — VirusTotal + AlienVault OTX, mock fallback if no keys set |
| Sandbox (`detonate_file`) | Mocked — real integration needs a submit+poll loop, not just a swapped function |
| RAG store | Real Supabase/pgvector schema; needs a Supabase project to actually run |
| Embeddings | Real (OpenAI) automatically once `OPENAI_API_KEY` is set; hashing fallback otherwise |
| File upload / sandbox detonation | Mocked; a real integration would need file upload handling + async polling |

## Open design questions for later

- Vault persistence/expiry policy if investigations need to be resumed.
- Multi-user isolation if this becomes a shared service (vault must never
  cross investigation/tenant boundaries).
- Whether entity detection needs an NER model in addition to regex once
  real logs are noisier than the mocked examples.
