# ASOC Investigator — Documentation

## 1. What this app does

Give it a security log excerpt or a suspicious file. It:

1. **Checks for similar prior incidents** — retrieves masked write-ups of
   past investigations from a vector store (RAG), so the investigator has
   pattern context before it starts.
2. **Investigates the indicators** — a ReAct agent pulls out IPs, domains,
   URLs, hashes, hostnames, etc. and calls tools to enrich them: threat
   intelligence (reputation, geolocation, campaign attribution) and sandbox
   detonation for files.
3. **Never lets an LLM see real PII** — every identifier is replaced with a
   reversible token before it reaches any model. Real values exist only for
   the instant it takes to call a real provider API, inside code the app
   controls — never in a prompt, never in a response a model reads back.
4. **Reviews its own output** — a separate LLM call (the "judge") scores
   the investigator's draft against a rubric and can send it back for
   revision, up to 3 times.
5. **Returns a report with a confidence level**, unmasked, flagged for
   human review if the judge wasn't satisfied within the loop budget.

It's usable two ways: a CLI (`asoc-investigate`) and a web app (FastAPI
backend + Next.js frontend with live streaming progress).

---

## 2. Tech stack

| Layer | Choice | Why |
|---|---|---|
| Orchestration | **LangGraph** (`StateGraph`) | Explicit graph of nodes/edges instead of a hand-rolled loop; conditional routing for the judge loop |
| LLMs | **OpenAI** (investigator + judge, for now — see §7) via `langchain-openai` | User's choice; `langchain-google-genai` stays installed for an easy swap back to a cross-provider judge |
| RAG store | **Supabase** (Postgres + `pgvector`) | One database for relational metadata and vector search, generous free tier |
| Embeddings | **OpenAI** `text-embedding-3-small`, local hashing fallback | No separate provider needed — reuses the same `OPENAI_API_KEY` already required for the agents |
| Threat intel | **VirusTotal** + **AlienVault OTX** | Free tiers; VirusTotal covers reputation *and* geolocation in one call; OTX adds named campaign context |
| Backend API | **FastAPI** + **uvicorn** | Blocking and SSE-streaming endpoints over the same graph |
| Frontend | **Next.js 16** (App Router, TypeScript, Tailwind) | Form + live progress view + report display |
| Package/env | Python 3.11+, `venv`, `pyproject.toml` | Standard, no exotic tooling |

---

## 3. System architecture

```
┌─────────────────┐        HTTP / SSE        ┌──────────────────────────┐
│  Next.js (3000)  │ ───────────────────────▶ │  FastAPI (8000)          │
│  form + progress │ ◀─────────────────────── │  api/app.py              │
│  + report view   │      streamed events      │  api/streaming.py        │
└─────────────────┘                            └───────────┬──────────────┘
                                                             │ builds + invokes
                                                             ▼
                                                ┌──────────────────────────┐
                                                │  LangGraph StateGraph     │
                                                │  graph/build.py           │
                                                │                           │
                                                │  ingest_and_mask          │
                                                │       │                   │
                                                │  rag_retrieve ───────────┼──▶ Supabase / pgvector
                                                │       │                   │
                                                │  investigator (ReAct) ───┼──▶ VirusTotal
                                                │       │       │           │  ▶ AlienVault OTX
                                                │       │       └──────────┼──▶ Hybrid Analysis (sandbox)
                                                │       ▼                   │
                                                │     judge                 │
                                                │       │  (loop, max 3)    │
                                                │       ▼                   │
                                                │    finalize                │
                                                └──────────────────────────┘
```

The CLI (`cli.py`) calls the same `graph.build_graph()` / `run_investigation()`
directly — it doesn't go through the API. The API exists only for the web
frontend (and anything else that wants HTTP access to the same pipeline).

### Repository layout

```
src/asoc_investigator/
  masking/
    entities.py      # regex patterns for IP/domain/URL/email/hash/path/username
    engine.py         # MaskingEngine — the reversible token vault
  tools/
    base.py           # ToolSpec + the mask-aware wrapper (the safety boundary)
    threat_intel.py   # threat_intel_lookup — real VirusTotal + OTX, mock fallback
    sandbox.py         # detonate_file — real Hybrid Analysis (submit+poll), mock fallback
    registry.py         # binds ToolSpecs to one investigation's MaskingEngine
  rag/
    embeddings.py       # Embedder protocol: OpenAIEmbedder (real) / HashingEmbedder (fallback)
    store.py             # RAGStore — Supabase/pgvector wrapper, degrades gracefully
    schema.sql             # incidents table + match_incidents() function — run once per Supabase project
  agents/
    investigator.py         # ReAct agent (OpenAI), bound to the tools
    judge.py                  # LLM-as-judge, structured output, separate context
    supervisor.py               # deterministic loop-control router (not an LLM call)
  graph/
    state.py                      # InvestigationState TypedDict — the shared state schema
    build.py                        # wires nodes + edges into a compiled graph
  api/
    app.py                           # FastAPI app: /api/investigate, /api/investigate/stream, /api/health
    streaming.py                      # bridges LangGraph's sync .stream() onto a background thread for SSE
  cli.py                              # `asoc-investigate` entry point

frontend/
  app/page.tsx                        # the whole UI (client component)
  components/
    InvestigationForm.tsx              # log/file input, sample-log generator buttons, model params
    ProgressLog.tsx                      # renders streamed per-node updates
    ReportView.tsx                         # final report + confidence badge + review flag
  lib/
    api.ts                                  # runInvestigationStream() — POSTs to /api/investigate/stream
    sse.ts                                    # hand-rolled SSE parser (fetch-based, not EventSource — see §9)
    sampleLogs.ts                               # raw-log generators for Sentinel/CrowdStrike/Splunk/etc.
    types.ts                                      # TypeScript mirrors of the backend's JSON shapes

docs/ARCHITECTURE.md                                # this file
scripts/                                              # smoke tests — see §11
```

---

## 4. Pipeline (the LangGraph)

```
input (log text | file)
  -> ingest_and_mask   (build a per-investigation MaskingEngine, mask the raw input)
  -> rag_retrieve       (embed the masked input, query Supabase/pgvector for similar prior incidents)
  -> investigator        (ReAct agent; tool calls go through the mask-aware executor)
       -> draft report (masked)
  -> judge                 (evaluates draft against a rubric)
       -> satisfied?            -> finalize
       -> needs_revision?       -> back to investigator, with feedback (max 3 loops total)
       -> max_iterations hit?   -> finalize anyway, flagged for review
  -> finalize                     (unmask — the ONLY point plaintext PII re-enters
                                    anything outside the tool-execution boundary)
  -> render (report + confidence + review flag)
```

State is one `InvestigationState` `TypedDict` (`graph/state.py`) threaded through
every node: `raw_input`, `masking_engine`, `masked_input`, `prior_incidents`,
`draft_report`, `judge_verdicts`, `iteration`, `final_report`, `confidence`,
`needs_review`, `review_note`. `masking_engine` and `investigator_messages`
are process-internal only — the API layer strips them before anything crosses
the HTTP boundary (see §8).

---

## 5. The masking boundary — the load-bearing design decision

No LLM in this app ever sees a real IP, hostname, username, email, file
path, or hash[^hashes]. But the tools that do real work (threat intel
lookups, sandbox detonation) need the *real* values to call external APIs.

**Resolution: masking is entity-level and reversible, and unmasking only
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

- **`masking/engine.py`** — `MaskingEngine` holds a per-investigation
  `vault` (dict: token → real value, dict: real value → token).
  `mask(text)` finds entities via regex (`masking/entities.py`: IP, domain,
  URL, email, SHA256/SHA1/MD5, MAC, username, hostname, file path) and
  replaces them with deterministic tokens (`IP_A3F9`, `HASH_7C21`,
  `USER_4B10`, ...). Deterministic *within* an investigation so the LLM can
  still reason about "this IP appears in 3 log lines" — but the vault
  itself is never serialized to the LLM or logged in plaintext anywhere
  the LLM's context could pick it up. `unmask(text)` reverses it;
  `resolve(token)` resolves a single token (used by the tool wrapper).
- **`tools/base.py`** — `build_mask_aware_tool(spec, engine)` wraps every
  tool. Before calling the underlying implementation, it unmasks whichever
  input fields are declared in `spec.masked_args`. After the call returns,
  it recursively re-masks every string in the result **before**
  JSON-serializing it — masking must happen on raw Python values, not on
  the already-escaped JSON string, or backslash-heavy content (Windows
  paths) breaks the regex on the re-mask pass (a real bug caught during
  development — see the smoke test). This is why these are custom
  function-backed tools, not MCP or bash: the harness needs a typed
  "before call / after call" hook to do this substitution, and a
  third-party MCP server would either receive a token it can't resolve, or
  require unmasking before the call anyway — at which point you've
  rebuilt this wrapper behind an extra protocol hop for no gain.
- The vault is scoped to one investigation and discarded after
  unmask-at-finalize (persistence/expiry policy for resumable
  investigations is an open question — see §12). It is never stored in the
  RAG corpus — prior incidents are written up and stored *already masked*.

[^hashes]: File hashes aren't strictly PII, but are treated the same way as
internal-identifier hygiene — no reason to let them sit in plaintext in an
LLM's context either.

---

## 6. RAG over prior incidents

Prior incident write-ups are stored **already masked** — they're the
output of this same pipeline — so retrieval never touches the vault: embed
the masked current-input text, query Supabase/pgvector for nearest
neighbors, return masked incident summaries directly into context.

- **Store**: Supabase Postgres + `pgvector`. One table (`incidents`)
  holding masked summary text, an embedding vector, indicator types, and
  resolution/confidence metadata. Schema + the `match_incidents()` RPC
  function live in `rag/schema.sql` — **run once per Supabase project**
  (SQL Editor → paste → run; enable RLS when prompted, since this app only
  ever accesses the table via the `service_role` key, which bypasses RLS
  regardless — see the README).
- **Embeddings**: pluggable via the `Embedder` protocol
  (`rag/embeddings.py`). `OpenAIEmbedder` (`text-embedding-3-small`,
  1536-dim) is used automatically whenever `OPENAI_API_KEY` is set — no
  separate key. `HashingEmbedder` (256-dim, dependency-free, deterministic
  bag-of-words) is the fallback for running with zero external services at
  all (e.g. `scripts/smoke_test_rag.py`). `rag/schema.sql`'s
  `vector(1536)` column matches the real embedder, the practical default.
- **Resilience**: `RAGStore` degrades gracefully in two distinct failure
  modes — not configured at all (`SUPABASE_URL`/`SUPABASE_SERVICE_ROLE_KEY`
  unset → `search()` returns `[]` without attempting a connection), and
  configured but failing (schema not yet applied, network error, rate
  limit → the query is wrapped in try/except, logs a warning, and still
  returns `[]`). RAG is enrichment, not a hard dependency — a failure here
  must never take down the whole investigation.
- **Known gap**: `RAGStore.upsert_incident()` is never called anywhere in
  the graph. The corpus doesn't grow from the app's own use yet — see §12.

---

## 7. Agents

Built with LangGraph, not a hand-rolled loop. Investigator and judge are
independent model parameters — currently both default to OpenAI.

- **Supervisor** (`agents/supervisor.py`, `route_after_judge`) — a thin
  deterministic router, **not an LLM call**. Reads the judge's last
  verdict and the iteration counter to decide "back to investigator" vs
  "finalize." Holds the max-3-loops budget.
- **Investigator** (`agents/investigator.py`) — a **ReAct** agent
  (`langgraph.prebuilt.create_react_agent`) on OpenAI (`ChatOpenAI`,
  default `gpt-4.1`), bound to the mask-aware tools (§10). "ReAct"
  (Reason + Act) is the standard tool-use agent pattern: the LLM
  alternates between reasoning about what it needs next and emitting a
  tool call, reads the tool's result back into the *same* conversation,
  reasons about that, and repeats — calling more tools or stopping to
  produce a final answer — until it decides it has enough to answer
  without another tool call. `create_react_agent` implements exactly this
  loop; nothing about it is bespoke to this project. System prompt
  explicitly tells it the input is masked and instructs it never to try to
  guess/reconstruct real values — that's by design, not a limitation to
  work around. Produces a draft report: summary, per-indicator findings
  (each citing the tool result that supports it), prior-incident pattern
  match, verdict + recommendation, confidence + justification. On a
  revision pass, prior judge feedback is appended to the user turn.
- **Judge** (`agents/judge.py`) — a separate LLM call with its **own fresh
  context** (not the investigator's conversation), so it can't rubber-stamp
  its own prior reasoning. Currently OpenAI as well (`ChatOpenAI`, default
  `gpt-4.1`) — a deliberate, **temporary** tradeoff: a cross-provider judge
  (e.g. Gemini) is a genuinely stronger independence check, since a
  same-family judge tends to share the author model's blind spots, but a
  free-tier Gemini key rate-limits exactly when iterating fastest during
  development. Revisit once the pipeline is stable — swapping is one
  import + one default string in `agents/judge.py`
  (`langchain_google_genai` is already installed for this). Scores the
  draft against a rubric — **grounding** (every claim traceable to a tool
  result or RAG hit), **completeness** (every investigated indicator
  addressed), **actionability** (a specific recommendation, not a hedge),
  **calibration** (stated confidence matches evidence quality) — and
  returns structured output (Pydantic → `with_structured_output`):
  `verdict` (`satisfied`/`needs_revision`), `confidence` (0–1), `feedback`.

Both model IDs are independent parameters everywhere: `build_graph(
investigator_model=..., judge_model=...)`, `--investigator-model` /
`--judge-model` on the CLI, `investigator_model` / `judge_model` fields on
the API request bodies.

### Why ReAct here, not a fixed pipeline

Worth being honest that ReAct isn't the only option, and is arguably more
than the current tool set strictly needs — it's a real tradeoff, not an
obvious choice.

**What it buys**: the investigator only ever sees opaque masked tokens
(`IP_A3F9`, `DOMAIN_1FA9`, ...) with no way to know in advance which
represent real signal vs. noise — an internal `10.0.5.23` isn't worth a
VirusTotal call; an external IP probably is. A ReAct agent can exercise
judgment about *which* indicators are worth investigating and in what
order, rather than blindly checking every single one — which matters
given VirusTotal's free tier is 4 requests/minute, so naively checking
every token in a busy log would burn through quota fast. It also means
future conditional logic ("if OTX flags a specific campaign, dig into it
further") is just a prompt change, not a rewrite.

**The honest alternative**: with only two tools, and a token list the
masking engine already hands you cleanly typed
(`engine.known_tokens()`, `entity_type_of()`), this could instead be a
fully deterministic pipeline — loop over every known token by type, call
the matching tool on each in plain code, then a single LLM call at the end
to synthesize a report from all the masked results. That would be more
predictable, cheaper (no reasoning overhead, no risk of the model skipping
something it shouldn't), and easier to test than an agent loop.

**When each is the right call**: ReAct earns its complexity if the tool
surface and investigation logic keep growing and relevance judgment stays
valuable. **This is the actual reason it's kept here** — the plan is to
extend the investigator with more tools over time, at which point
"decide which of N tools are relevant, in what order, and whether a result
warrants a follow-up call" stops being optional and becomes exactly the
problem ReAct solves. For today's 2-tool set alone it would be defensible
to call this over-engineered; it stops being over-engineered the moment a
third or fourth tool shows up and the deterministic "call everything"
pipeline would otherwise need hand-written branching logic to decide what
to skip and what to chain.

### Worked example: a tool call, end to end

It's easy to conflate "the investigator calls a tool" with "an LLM
evaluates the tool's result" as two separate model calls. They aren't —
it's one continuous reasoning loop, with a genuinely separate model call
only happening afterward, over the finished draft. Concretely, for a
`detonate_file` call:

1. The **investigator LLM** is mid-conversation, working through the
   masked input. It decides it needs to check a file and emits a tool
   call: `detonate_file(file_reference=PATH_XXXX)`.
2. LangGraph's ReAct loop intercepts that call, routes it through the
   mask-aware wrapper (§5), unmasks the token, runs the real Hybrid
   Analysis logic (§10), gets back a report, re-masks anything sensitive
   in the result, and hands it back **into the same conversation** as a
   `tool_result` message.
3. **The same investigator LLM** reads that result — still the same agent
   turn, same context, not a fresh call — and reasons about it: does this
   verdict corroborate what `threat_intel_lookup` already found? Does the
   C2-beacon behavior match an IP already seen in the log? It can call
   more tools if it needs to, or move on to write its draft report,
   weaving the sandbox finding in as one piece of evidence among several.
4. Only **after** a complete draft report exists does a genuinely separate
   LLM call happen: the **judge**, in its own fresh context. But the judge
   doesn't re-read the raw Hybrid Analysis data — it evaluates the
   investigator's *draft report as a whole* against its rubric (is every
   claim traceable to a tool result, is the recommendation specific,
   etc.). "You cited a malicious verdict but didn't say what behaviors
   support it" is exactly the kind of thing that sends a draft back for
   revision.

So: one agent, one tool call, one continuous reasoning pass to synthesize
the finding into the draft — then a second, independent LLM pass that
reviews the finished draft, not the raw tool data itself.

### Judge loop

```
iteration = 0
loop:
  draft = investigator.run(state)          # sees prior judge feedback, if any
  verdict = judge.evaluate(draft)
  iteration += 1
  if verdict.verdict == "satisfied": break
  if iteration >= max_iterations: break     # exhausted budget, not necessarily satisfied
  # loop back to investigator with verdict.feedback in context
```

Final display: judge satisfied within budget → report + confidence, no
flag. Budget exhausted without satisfaction → report + confidence **+
"needs human review"**, with the judge's last feedback attached so a
reviewer knows what it flagged.

---

## 8. Backend API (FastAPI)

`src/asoc_investigator/api/app.py`, run with
`uvicorn asoc_investigator.api.app:app --reload` (port 8000 by default).
CORS is currently locked to `http://localhost:3000` (add your deployed
frontend origin before shipping this anywhere).

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/health` | GET | Liveness check, returns `{"status": "ok"}` |
| `/api/investigate` | POST | Blocking — JSON body (`log_text`, `investigator_model`, `judge_model`, `max_iterations`), runs the full graph, returns the final state as JSON |
| `/api/investigate/stream` | POST | Streaming — multipart form (`log_text` or `file`, plus the same model params), Server-Sent Events, one event per graph node as it completes |

**Why SSE needs a custom bridge**: the graph's node functions are
synchronous (investigator/judge make blocking LLM calls). `api/streaming.py`
runs `compiled_graph.stream(...)` on a background thread and relays events
into an `asyncio.Queue` via `loop.call_soon_threadsafe`, so a
multi-minute investigation doesn't block FastAPI's event loop for other
requests.

**What crosses the API boundary**: `_serialize_update()` /
`_public_result()` in `api/app.py` strip `masking_engine` (never
serializable — it's the vault) and `investigator_messages` (raw LangChain
message objects) from every response. `prior_incidents` (a list of
`IncidentHit` dataclasses) gets `dataclasses.asdict()`'d. Everything else
in `InvestigationState` is already JSON-safe.

**SSE event shape**: each `data:` line is `{node_name: partial_state}` for
whichever node just completed (`ingest_and_mask`, `rag_retrieve`,
`investigator`, `judge`, or `finalize`) — a discriminated-by-key-presence
union the frontend switches on (see §9). Terminal events use the SSE
`event:` field: `event: done` (stream complete) or `event: error` (an
exception surfaced from the worker thread, with `{"message": "..."}` as
the payload).

**File uploads**: `_resolve_input()` writes the uploaded bytes to a
server-side temp file (`tempfile.gettempdir()/asoc_investigator_uploads/`,
UUID-prefixed, client filename reduced to its basename before use in a
path) and puts that temp path into `raw_input` — the pipeline treats it
exactly like a CLI-submitted local file (see §10, `detonate_file`). The
temp file is deleted in `event_generator()`'s `finally` block once the
investigation is fully done with it, whether it succeeded or errored. No
file-size limit is enforced yet (see §12).

---

## 9. Frontend (Next.js)

Everything lives in one client component (`app/page.tsx`, `"use client"`)
composing three pieces:

- **`InvestigationForm.tsx`** — toggles between log-text and file-upload
  input; five "generate sample" buttons (`lib/sampleLogs.ts`) that fill the
  textarea with randomized, realistic **raw** log data (Azure AD
  `SignInLogs` JSON, CrowdStrike Falcon Data Replicator-style telemetry,
  raw syslog SSH lines, a verbatim Windows Security Event 4625 text dump,
  a Squid-style proxy access-log line) — deliberately raw ingested-log
  shapes, not formatted alert summaries, so the masking engine gets
  exercised against realistic messy input; investigator/judge model
  fields; max-iterations field.
- **`ProgressLog.tsx`** — renders each streamed node update as a
  human-readable line (`describeUpdate()` in `page.tsx` turns e.g. a
  `judge` update into "Needs revision (confidence 62%): ...").
- **`ReportView.tsx`** — final report (`whitespace-pre-wrap`, not
  markdown-rendered — a deliberate v1 simplification), confidence badge
  (color-coded by `needs_review`), review-note callout when flagged.

**Why a hand-rolled SSE parser** (`lib/sse.ts`) instead of the browser's
`EventSource`: `EventSource` only supports `GET`, and the streaming
endpoint needs `POST` (multipart body for the optional file upload). `sse.ts`
reads the `fetch()` response body as a stream and parses the
`event:`/`data:` framing by hand; `lib/api.ts`'s `runInvestigationStream()`
wraps that into `{onUpdate, onError, onDone}` callbacks consumed by
`page.tsx`.

`NEXT_PUBLIC_API_BASE_URL` (`.env.local`, default
`http://localhost:8000`) points the frontend at the backend.

---

## 10. Tools reference

Two tools are bound to the investigator per investigation
(`tools/registry.py`, called fresh for every investigation so a vault
never crosses investigation boundaries). Both go through the mask-aware
wrapper described in §5 — the LLM only ever passes/receives masked tokens.

### `threat_intel_lookup` (`tools/threat_intel.py`) — real

**Args**: `indicator` (str) — a masked token for an IP, domain, URL, or
file hash.

**What it does**: classifies the indicator type from the *unmasked* value
(`_classify()`: IP/hash/URL by regex, else domain), then queries whichever
providers are configured and merges the results:

- **VirusTotal** (`VIRUSTOTAL_API_KEY`) — `GET /ip_addresses/{ip}`,
  `/domains/{domain}`, `/files/{hash}`, or `/urls/{base64url(url)}`.
  Extracts `verdict` (malicious/suspicious/benign, from
  `last_analysis_stats`), `detections` (`"N/total"`), `categories`, and —
  **for IPs only** — `country` and `asn`/`as_owner`. This is where
  geolocation comes from; there is deliberately no separate geolocation
  tool or provider. A standalone `geolocate_ip` tool existed briefly during
  development but was removed once it became clear VirusTotal's IP report
  already returns country/ASN for free — a second tool hitting a second
  provider (MaxMind) for data the first call already had was redundant
  complexity, not a real capability gap.
- **AlienVault OTX** (`OTX_API_KEY`) — `GET /indicators/{IPv4|domain|file|url}/{value}/general`.
  Extracts `pulse_count` and up to 5 `pulse_names` — named campaigns/threat
  reports the indicator is tagged in. This is what gives the judge's
  "grounding" check something more specific to cite than a bare detection
  ratio.

Set either or both keys; the tool merges whichever responses are
available under `"virustotal"` / `"alienvault_otx"` keys in the result. Set
**neither** and it falls back to a deterministic mock (hash-derived,
shaped identically to the real responses) — this is the only path
actually exercised in development so far (see §11).

Handles 404 (no report), 429 (rate limited), and network errors per
provider without raising — a failed lookup returns an `"error"` field
under that provider's key rather than crashing the tool call.

### `detonate_file` (`tools/sandbox.py`) — real

**What Hybrid Analysis (Falcon Sandbox) actually is**: a malware
detonation service, conceptually distinct from `threat_intel_lookup`.
Where VirusTotal/OTX are reputation *lookups* (has someone else already
judged this indicator?), Hybrid Analysis **runs the file**. You give it a
file; it actually executes it inside an isolated virtual machine (Windows,
Linux, etc. — the `environment_id`) that's cut off from real networks and
systems, so nothing it does can escape. While the file runs, the sandbox
watches and records:

- **Process behavior** — does it spawn child processes, inject code into
  other processes?
- **Filesystem changes** — does it drop new files, encrypt/delete things
  (a ransomware signature)?
- **Registry changes** — does it set itself to auto-run at startup
  (persistence)?
- **Network activity** — does it "phone home" to a C2 server, download a
  second-stage payload?

Alongside that it runs static checks too (multi-engine AV scan, similar to
VirusTotal). After a few minutes it packages all of this into a report: an
overall verdict, a threat score, and a list of specific observed behaviors
(`persistence_via_registry_run_key`, `outbound_c2_beacon`, etc. — the
exact shape the mock has always returned).

**"Existing report" shortcut**: if that exact file (by hash) has already
been analyzed by *anyone* before — Hybrid Analysis has a shared community
database — you get that report back instantly, no waiting. That's why the
tool checks `search/hash` first before submitting; only genuinely novel
files trigger a fresh run (and the poll loop below).

**Does it "investigate" for you?** — Only the behavioral-analysis piece,
not the investigation. It answers "what does this specific file *do* when
executed?" It doesn't know about the rest of the log, the other
indicators, prior incidents, or what should actually be done about it —
that synthesis is the investigator agent's job (see the worked example
above). Hybrid Analysis runs the file and reports facts; the LLM figures
out what those facts mean for *this* incident.

**Args**: `file_reference` (str) — a masked token for a file path or hash.

**Mechanics**: classifies the unmasked value as a `hash` or a `path`
(`_classify()`), then:

- **`hash`** — existing-report lookup only (`GET /search/hash?hash=`).
  There are no bytes to submit for a bare hash reference; if Hybrid
  Analysis has no prior report, the tool returns an `"error"` explaining
  why rather than fabricating a verdict.
- **`path`** — reads the file from disk at that path, hashes it, and tries
  the existing-report lookup first (cheap, avoids burning submission
  quota on something already analyzed). On a miss, submits the file
  (`POST /submit/file`, multipart, `environment_id=160` — Windows 10
  64-bit by default) and polls `GET /report/{job_id}/state` every 10s for
  up to 4 minutes. On `SUCCESS`, fetches `GET /report/{job_id}/summary`
  and returns `verdict` (from `verdict_human`), `threat_score`, and
  `behaviors` (`classification_tags`/`tags`). If still running after 4
  minutes, returns a `"pending"` status with the `job_id` rather than
  blocking indefinitely — real detonation can take longer than that.

**Where the file bytes come from** — this is the part that needed real
plumbing, not just an API swap:

- **CLI** (`asoc-investigate --file <path>`) — the file is already local.
  Its resolved absolute path is included as plain text in `raw_input`
  (`cli.py`), gets masked like any other entity (matches the `FILE_PATH`
  pattern → `PATH_XXXX` token), and `detonate_file` reads bytes straight
  from that path after unmasking. No upload step needed — the tool and
  the CLI process run on the same machine.
- **Web app** — the frontend's file input sends real bytes via multipart
  form to `/api/investigate/stream`. `api/app.py::_resolve_input` **saves
  those bytes to a server-side temp file** (`tempfile.gettempdir() /
  asoc_investigator_uploads/`, UUID-prefixed to avoid collisions, and the
  client-supplied filename is stripped to its basename before being used
  in the path — never trust a client filename as a path segment) and puts
  that temp path into `raw_input` in exactly the same shape the CLI would
  have. The rest of the pipeline can't tell the difference between "a
  user's local file" and "a server-side temp copy of an upload" — same
  masking, same tool, same code path. The temp file is deleted in the SSE
  generator's `finally` block once the investigation (success or error) is
  fully done with it — before that fix, uploaded bytes were read and then
  silently discarded, so file uploads through the web app never actually
  reached any tool.

Falls back to a deterministic mock (shaped identically to the real
`_format_summary()` output) when `HYBRID_ANALYSIS_API_KEY` isn't set —
this is the only path actually exercised in development so far (see §11).

---

## 11. What's real vs. mocked

| Component | Status |
|---|---|
| PII masking/unmasking | Real, regex-based entity detection |
| Tool mask/unmask boundary | Real |
| LangGraph supervisor/investigator/judge wiring | Real |
| Judge loop (max 3) | Real |
| Threat intel (`threat_intel_lookup`) | **Real** — VirusTotal + AlienVault OTX; mock fallback if neither key is set. Only the mock path has actually been exercised in this environment so far — the live integration has been verified against the providers' documented API shapes, not live-tested with real keys. |
| Sandbox (`detonate_file`) | **Real** — Hybrid Analysis submit+poll+hash-search; mock fallback if `HYBRID_ANALYSIS_API_KEY` isn't set. Only the mock path and the offline logic (path/hash classification, missing-file handling) have actually been exercised here — the live submit/poll/summary flow hasn't been tested against a real key. |
| File upload (web app) | **Real** — uploaded bytes are saved to a server-side temp file and cleaned up after the investigation completes, so `detonate_file` has real bytes to act on. Not yet exercised end-to-end here (needs a live `HYBRID_ANALYSIS_API_KEY` + a running frontend to actually drive an upload through). |
| RAG store | Real Supabase/pgvector schema; degrades gracefully if unconfigured or if a query fails |
| Embeddings | Real (OpenAI) automatically once `OPENAI_API_KEY` is set; hashing fallback otherwise |
| Backend API (FastAPI) | Real — both endpoints verified to import/route correctly; the actual LLM round-trip through them hasn't been exercised in this environment (no live API keys here) |
| Frontend | Real — typecheck/lint/build all verified; the live SSE round-trip against a running backend hasn't been exercised in this environment |

### Smoke tests (`scripts/`)

Runnable without any API key except `smoke_test_graph_compile.py` (needs a
placeholder value — it only compiles the graph, never calls the API):

```bash
python scripts/smoke_test_masking.py         # mask/unmask roundtrip, no PII leakage
python scripts/smoke_test_tools.py            # mask-aware tool boundary, mock threat intel + sandbox
python scripts/smoke_test_rag.py               # hashing embedder + RAGStore no-op behavior
python scripts/smoke_test_graph_compile.py      # graph wiring is internally consistent
```

These exercise every layer except the actual LLM calls. Run a real
`asoc-investigate "..."` (or the web app) with `OPENAI_API_KEY` set to
test those.

---

## 12. Open design questions / known gaps

- **`RAGStore.upsert_incident()` is never called.** The graph doesn't
  persist finished investigations back into the RAG store, so "checks for
  similar prior incidents" only ever finds whatever was seeded manually —
  the corpus doesn't grow from the app's own use. Wiring this in means
  answering policy questions first: should `needs_review` investigations
  be persisted at all, or only judge-satisfied ones? Is there a confidence
  floor? A dedicated node after `finalize`, or inline in it?
- **Judge is same-provider as the investigator (OpenAI/OpenAI), temporarily.**
  See §7 — revisit once the pipeline is stable enough that free-tier
  Gemini rate limits aren't a development-loop annoyance.
- **Vault persistence/expiry policy** if investigations ever need to be
  resumable across process restarts (currently in-memory only, scoped to
  one `graph.invoke()` call).
- **Multi-user isolation** if this becomes a shared service — the vault
  must never cross investigation/tenant boundaries; currently trivially
  true because each investigation gets a fresh `MaskingEngine`, but that
  invariant needs to be preserved deliberately if the architecture changes.
- **Entity detection is regex-only.** Fine for the mocked/generated test
  logs; may need an NER model layered in once real logs are noisier and
  less regularly formatted than the samples in `lib/sampleLogs.ts`.
- **No file-size limit on uploads.** `api/app.py::_resolve_input` reads the
  entire upload into memory (`await file.read()`) and then writes it to a
  server-side temp file — nothing currently caps how large that upload can
  be, on either the frontend `<input type="file">` or the backend. Worth a
  limit before this is exposed beyond localhost.
- **`detonate_file`'s poll loop is a fixed 4-minute synchronous wait**
  inside one tool call. Fine for a side project; a production version
  would want the investigator to be able to move on and check back later
  rather than blocking the whole investigation on one slow detonation.
