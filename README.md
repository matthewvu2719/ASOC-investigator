# ASOC Investigator

A multi-agent security investigation assistant. Give it a log excerpt or a
suspicious file; it checks for similar prior incidents (RAG), enriches
indicators via threat intel (VirusTotal + AlienVault OTX — reputation,
geolocation, and campaign context in one call) and sandbox tools,
self-reviews its own conclusions (LLM-as-judge, up to 3 revision passes),
and returns a report with a confidence level — flagged for human review if
the judge wasn't satisfied within budget.

**PII never reaches the LLM in plaintext.** Every IP, hostname, username,
email, file path, and hash is replaced with a reversible token before
anything is sent to a model; real values are only resolved inside the tool
layer to make actual API calls, then re-masked before the result comes
back. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full
design, including why this is built as custom tools rather than MCP or
bash.

The investigator (ReAct agent, tool use) and judge both run on **OpenAI**
right now — a temporary choice to avoid free-tier Gemini rate limits during
development. Putting the judge on a different provider (e.g. Gemini) is a
genuinely stronger independence check and worth doing once the pipeline is
stable; both models are independent parameters, swappable without touching
the rest of the code — see `docs/ARCHITECTURE.md` "Agents".

## Status

v0.1 — architecture and pipeline are real and tested (masking round-trip,
the tool mask/unmask boundary, RAG store degrade-gracefully behavior, and
graph compilation all have smoke tests in `scripts/`). Threat intel
(VirusTotal + AlienVault OTX) is **real** when `VIRUSTOTAL_API_KEY` /
`OTX_API_KEY` are set, and falls back to a deterministic mock otherwise.
Sandbox is still **mocked** — see the "What's stubbed vs. real" table in
`docs/ARCHITECTURE.md` for exactly what's left to swap for production use.

The end-to-end LLM run (investigator + judge, which need a live
`OPENAI_API_KEY`) has not been exercised yet in this environment — do that
first before trusting the pipeline beyond the component-level tests. The
VirusTotal/OTX integration specifically has also only been verified against
their documented API shapes, not live-tested against real keys — the mock
fallback path is what's actually been run.

## Setup

Requires Python 3.11+.

```bash
python -m venv .venv
.venv/Scripts/activate        # Windows
# source .venv/bin/activate   # macOS/Linux

pip install -e .
cp .env.example .env
```

Edit `.env` and set at minimum `OPENAI_API_KEY` (used by the investigator,
the judge for now, and RAG embeddings — see `docs/ARCHITECTURE.md`
"Agents"). `GOOGLE_API_KEY` is only needed if you switch the judge back to
Gemini. Everything else (`SUPABASE_URL`, `VIRUSTOTAL_API_KEY`, `OTX_API_KEY`,
`HYBRID_ANALYSIS_API_KEY`) is optional — the pipeline degrades gracefully
without them (see below).

### Optional: Supabase (RAG over prior incidents)

1. Create a free Supabase project.
2. Run `src/asoc_investigator/rag/schema.sql` in the Supabase SQL editor.
3. Set `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` in `.env`.

Without these set, `RAGStore` no-ops — investigations run without prior-incident
context instead of failing. Once you do set them, embeddings use OpenAI
automatically (see below) — `rag/schema.sql`'s `vector(1536)` column
already matches.

### Embeddings

Real embeddings (OpenAI `text-embedding-3-small`) are used automatically as
soon as `OPENAI_API_KEY` is set — no separate key, no extra install step.
The local, dependency-free hashing embedder only kicks in if `OPENAI_API_KEY`
is entirely unset (e.g. running `scripts/smoke_test_rag.py` in isolation);
it's deterministic but not semantically meaningful, fine for wiring things
up, not for real similarity search.

### Threat intel: VirusTotal + AlienVault OTX

`tools/threat_intel.py` calls both automatically once you set the relevant
keys in `.env`:

- `VIRUSTOTAL_API_KEY` — free tier at [virustotal.com](https://www.virustotal.com)
  (sign up → profile → API key). Reputation, detection count, categories,
  and (for IPs) country/ASN — geolocation isn't a separate tool, VirusTotal
  already returns it.
- `OTX_API_KEY` — free at [otx.alienvault.com](https://otx.alienvault.com)
  (sign up → settings → API key). Adds named campaign/threat "pulses" the
  indicator is tagged in, for stronger grounding in the report than a bare
  detection ratio.

Set either or both — the tool merges whichever responses are available. Set
neither and it falls back to a deterministic mock shaped like the real
responses (this is the only path actually exercised so far in this
environment — see "Status" above).

### Optional: real sandbox provider

`tools/sandbox.py` is still mocked. Real detonation (e.g. Hybrid Analysis)
is async — submit, then poll for a report — so wiring it up needs a poll
loop added to the tool, not just a swapped function body like the threat
intel tools above.

## Usage

### CLI

```bash
asoc-investigate "Failed login for CORP\alice from 203.0.113.7 to WKSTN-042. Outbound connection to evil-c2.example.com (203.0.113.7)."

asoc-investigate --file suspicious.exe
```

Or from Python:

```python
from asoc_investigator.graph import run_investigation

result = run_investigation(raw_input="...", input_kind="log")
print(result["final_report"])       # unmasked
print(result["confidence"])         # 0-1
print(result["needs_review"])       # True if judge wasn't satisfied within budget
```

### Web app (FastAPI + Next.js)

Two processes, run in separate terminals.

**Backend:**

```bash
.venv/Scripts/activate   # if not already active
uvicorn asoc_investigator.api.app:app --reload
```

Runs on `http://localhost:8000`. `GET /api/health` for a liveness check;
interactive API docs at `http://localhost:8000/docs`.

**Frontend:**

```bash
cd frontend
npm install       # first time only
cp .env.local.example .env.local
npm run dev
```

Runs on `http://localhost:3000`. Fill in the form, submit, and watch the
investigation progress live via Server-Sent Events (masking → RAG lookup →
investigator → judge, looping up to `max_iterations` → final report).

The frontend build/typecheck/lint were verified in this environment; the
actual SSE round-trip against a running backend was not (no LLM API keys
available here) — test that next.

## Project layout

```
src/asoc_investigator/
  masking/    # reversible PII masking engine (the core safety boundary)
  tools/      # mask-aware tool wrapper + threat intel (VT+OTX) / sandbox
  rag/        # Supabase/pgvector store + pluggable embeddings
  agents/     # investigator (ReAct, OpenAI), judge (OpenAI for now), supervisor routing
  graph/      # LangGraph StateGraph wiring + shared state schema
  api/        # FastAPI app: blocking + SSE-streaming investigation endpoints
  cli.py

frontend/               # Next.js (TypeScript + Tailwind) — form, live
                         # progress view, report display
docs/ARCHITECTURE.md   # design doc — read this first
scripts/                # smoke tests for each layer, runnable without an API key
                         # except smoke_test_graph_compile.py which needs one
                         # set (a placeholder value works — it only compiles,
                         # doesn't call the API)
```

## Development

```bash
python scripts/smoke_test_masking.py
python scripts/smoke_test_tools.py
python scripts/smoke_test_rag.py
python scripts/smoke_test_graph_compile.py
```

These exercise every layer except the actual LLM calls (investigator ReAct
loop, judge). Run a real `asoc-investigate "..."` with `OPENAI_API_KEY` set
to test those.
