"""FastAPI backend wrapping the LangGraph investigation pipeline.

Two ways to run an investigation:
  - POST /api/investigate         blocking, returns the final result as JSON
  - POST /api/investigate/stream  Server-Sent Events, one event per graph
                                   node as it completes (masking done, RAG
                                   hits found, draft ready, judge verdict,
                                   ..., final result)

Run with: uvicorn asoc_investigator.api.app:app --reload
"""

from __future__ import annotations

import dataclasses
import json
import tempfile
import uuid
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from asoc_investigator.graph import build_graph
from asoc_investigator.graph.state import DEFAULT_MAX_ITERATIONS

from .streaming import stream_graph_events

load_dotenv()

app = FastAPI(title="ASOC Investigator API", version="0.1.0")

_UPLOAD_DIR = Path(tempfile.gettempdir()) / "asoc_investigator_uploads"

# Local Next.js dev server. Add your deployed frontend origin here too once
# this leaves localhost.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class InvestigateRequest(BaseModel):
    log_text: str
    investigator_model: str = "gpt-4.1"
    judge_model: str = "gpt-4.1"
    max_iterations: int = DEFAULT_MAX_ITERATIONS


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


def _resolve_input(
    log_text: str | None, file: UploadFile | None, file_bytes: bytes | None
) -> tuple[str, str, Path | None]:
    """Returns (raw_input, input_kind, temp_file_path). temp_file_path is
    non-None only for the file-upload case — the caller must delete it once
    the investigation is done (see investigate_stream's event_generator)."""
    if file is not None and file_bytes is not None:
        _UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        # Path(...).name strips any path components from the client-supplied
        # filename — never trust it as a path segment directly.
        safe_name = Path(file.filename or "upload").name
        tmp_path = _UPLOAD_DIR / f"{uuid.uuid4().hex}_{safe_name}"
        tmp_path.write_bytes(file_bytes)

        # A real, readable path — same as what the CLI puts here for a
        # local file. It gets masked like any other entity in the text,
        # and tools/sandbox.py reads bytes from it after unmasking.
        raw_input = (
            f"File submitted for analysis: {file.filename}\n"
            f"Path: {tmp_path.resolve()}\n"
            f"Size: {len(file_bytes)} bytes"
        )
        return raw_input, "file", tmp_path
    if log_text:
        return log_text, "log", None
    raise HTTPException(status_code=400, detail="Provide log_text or a file.")


@app.post("/api/investigate")
def investigate(body: InvestigateRequest) -> dict:
    """Blocking variant — runs the full graph and returns the final state.
    Fine for curl/testing; the frontend uses the streaming endpoint below
    for a live progress view since a full run can take a while."""
    graph = build_graph(
        investigator_model=body.investigator_model,
        judge_model=body.judge_model,
        max_iterations=body.max_iterations,
    )
    result = graph.invoke(
        {
            "raw_input": body.log_text,
            "input_kind": "log",
            "max_iterations": body.max_iterations,
        }
    )
    return _public_result(result)


def _public_result(state: dict) -> dict:
    """Strip fields that shouldn't cross the API boundary (the masking
    vault, raw LangChain message objects) and make the rest JSON-safe."""
    return {
        "final_report": state.get("final_report"),
        "confidence": state.get("confidence"),
        "needs_review": state.get("needs_review"),
        "review_note": state.get("review_note"),
        "iterations": state.get("iteration"),
        "prior_incidents": [
            dataclasses.asdict(h) for h in state.get("prior_incidents", [])
        ],
    }


def _serialize_update(update: dict[str, Any]) -> dict[str, Any]:
    """Sanitize one `{node_name: partial_state}` update from
    stream_graph_events for JSON/SSE — drops the masking vault and raw
    LangChain message objects, which are internal-only."""
    out: dict[str, Any] = {}
    for node_name, partial in update.items():
        if not isinstance(partial, dict):
            out[node_name] = partial
            continue
        safe: dict[str, Any] = {}
        for key, value in partial.items():
            if key in ("masking_engine", "investigator_messages"):
                continue
            if key == "prior_incidents":
                safe[key] = [dataclasses.asdict(h) for h in value]
                continue
            safe[key] = value
        out[node_name] = safe
    return out


@app.post("/api/investigate/stream")
async def investigate_stream(
    log_text: str | None = Form(default=None),
    investigator_model: str = Form(default="gpt-4.1"),
    judge_model: str = Form(default="gpt-4.1"),
    max_iterations: int = Form(default=DEFAULT_MAX_ITERATIONS),
    file: UploadFile | None = File(default=None),
):
    file_bytes = await file.read() if file is not None else None
    raw_input, input_kind, tmp_path = _resolve_input(log_text, file, file_bytes)

    graph = build_graph(
        investigator_model=investigator_model,
        judge_model=judge_model,
        max_iterations=max_iterations,
    )
    initial_state = {
        "raw_input": raw_input,
        "input_kind": input_kind,
        "max_iterations": max_iterations,
    }

    async def event_generator():
        try:
            async for update in stream_graph_events(graph, initial_state):
                if "__error__" in update:
                    yield f"event: error\ndata: {json.dumps({'message': update['__error__']})}\n\n"
                    return
                yield f"data: {json.dumps(_serialize_update(update))}\n\n"
        finally:
            # Clean up the temp upload only after the graph is fully done
            # with it — detonate_file may read this path mid-run.
            if tmp_path is not None:
                tmp_path.unlink(missing_ok=True)
            yield "event: done\ndata: {}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
