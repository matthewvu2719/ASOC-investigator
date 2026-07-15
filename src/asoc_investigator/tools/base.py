"""Mask-aware tool wrapper — the tool-execution boundary described in
docs/ARCHITECTURE.md.

This is the ONLY place real values and the masking vault are allowed to
meet an external API call. A `ToolSpec.impl` never sees a token; the LLM
never sees a resolved real value — the wrapper unmasks declared args right
before calling `impl`, and re-masks whatever `impl` returns right after.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from asoc_investigator.masking import MaskingEngine


@dataclass
class ToolSpec:
    name: str
    description: str
    args_schema: type[BaseModel]
    masked_args: tuple[str, ...]
    impl: Callable[..., dict[str, Any]]


def _mask_structure(obj: Any, engine: MaskingEngine) -> Any:
    """Recursively mask every string leaf in a JSON-able structure.

    Masking must happen on raw Python strings BEFORE json.dumps, not after
    — json.dumps escapes backslashes (Windows paths like
    C:\\Users\\alice\\... become C:\\\\Users\\\\alice\\\\... in the encoded
    text), which breaks the backslash-anchored FILE_PATH / USERNAME regexes
    on the re-mask pass and lets real values leak through. Masking the
    structure first sidesteps escaping entirely.
    """
    if isinstance(obj, str):
        return engine.mask(obj)
    if isinstance(obj, dict):
        return {k: _mask_structure(v, engine) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mask_structure(v, engine) for v in obj]
    return obj


def build_mask_aware_tool(spec: ToolSpec, engine: MaskingEngine) -> StructuredTool:
    """Bind `spec` to one investigation's `engine` and produce a LangChain
    tool. Called once per investigation (not shared across investigations —
    the engine, and therefore the vault, is per-investigation)."""

    def _run(**kwargs: Any) -> str:
        resolved = dict(kwargs)
        for field in spec.masked_args:
            token = resolved.get(field)
            if token is None:
                continue
            try:
                resolved[field] = engine.resolve(token)
            except KeyError as exc:
                # Deliberately returned as a tool result, not raised: the
                # agent should see this and retry with a valid token rather
                # than crash the graph run.
                return (
                    f"Error: {field}={token!r} is not a known masked entity "
                    f"from this investigation. Only call this tool with "
                    f"tokens that appeared in the log, the file metadata, or "
                    f"a prior tool result — never invent or guess a token. "
                    f"({exc})"
                )

        result = spec.impl(**resolved)
        # Re-mask each value BEFORE serializing (see _mask_structure) — a
        # tool response can legitimately echo back a real value (e.g.
        # threat intel returning the queried IP in its payload), and it
        # must never reach the agent's context unmasked.
        masked_result = _mask_structure(result, engine)
        return json.dumps(masked_result, indent=2, default=str)

    return StructuredTool.from_function(
        func=_run,
        name=spec.name,
        description=spec.description,
        args_schema=spec.args_schema,
    )
