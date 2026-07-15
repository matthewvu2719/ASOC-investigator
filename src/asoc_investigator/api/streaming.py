"""Bridges LangGraph's synchronous `.stream()` iterator into an async
generator, so a FastAPI SSE endpoint can consume graph progress without
blocking the event loop on tool calls / LLM requests.

The graph's node functions (agents/investigator.py, agents/judge.py) are
written synchronously — `.stream()` on a sync graph runs each node in the
calling thread. To keep FastAPI's event loop free for other requests while
a (possibly minutes-long) investigation runs, the whole `.stream()` call is
pushed onto a background thread, and events cross back to the event loop
through an asyncio.Queue via `loop.call_soon_threadsafe`.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any, AsyncIterator

_SENTINEL = object()


async def stream_graph_events(
    compiled_graph: Any, initial_state: dict
) -> AsyncIterator[dict]:
    """Yield `{node_name: partial_state_update}` dicts as the graph runs,
    in execution order, without blocking the event loop."""
    loop = asyncio.get_event_loop()
    queue: asyncio.Queue = asyncio.Queue()

    def _worker() -> None:
        try:
            for event in compiled_graph.stream(initial_state, stream_mode="updates"):
                loop.call_soon_threadsafe(queue.put_nowait, event)
        except Exception as exc:  # surfaced to the client as an SSE error event
            loop.call_soon_threadsafe(queue.put_nowait, {"__error__": str(exc)})
        finally:
            loop.call_soon_threadsafe(queue.put_nowait, _SENTINEL)

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()

    while True:
        item = await queue.get()
        if item is _SENTINEL:
            break
        yield item
