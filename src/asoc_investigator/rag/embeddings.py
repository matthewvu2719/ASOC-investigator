"""Pluggable embedding backends for the RAG store.

Real embeddings (OpenAI `text-embedding-3-small`) are used automatically
whenever `OPENAI_API_KEY` is set — which is already required for the
investigator/judge agents, so there's no extra provider or key to manage.
The dependency-free hashing embedder is only a fallback for running the
pipeline with zero external services at all (e.g. component tests that
don't set any API key) — see docs/ARCHITECTURE.md.

IMPORTANT: the two backends have different vector dimensions (256 vs
1536). `rag/schema.sql`'s `vector(1536)` column matches OpenAI embeddings,
the practical default — update the schema if you deliberately run without
OPENAI_API_KEY against a live Supabase project.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from typing import Protocol


class Embedder(Protocol):
    dimensions: int

    def embed(self, text: str) -> list[float]: ...


_TOKEN_RE = re.compile(r"[a-z0-9_]+")


class HashingEmbedder:
    """Dependency-free, deterministic bag-of-words hashing embedder.

    NOT semantically meaningful — two log excerpts describing the same
    incident type but worded differently won't necessarily land close
    together in vector space. This exists purely so the RAG pipeline is
    runnable end-to-end without external services. Swap in a real
    embedding model (OpenAIEmbedder below, or another provider) for
    anything beyond a demo.
    """

    dimensions = 256

    def embed(self, text: str) -> list[float]:
        vec = [0.0] * self.dimensions
        tokens = _TOKEN_RE.findall(text.lower())
        for token in tokens:
            digest = hashlib.sha256(token.encode()).digest()
            bucket = int.from_bytes(digest[:4], "big") % self.dimensions
            sign = 1.0 if digest[4] % 2 == 0 else -1.0
            vec[bucket] += sign
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]


class OpenAIEmbedder:
    """Real embeddings via OpenAI. Uses OPENAI_API_KEY — the same
    credential already required for the investigator/judge agents, so
    enabling this costs nothing extra to set up. `langchain-openai` is a
    base project dependency, not an optional extra."""

    dimensions = 1536
    _model = "text-embedding-3-small"

    def __init__(self) -> None:
        from langchain_openai import OpenAIEmbeddings  # deferred import

        self._client = OpenAIEmbeddings(model=self._model)

    def embed(self, text: str) -> list[float]:
        return self._client.embed_query(text)


def get_embedder() -> Embedder:
    """Real (OpenAI) embeddings whenever OPENAI_API_KEY is set, else the
    local hashing fallback. Never raises — a missing key should degrade to
    the demo-quality embedder, not break the pipeline."""
    if os.environ.get("OPENAI_API_KEY"):
        return OpenAIEmbedder()
    return HashingEmbedder()
