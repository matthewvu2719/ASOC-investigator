"""Supabase/pgvector-backed store of prior (masked) investigations.

Incident write-ups are stored already masked — they're the output of this
same pipeline — so this class never touches a MaskingEngine vault and never
performs an unmask. See docs/ARCHITECTURE.md "RAG over prior incidents".

Gracefully degrades to a no-op when SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY
aren't set, so the rest of the pipeline (masking, tools, agents) can be
exercised without a live Supabase project.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from supabase import Client, create_client

from .embeddings import Embedder, get_embedder

logger = logging.getLogger(__name__)


@dataclass
class IncidentHit:
    id: str
    masked_summary: str
    indicator_types: list[str]
    resolution: str | None
    confidence: float | None
    similarity: float


class RAGStore:
    def __init__(self, embedder: Embedder | None = None) -> None:
        self.embedder = embedder or get_embedder()
        self._client: Client | None = self._maybe_connect()

    @staticmethod
    def _maybe_connect() -> Client | None:
        url = os.environ.get("SUPABASE_URL")
        key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
        if not url or not key:
            return None
        return create_client(url, key)

    @property
    def is_connected(self) -> bool:
        return self._client is not None

    def search(self, masked_query_text: str, top_k: int = 5) -> list[IncidentHit]:
        """Find prior incidents similar to the current (already-masked)
        input. Returns [] both when Supabase isn't configured AND when a
        configured lookup fails (missing schema, network error, rate
        limit, ...) — RAG is enrichment, not a hard dependency, so a
        failure here must not take down the whole investigation. Callers
        should treat [] as "no prior-incident context available"."""
        if self._client is None:
            return []

        try:
            embedding = self.embedder.embed(masked_query_text)
            response = self._client.rpc(
                "match_incidents",
                {"query_embedding": embedding, "match_count": top_k},
            ).execute()
        except Exception:
            logger.warning(
                "RAG lookup failed — continuing without prior-incident context. "
                "If this persists, confirm rag/schema.sql has been run against "
                "your Supabase project.",
                exc_info=True,
            )
            return []

        return [
            IncidentHit(
                id=row["id"],
                masked_summary=row["masked_summary"],
                indicator_types=row.get("indicator_types") or [],
                resolution=row.get("resolution"),
                confidence=row.get("confidence"),
                similarity=row["similarity"],
            )
            for row in (response.data or [])
        ]

    def upsert_incident(
        self,
        masked_summary: str,
        indicator_types: list[str],
        resolution: str | None,
        confidence: float | None,
    ) -> None:
        """Persist a finalized (masked) investigation so future
        investigations can retrieve it. No-op if Supabase isn't configured;
        logs and swallows the error if a configured write fails, for the
        same reason as `search` — this must not crash the caller.

        NOTE: nothing in the graph calls this yet (see
        docs/ARCHITECTURE.md) — investigations aren't currently persisted
        back into the RAG store after they finish."""
        if self._client is None:
            return

        try:
            embedding = self.embedder.embed(masked_summary)
            self._client.table("incidents").insert(
                {
                    "masked_summary": masked_summary,
                    "indicator_types": indicator_types,
                    "resolution": resolution,
                    "confidence": confidence,
                    "embedding": embedding,
                }
            ).execute()
        except Exception:
            logger.warning("Failed to persist incident to RAG store.", exc_info=True)
