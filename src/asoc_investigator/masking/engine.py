"""Reversible, deterministic PII masking scoped to one investigation.

See docs/ARCHITECTURE.md "The masking boundary" for why this exists and how
it's used: the vault built here is only ever unmasked inside the
tool-execution layer (tools/base.py), never handed back to the LLM.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .entities import EntityType, iter_matches


def _token_suffix(real_value: str, salt: int = 0) -> str:
    digest = hashlib.sha256(f"{real_value}:{salt}".encode()).hexdigest()
    return digest[:4].upper()


@dataclass
class MaskingEngine:
    """Holds the token<->real-value vault for a single investigation.

    Deterministic within an investigation: the same real value always maps
    to the same token, so the LLM can still reason about recurring
    indicators ("this IP shows up in 3 log lines") without ever seeing the
    real value.
    """

    _token_to_real: dict[str, str] = field(default_factory=dict)
    _real_to_token: dict[str, str] = field(default_factory=dict)
    _entity_types: dict[str, EntityType] = field(default_factory=dict)

    def _get_or_create_token(self, entity_type: EntityType, real_value: str) -> str:
        if real_value in self._real_to_token:
            return self._real_to_token[real_value]

        salt = 0
        while True:
            token = f"{entity_type.value}_{_token_suffix(real_value, salt)}"
            existing = self._token_to_real.get(token)
            if existing is None or existing == real_value:
                break
            salt += 1  # collision with a *different* real value — resalt

        self._token_to_real[token] = real_value
        self._real_to_token[real_value] = token
        self._entity_types[token] = entity_type
        return token

    def mask(self, text: str) -> str:
        """Replace every detected entity in `text` with its token.

        Safe to call repeatedly / on overlapping content from the same
        investigation — tokens are stable.
        """
        if not text:
            return text

        matches = iter_matches(text)
        if not matches:
            return text

        out: list[str] = []
        cursor = 0
        for entity_type, value, start, end in matches:
            out.append(text[cursor:start])
            out.append(self._get_or_create_token(entity_type, value))
            cursor = end
        out.append(text[cursor:])
        return "".join(out)

    def unmask(self, text: str) -> str:
        """Replace every known token in `text` with its real value.

        Unknown tokens (not produced by this engine instance) are left
        untouched rather than raising — a judge or investigator draft may
        legitimately quote a token verbatim without it being a masking bug.
        """
        if not text:
            return text
        out = text
        # Longest tokens first to avoid partial-prefix collisions (unlikely
        # given the fixed TYPE_HEX shape, but cheap to guard).
        for token in sorted(self._token_to_real, key=len, reverse=True):
            if token in out:
                out = out.replace(token, self._token_to_real[token])
        return out

    def resolve(self, token: str) -> str:
        """Unmask a single token, e.g. a tool-call argument. Raises if the
        token wasn't produced by this engine — a tool should never receive
        an unknown token to resolve."""
        if token not in self._token_to_real:
            raise KeyError(f"Unknown masking token: {token!r}")
        return self._token_to_real[token]

    def entity_type_of(self, token: str) -> EntityType | None:
        return self._entity_types.get(token)

    def known_tokens(self) -> list[str]:
        return list(self._token_to_real.keys())

    def vault_size(self) -> int:
        return len(self._token_to_real)
