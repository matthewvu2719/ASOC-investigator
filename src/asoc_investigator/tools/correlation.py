"""Correlation-agent tools: MITRE ATT&CK technique mapping and follow-up
RAG search. See docs/ARCHITECTURE.md "Tools reference".

The ATT&CK mapping is a small, curated local table keyed on the exact
behavior/category-tag vocabulary tools/sandbox.py and tools/threat_intel.py
already return (persistence_via_registry_run_key, outbound_c2_beacon,
...), not a live MITRE TAXII/STIX feed pull. The technique IDs and names
below are real, current ATT&CK entries — but the mapping itself is
heuristic tag-matching, not authoritative attribution. That's a deliberate
scope choice worth stating honestly rather than implying a live
threat-intel-grade ATT&CK integration: it gives the correlation agent
something concrete to cite without pulling in a large external dataset for
a handful of tags this project's tools actually produce.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from asoc_investigator.rag import RAGStore

from .base import ToolSpec

# tag (as returned by sandbox/threat-intel tools, lowercased) ->
# (technique_id, technique_name, tactic)
_MITRE_TAG_MAP: dict[str, tuple[str, str, str]] = {
    "persistence_via_registry_run_key": (
        "T1547.001",
        "Registry Run Keys / Startup Folder",
        "Persistence",
    ),
    "outbound_c2_beacon": ("T1071", "Application Layer Protocol", "Command and Control"),
    "unusual_network_connection": ("T1071", "Application Layer Protocol", "Command and Control"),
    "network_connection": ("T1071", "Application Layer Protocol", "Command and Control"),
    "process_injection": ("T1055", "Process Injection", "Defense Evasion"),
    "credential_dumping": ("T1003", "OS Credential Dumping", "Credential Access"),
    "ransomware": ("T1486", "Data Encrypted for Impact", "Impact"),
    "c2": ("T1071", "Application Layer Protocol", "Command and Control"),
    "botnet": ("T1584.005", "Compromise Infrastructure: Botnet", "Resource Development"),
    "malware": ("T1204", "User Execution", "Execution"),
}


class MitreLookupArgs(BaseModel):
    behavior_tags: list[str] = Field(
        ...,
        description=(
            "Behavior/category tags from a threat_intel_lookup or "
            "detonate_file result (e.g. 'outbound_c2_beacon', 'c2', "
            "'persistence_via_registry_run_key') to map to MITRE ATT&CK "
            "techniques."
        ),
    )


def _mitre_lookup(behavior_tags: list[str]) -> dict[str, Any]:
    matched = []
    unmatched = []
    for tag in behavior_tags:
        hit = _MITRE_TAG_MAP.get(tag.lower())
        if hit:
            technique_id, technique_name, tactic = hit
            matched.append(
                {
                    "tag": tag,
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "tactic": tactic,
                }
            )
        else:
            unmatched.append(tag)
    return {
        "matched_techniques": matched,
        "unmatched_tags": unmatched,
        "source": "curated local ATT&CK tag mapping, not a live MITRE feed",
    }


def build_mitre_lookup_spec() -> ToolSpec:
    return ToolSpec(
        name="mitre_attack_lookup",
        description=(
            "Map observed behavior/category tags (from sandbox or "
            "threat-intel results) to MITRE ATT&CK techniques and tactics, "
            "where a mapping is known."
        ),
        args_schema=MitreLookupArgs,
        masked_args=(),
        impl=_mitre_lookup,
    )


class SearchPriorIncidentsArgs(BaseModel):
    query: str = Field(
        ...,
        description=(
            "Masked text describing the pattern to search for among prior "
            "incidents (e.g. a specific behavior or indicator type "
            "mentioned in the findings). Never include a real, unmasked "
            "value."
        ),
    )
    top_k: int = Field(default=3, ge=1, le=10)


def build_search_prior_incidents_spec(rag_store: RAGStore) -> ToolSpec:
    def _search(query: str, top_k: int = 3) -> dict[str, Any]:
        hits = rag_store.search(query, top_k=top_k)
        return {
            "hits": [
                {
                    "masked_summary": h.masked_summary,
                    "indicator_types": h.indicator_types,
                    "resolution": h.resolution,
                    "confidence": h.confidence,
                    "similarity": h.similarity,
                }
                for h in hits
            ]
        }

    return ToolSpec(
        name="search_prior_incidents",
        description=(
            "Search the (masked) prior-incident history for a specific "
            "pattern beyond what was already retrieved at the start of "
            "this investigation. Returns similar incident summaries."
        ),
        args_schema=SearchPriorIncidentsArgs,
        masked_args=(),
        impl=_search,
    )
