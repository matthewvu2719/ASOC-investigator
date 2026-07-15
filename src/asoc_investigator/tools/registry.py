"""Aggregates all tool specs and binds them to a per-investigation
MaskingEngine to produce the tool list handed to the investigator agent."""

from __future__ import annotations

from langchain_core.tools import StructuredTool

from asoc_investigator.masking import MaskingEngine

from . import sandbox, threat_intel
from .base import build_mask_aware_tool

ALL_SPECS = [threat_intel.SPEC, sandbox.SPEC]


def build_tools(engine: MaskingEngine) -> list[StructuredTool]:
    """One call per investigation — binds every tool to that investigation's
    vault so unmask/remask never crosses investigation boundaries."""
    return [build_mask_aware_tool(spec, engine) for spec in ALL_SPECS]
