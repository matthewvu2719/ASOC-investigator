import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from asoc_investigator.masking import MaskingEngine
from asoc_investigator.rag import RAGStore
from asoc_investigator.tools.base import build_mask_aware_tool
from asoc_investigator.tools.correlation import (
    build_mitre_lookup_spec,
    build_search_prior_incidents_spec,
)
from asoc_investigator.tools.remediation import SPEC as REMEDIATION_SPEC

if __name__ == "__main__":
    engine = MaskingEngine()
    ip_token = engine.mask("203.0.113.7")

    print("--- mitre_attack_lookup ---")
    mitre_tool = build_mask_aware_tool(build_mitre_lookup_spec(), engine)
    result = mitre_tool.invoke(
        {"behavior_tags": ["outbound_c2_beacon", "persistence_via_registry_run_key", "totally_unknown_tag"]}
    )
    print(result)
    assert "T1071" in result and "T1547.001" in result
    assert "totally_unknown_tag" in result
    print()

    print("--- search_prior_incidents (no Supabase configured -> [] gracefully) ---")
    store = RAGStore()
    search_tool = build_mask_aware_tool(build_search_prior_incidents_spec(store), engine)
    result = search_tool.invoke({"query": "outbound c2 beacon", "top_k": 3})
    print(result)
    assert '"hits": []' in result
    print()

    print("--- propose_firewall_block(indicator=<masked IP token>) ---")
    remediation_tool = build_mask_aware_tool(REMEDIATION_SPEC, engine)
    result = remediation_tool.invoke({"indicator": ip_token, "reason": "malicious per threat intel"})
    print(result)
    assert "203.0.113.7" not in result, "real IP leaked back into tool result!"
    assert "proposed_pending_human_approval" in result
    assert "MOCK ACTION" in result
    print()

    print("--- propose_firewall_block with an UNKNOWN token (should error gracefully) ---")
    result = remediation_tool.invoke({"indicator": "IP_FFFF", "reason": "test"})
    print(result)
    assert "Error" in result

    print()
    print("OK: correlation + remediation tools resolve/mask correctly through the shared wrapper")
