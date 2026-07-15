import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from asoc_investigator.masking import MaskingEngine
from asoc_investigator.tools import build_tools

LOG = "Outbound connection to evil-c2.example.com (203.0.113.7); file C:\\Users\\alice\\Downloads\\payload.exe dropped"

if __name__ == "__main__":
    engine = MaskingEngine()
    masked_log = engine.mask(LOG)
    print("--- MASKED LOG (what the LLM sees) ---")
    print(masked_log)
    print()

    tools = {t.name: t for t in build_tools(engine)}
    ip_token = next(t for t in engine.known_tokens() if t.startswith("IP_"))
    path_token = next(t for t in engine.known_tokens() if t.startswith("PATH_"))

    print("--- threat_intel_lookup(indicator=<masked IP token>) ---")
    print("(no VIRUSTOTAL_API_KEY/OTX_API_KEY set -> exercises the mock fallback path)")
    result = tools["threat_intel_lookup"].invoke({"indicator": ip_token})
    print(result)
    assert "203.0.113.7" not in result, "real IP leaked back into tool result!"
    # Geolocation is folded into this same tool (no separate geolocate_ip
    # tool) — confirm the mock still returns geo fields for an IP indicator.
    assert '"country"' in result and '"asn"' in result, "geo fields missing from threat_intel_lookup result"
    print()

    print("--- detonate_file(file_reference=<masked PATH token>) ---")
    result = tools["detonate_file"].invoke({"file_reference": path_token})
    print(result)
    assert "alice" not in result and "payload.exe" not in result
    print()

    print("--- calling a tool with an UNKNOWN token (should error gracefully, not crash) ---")
    result = tools["threat_intel_lookup"].invoke({"indicator": "IP_FFFF"})
    print(result)
    assert "Error" in result

    print()
    print("OK: tools resolve real values internally, results stay masked, unknown tokens handled gracefully")
