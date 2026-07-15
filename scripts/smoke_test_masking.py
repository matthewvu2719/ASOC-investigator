import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from asoc_investigator.masking import MaskingEngine

LOG = r"""
2026-07-10 14:22:01 Failed login for CORP\alice from 203.0.113.7 to WKSTN-042
2026-07-10 14:22:05 Outbound connection to evil-c2.example.com (203.0.113.7)
File dropped: C:\Users\alice\Downloads\payload.exe
SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd01
Alert sent to soc-analyst@company.com
"""

if __name__ == "__main__":
    engine = MaskingEngine()
    masked = engine.mask(LOG)
    print("--- MASKED ---")
    print(masked)
    print()
    print("--- UNMASKED ROUNDTRIP ---")
    unmasked = engine.unmask(masked)
    print(unmasked)
    print()
    print("vault size:", engine.vault_size())

    assert "203.0.113.7" not in masked, "IP leaked into masked text"
    assert "alice" not in masked, "username leaked into masked text"
    assert "soc-analyst@company.com" not in masked, "email leaked into masked text"
    assert "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd01" not in masked, "hash leaked into masked text"
    assert unmasked.strip() == LOG.strip(), "roundtrip mismatch"
    print("OK: roundtrip matches original, no PII leaked into masked text")
