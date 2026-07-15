import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from asoc_investigator.rag import RAGStore
from asoc_investigator.rag.embeddings import HashingEmbedder

if __name__ == "__main__":
    embedder = HashingEmbedder()
    v1 = embedder.embed("failed login brute force from suspicious IP")
    v2 = embedder.embed("brute force failed login from suspicious ip address")
    v3 = embedder.embed("quarterly revenue report finance summary")
    assert len(v1) == embedder.dimensions
    dot12 = sum(a * b for a, b in zip(v1, v2))
    dot13 = sum(a * b for a, b in zip(v1, v3))
    print(f"similarity(login-vs-login-reworded) = {dot12:.3f}")
    print(f"similarity(login-vs-finance)         = {dot13:.3f}")
    assert dot12 > dot13, "hashing embedder should still favor shared vocabulary"

    # No SUPABASE_URL/KEY set in this environment -> must degrade gracefully,
    # not raise.
    store = RAGStore()
    print("store.is_connected:", store.is_connected)
    assert store.is_connected is False
    hits = store.search("some masked query text")
    assert hits == []
    store.upsert_incident("masked summary", ["IP"], "resolved", 0.9)  # no-op, must not raise

    print("OK: hashing embedder favors shared vocabulary; RAGStore no-ops safely without Supabase configured")
