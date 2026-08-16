import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# ChatOpenAI()/ChatGoogleGenerativeAI() construct fine without a live key at
# build time — they only hit the network on .invoke(). We just want to
# confirm the graph wires up: nodes, conditional edges, and state schema are
# all consistent.
import os

os.environ.setdefault("OPENAI_API_KEY", "sk-placeholder-for-compile-check")
os.environ.setdefault("GOOGLE_API_KEY", "placeholder-for-compile-check")

from asoc_investigator.graph import build_graph

if __name__ == "__main__":
    app = build_graph(investigator_model="gpt-4.1", judge_model="gpt-4.1", max_iterations=3)
    print("Graph compiled OK.")
    print()
    nodes = list(app.get_graph().nodes.keys())
    print("Nodes:", nodes)

    expected = {
        "__start__",
        "ingest_and_mask",
        "supervisor",
        "investigator",
        "correlation",
        "remediation",
        "judge",
        "finalize",
        "__end__",
    }
    missing = expected - set(nodes)
    assert not missing, f"expected nodes missing from compiled graph: {missing}"
    print("OK: supervisor + all three specialist agents wired in")
