"""CLI entry point: `asoc-investigate "<log text>"` or
`asoc-investigate --file path/to/suspicious.exe`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from asoc_investigator.graph import run_investigation


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="asoc-investigate",
        description="Run a multi-agent security investigation over a log excerpt or file.",
    )
    parser.add_argument("input", nargs="?", help="Log text, or a file path (with --file).")
    parser.add_argument(
        "--file",
        action="store_true",
        help="Treat `input` as a file path rather than literal log text.",
    )
    parser.add_argument(
        "--investigator-model",
        default="gpt-4.1",
        help="OpenAI model for the ReAct investigator agent.",
    )
    parser.add_argument(
        "--judge-model",
        default="gpt-4.1",
        help="OpenAI model for the LLM-as-judge review agent (defaults to OpenAI for now — see agents/judge.py to swap to Gemini).",
    )
    parser.add_argument(
        "--max-iterations", type=int, default=3, help="Max judge-loop revision iterations."
    )
    return parser


def main() -> None:
    load_dotenv()
    parser = _build_parser()
    args = parser.parse_args()
    console = Console()

    if not args.input:
        parser.error("Provide log text as an argument, or a path with --file.")

    if args.file:
        path = Path(args.input)
        if not path.exists():
            parser.error(f"File not found: {path}")
        # v0.1 does not upload/detonate real file bytes — see
        # docs/ARCHITECTURE.md "What's stubbed vs. real". We pass file
        # metadata through the same masking + investigation pipeline so the
        # sandbox tool has a file_reference to act on.
        raw_input = (
            f"File submitted for analysis: {path.name}\n"
            f"Path: {path.resolve()}\n"
            f"Size: {path.stat().st_size} bytes"
        )
        input_kind = "file"
    else:
        raw_input = args.input
        input_kind = "log"

    console.print(Panel.fit(f"Investigating ({input_kind})...", style="bold cyan"))

    result = run_investigation(
        raw_input=raw_input,
        input_kind=input_kind,
        investigator_model=args.investigator_model,
        judge_model=args.judge_model,
        max_iterations=args.max_iterations,
    )

    console.print()
    console.print(Markdown(result.get("final_report", "(no report produced)")))
    console.print()

    confidence = result.get("confidence", 0.0)
    needs_review = result.get("needs_review", True)
    if needs_review:
        console.print(
            Panel(
                f"Confidence: {confidence:.0%}\n\n{result.get('review_note') or ''}",
                title="[bold yellow]NEEDS HUMAN REVIEW[/bold yellow]",
                border_style="yellow",
            )
        )
    else:
        console.print(
            Panel(
                f"Confidence: {confidence:.0%}",
                title="[bold green]Reviewed & Satisfied[/bold green]",
                border_style="green",
            )
        )

    sys.exit(0)


if __name__ == "__main__":
    main()
