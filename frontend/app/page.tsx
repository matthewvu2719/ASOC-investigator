"use client";

import { useRef, useState } from "react";
import InvestigationForm from "@/components/InvestigationForm";
import ProgressLog from "@/components/ProgressLog";
import ReportView from "@/components/ReportView";
import { runInvestigationStream } from "@/lib/api";
import type { FinalizeResult, InvestigationParams, LogEntry, NodeUpdate } from "@/lib/types";

function describeUpdate(node: string, payload: NodeUpdate[string]): string {
  switch (node) {
    case "ingest_and_mask":
      return "PII replaced with reversible tokens before anything reaches the LLM.";
    case "rag_retrieve": {
      const count = payload.prior_incidents?.length ?? 0;
      return count > 0
        ? `Found ${count} similar prior incident${count === 1 ? "" : "s"}.`
        : "No similar prior incidents found.";
    }
    case "investigator":
      return "Draft report produced from tool findings and prior-incident context.";
    case "judge": {
      const verdicts = payload.judge_verdicts ?? [];
      const latest = verdicts[verdicts.length - 1];
      if (!latest) return "Reviewing draft...";
      const pct = Math.round(latest.confidence * 100);
      return latest.verdict === "satisfied"
        ? `Satisfied (confidence ${pct}%). ${latest.feedback}`
        : `Needs revision (confidence ${pct}%): ${latest.feedback}`;
    }
    case "finalize":
      return "Unmasked and finalized.";
    default:
      return "Done.";
  }
}

let nextLogId = 1;

export default function Home() {
  const [isRunning, setIsRunning] = useState(false);
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [result, setResult] = useState<FinalizeResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const runIdRef = useRef(0);

  function handleSubmit(params: InvestigationParams) {
    const runId = ++runIdRef.current;
    setIsRunning(true);
    setEntries([]);
    setResult(null);
    setError(null);

    runInvestigationStream(params, {
      onUpdate: (update) => {
        if (runIdRef.current !== runId) return; // a newer run superseded this one
        setEntries((prev) => {
          const additions: LogEntry[] = Object.entries(update).map(([node, payload]) => ({
            id: nextLogId++,
            node,
            summary: describeUpdate(node, payload),
          }));
          return [...prev, ...additions];
        });

        if (update.finalize) {
          const f = update.finalize;
          if (
            f.final_report !== undefined &&
            f.confidence !== undefined &&
            f.needs_review !== undefined
          ) {
            setResult({
              final_report: f.final_report,
              confidence: f.confidence,
              needs_review: f.needs_review,
              review_note: f.review_note ?? null,
            });
          }
        }
      },
      onError: (message) => {
        if (runIdRef.current !== runId) return;
        setError(message);
        setIsRunning(false);
      },
      onDone: () => {
        if (runIdRef.current !== runId) return;
        setIsRunning(false);
      },
    });
  }

  return (
    <main className="mx-auto flex w-full max-w-3xl flex-col gap-6 p-6">
      <header>
        <h1 className="text-xl font-semibold">ASOC Investigator</h1>
        <p className="text-sm text-black/60 dark:text-white/60">
          PII-safe multi-agent security investigation. Investigator and judge both run on
          OpenAI.
        </p>
      </header>

      <InvestigationForm isRunning={isRunning} onSubmit={handleSubmit} />

      {error && (
        <div className="rounded-md border border-red-500/50 bg-red-500/10 p-3 text-sm text-red-700 dark:text-red-400">
          {error}
        </div>
      )}

      <ProgressLog entries={entries} />

      {result && <ReportView result={result} />}
    </main>
  );
}
