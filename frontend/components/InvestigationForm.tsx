import { useState } from "react";
import type { InvestigationParams } from "@/lib/types";

interface Props {
  isRunning: boolean;
  onSubmit: (params: InvestigationParams) => void;
}

export default function InvestigationForm({ isRunning, onSubmit }: Props) {
  const [mode, setMode] = useState<"log" | "file">("log");
  const [logText, setLogText] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [investigatorModel, setInvestigatorModel] = useState("gpt-4.1");
  const [judgeModel, setJudgeModel] = useState("gpt-4.1");
  const [maxIterations, setMaxIterations] = useState(3);

  const canSubmit =
    !isRunning && ((mode === "log" && logText.trim().length > 0) || (mode === "file" && file));

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    onSubmit({
      logText: mode === "log" ? logText : undefined,
      file: mode === "file" ? (file ?? undefined) : undefined,
      investigatorModel,
      judgeModel,
      maxIterations,
    });
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4 rounded-lg border border-black/10 dark:border-white/15 p-4">
      <div className="flex gap-4 text-sm">
        <label className="flex items-center gap-1.5">
          <input
            type="radio"
            checked={mode === "log"}
            onChange={() => setMode("log")}
            disabled={isRunning}
          />
          Log text
        </label>
        <label className="flex items-center gap-1.5">
          <input
            type="radio"
            checked={mode === "file"}
            onChange={() => setMode("file")}
            disabled={isRunning}
          />
          File
        </label>
      </div>

      {mode === "log" ? (
        <textarea
          value={logText}
          onChange={(e) => setLogText(e.target.value)}
          disabled={isRunning}
          rows={6}
          placeholder={'Failed login for CORP\\alice from 203.0.113.7 to WKSTN-042. Outbound connection to evil-c2.example.com (203.0.113.7).'}
          className="w-full rounded-md border border-black/15 dark:border-white/20 bg-transparent p-2 font-mono text-sm"
        />
      ) : (
        <input
          type="file"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          disabled={isRunning}
          className="text-sm"
        />
      )}

      <div className="flex flex-wrap gap-4 text-sm">
        <label className="flex flex-col gap-1">
          Investigator model (OpenAI)
          <input
            value={investigatorModel}
            onChange={(e) => setInvestigatorModel(e.target.value)}
            disabled={isRunning}
            className="rounded-md border border-black/15 dark:border-white/20 bg-transparent px-2 py-1"
          />
        </label>
        <label className="flex flex-col gap-1">
          Judge model (OpenAI for now)
          <input
            value={judgeModel}
            onChange={(e) => setJudgeModel(e.target.value)}
            disabled={isRunning}
            className="rounded-md border border-black/15 dark:border-white/20 bg-transparent px-2 py-1"
          />
        </label>
        <label className="flex flex-col gap-1">
          Max judge iterations
          <input
            type="number"
            min={1}
            max={10}
            value={maxIterations}
            onChange={(e) => setMaxIterations(Number(e.target.value))}
            disabled={isRunning}
            className="w-20 rounded-md border border-black/15 dark:border-white/20 bg-transparent px-2 py-1"
          />
        </label>
      </div>

      <button
        type="submit"
        disabled={!canSubmit}
        className="self-start rounded-md bg-black dark:bg-white text-white dark:text-black px-4 py-2 text-sm font-medium disabled:opacity-40"
      >
        {isRunning ? "Investigating..." : "Investigate"}
      </button>
    </form>
  );
}
