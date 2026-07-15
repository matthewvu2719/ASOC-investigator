import type { LogEntry } from "@/lib/types";

const NODE_LABELS: Record<string, string> = {
  ingest_and_mask: "Masking input",
  rag_retrieve: "Checking prior incidents",
  investigator: "Investigating",
  judge: "Reviewing draft",
  finalize: "Finalizing",
};

export default function ProgressLog({ entries }: { entries: LogEntry[] }) {
  if (entries.length === 0) return null;

  return (
    <ol className="flex flex-col gap-2 text-sm">
      {entries.map((entry) => (
        <li key={entry.id} className="flex gap-2 rounded-md border border-black/10 dark:border-white/15 p-2">
          <span className="font-medium shrink-0">{NODE_LABELS[entry.node] ?? entry.node}</span>
          <span className="text-black/70 dark:text-white/70">{entry.summary}</span>
        </li>
      ))}
    </ol>
  );
}
