import type { FinalizeResult } from "@/lib/types";

export default function ReportView({ result }: { result: FinalizeResult }) {
  const confidencePct = Math.round(result.confidence * 100);

  const badgeStyle = result.needs_review
    ? "border-amber-500/50 bg-amber-500/10 text-amber-700 dark:text-amber-400"
    : "border-emerald-500/50 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400";

  return (
    <div className="flex flex-col gap-3">
      <div className={`flex items-center gap-3 rounded-md border px-3 py-2 text-sm ${badgeStyle}`}>
        <span className="font-semibold">
          {result.needs_review ? "Needs human review" : "Reviewed & satisfied"}
        </span>
        <span>Confidence: {confidencePct}%</span>
      </div>

      {result.needs_review && result.review_note && (
        <p className="text-sm text-amber-700 dark:text-amber-400 italic">
          Judge&apos;s last feedback: {result.review_note}
        </p>
      )}

      <div className="whitespace-pre-wrap rounded-md border border-black/10 dark:border-white/15 p-4 text-sm leading-relaxed">
        {result.final_report}
      </div>
    </div>
  );
}
