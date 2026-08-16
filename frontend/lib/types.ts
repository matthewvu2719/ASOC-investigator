// Mirrors the JSON shapes produced by the backend (see
// ../../src/asoc_investigator/api/app.py `_serialize_update` /
// `_public_result`). Kept as plain types, not generated, since the API
// surface is small — revisit with an OpenAPI client generator if it grows.

export interface IncidentHit {
  id: string;
  masked_summary: string;
  indicator_types: string[];
  resolution: string | null;
  confidence: number | null;
  similarity: number;
}

export type AgentName = "investigator" | "correlation" | "remediation";

export interface JudgeVerdict {
  verdict: "satisfied" | "needs_revision";
  target_agent: AgentName | null;
  confidence: number;
  feedback: string;
}

// One node's partial state update, as streamed by
// POST /api/investigate/stream. Only the fields that node can actually
// produce are present.
export interface NodeUpdatePayload {
  masked_input?: string;
  prior_incidents?: IncidentHit[];
  investigator_report?: string;
  correlation_report?: string;
  remediation_report?: string;
  agents_completed?: AgentName[];
  agent_steps?: number;
  supervisor_decision?: AgentName | "judge";
  judge_verdicts?: JudgeVerdict[];
  iteration?: number;
  final_report?: string;
  confidence?: number;
  needs_review?: boolean;
  review_note?: string | null;
}

// `{ node_name: partial_state }` — the shape of one SSE `data:` payload.
export type NodeUpdate = Record<string, NodeUpdatePayload>;

export interface FinalizeResult {
  final_report: string;
  confidence: number;
  needs_review: boolean;
  review_note: string | null;
}

export interface LogEntry {
  id: number;
  node: string;
  summary: string;
}

export interface InvestigationParams {
  logText?: string;
  file?: File;
  investigatorModel: string;
  judgeModel: string;
  maxIterations: number;
}
