import { parseSSEStream } from "./sse";
import type { InvestigationParams, NodeUpdate } from "./types";

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/$/, "") ?? "http://localhost:8000";

export interface StreamHandlers {
  onUpdate: (update: NodeUpdate) => void;
  onError: (message: string) => void;
  onDone: () => void;
}

/**
 * Runs an investigation via the streaming endpoint and invokes `handlers`
 * as each graph node completes. See
 * ../../src/asoc_investigator/api/app.py `investigate_stream` for the
 * server side of this contract.
 */
export async function runInvestigationStream(
  params: InvestigationParams,
  handlers: StreamHandlers
): Promise<void> {
  const formData = new FormData();
  if (params.file) {
    formData.append("file", params.file);
  } else if (params.logText) {
    formData.append("log_text", params.logText);
  } else {
    handlers.onError("Provide log text or a file.");
    return;
  }
  formData.append("investigator_model", params.investigatorModel);
  formData.append("judge_model", params.judgeModel);
  formData.append("max_iterations", String(params.maxIterations));

  let response: Response;
  try {
    response = await fetch(`${API_BASE}/api/investigate/stream`, {
      method: "POST",
      body: formData,
    });
  } catch (err) {
    handlers.onError(
      `Could not reach the API at ${API_BASE} — is the backend running? (${String(err)})`
    );
    return;
  }

  if (!response.ok || !response.body) {
    const text = await response.text().catch(() => "");
    handlers.onError(`Request failed: ${response.status} ${response.statusText} ${text}`);
    return;
  }

  const reader = response.body.getReader();
  try {
    for await (const evt of parseSSEStream(reader)) {
      if (!evt.data) continue;

      if (evt.event === "error") {
        const parsed = JSON.parse(evt.data) as { message?: string };
        handlers.onError(parsed.message ?? "Unknown error from the investigation pipeline.");
        return;
      }
      if (evt.event === "done") {
        handlers.onDone();
        return;
      }
      handlers.onUpdate(JSON.parse(evt.data) as NodeUpdate);
    }
  } catch (err) {
    handlers.onError(`Stream parsing failed: ${String(err)}`);
    return;
  }

  handlers.onDone();
}
