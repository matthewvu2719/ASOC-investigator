// Minimal Server-Sent Events parser for a fetch() ReadableStream.
//
// The browser's built-in EventSource only supports GET requests, and our
// investigation endpoint needs POST (multipart form for optional file
// upload) — so we read the streamed response body ourselves and parse the
// "event: <type>\ndata: <payload>\n\n" framing by hand.

export interface SSEEvent {
  event: string; // defaults to "message" per the SSE spec, but the backend
  // always sets one explicitly for terminal events ("done" / "error");
  // regular progress updates arrive as the default "message" type.
  data: string;
}

export async function* parseSSEStream(
  reader: ReadableStreamDefaultReader<Uint8Array>
): AsyncGenerator<SSEEvent> {
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    let boundary: number;
    while ((boundary = buffer.indexOf("\n\n")) !== -1) {
      const rawEvent = buffer.slice(0, boundary);
      buffer = buffer.slice(boundary + 2);
      yield parseEventBlock(rawEvent);
    }
  }

  // Flush anything left in the buffer without a trailing blank line.
  if (buffer.trim().length > 0) {
    yield parseEventBlock(buffer);
  }
}

function parseEventBlock(rawEvent: string): SSEEvent {
  let eventType = "message";
  const dataLines: string[] = [];
  for (const line of rawEvent.split("\n")) {
    if (line.startsWith("event:")) {
      eventType = line.slice("event:".length).trim();
    } else if (line.startsWith("data:")) {
      dataLines.push(line.slice("data:".length).trim());
    }
  }
  return { event: eventType, data: dataLines.join("\n") };
}
