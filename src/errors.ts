import type { Protection } from "./models.js";

export class AmbiguousProtectionError extends Error {
  readonly candidates: readonly Protection[];

  constructor(candidates: readonly Protection[]) {
    super(
      `Found ${candidates.length} protection candidates; narrow discovery with where or set panic: false to inspect them all`,
    );
    this.name = "AmbiguousProtectionError";
    this.candidates = candidates;
  }
}

export class NullgateAPIError extends Error {
  readonly statusCode: number;
  readonly requestId: string | null;
  declare readonly detail: unknown;

  constructor(statusCode: number, requestId: string | null, detail: unknown) {
    super(
      `Nullgate HTTP ${statusCode}${requestId ? ` (request_id=${requestId})` : ""}`,
    );
    this.name = "NullgateAPIError";
    this.statusCode = statusCode;
    this.requestId = requestId;
    // Server validation details can echo private inputs; never include them in inspection.
    Object.defineProperty(this, "detail", { value: detail, enumerable: false });
  }
}

export class NullgateProtocolError extends Error {
  readonly statusCode: number;
  readonly requestId: string | null;

  constructor(message: string, statusCode: number, requestId: string | null) {
    super(
      `Invalid Nullgate response: ${message}${requestId ? ` (request_id=${requestId})` : ""}`,
    );
    this.name = "NullgateProtocolError";
    this.statusCode = statusCode;
    this.requestId = requestId;
  }
}

export class NullgateClosedError extends Error {
  constructor(owner: "client" | "session" | "profile") {
    super(`Nullgate ${owner} is closed`);
    this.name = "NullgateClosedError";
  }
}

export class NullgateTransportError extends Error {
  readonly statusCode: number;
  readonly requestId: string | null;

  constructor(requestId?: string | null, statusCode = 0) {
    super(
      requestId === undefined
        ? "Nullgate generation request failed before a complete response was received"
        : `Nullgate profile connection failed${requestId ? ` (request_id=${requestId})` : ""}`,
    );
    this.statusCode = statusCode;
    this.requestId = requestId ?? null;
    this.name = "NullgateTransportError";
  }
}
