import { type ErrorInfo, parseErrorInfo } from "./error-info.js";
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
  declare readonly errorInfo: ErrorInfo | undefined;
  declare readonly targetError: unknown;

  constructor(
    statusCode: number,
    requestId: string | null,
    detail: unknown,
    metadata?: unknown,
    targetError?: unknown,
  ) {
    const errorInfo = parseErrorInfo(metadata);
    let description = "Unclassified Nullgate HTTP failure";
    if (errorInfo) {
      const failure =
        errorInfo.code === "CLIENT_TRANSPORT_ERROR" &&
        errorInfo.origin === "client"
          ? "Target HTTP transport failed"
          : "HTTP failure";
      description = `[${errorInfo.code}/${errorInfo.origin}] ${failure}`;
    }
    super(
      `${description} (status=${statusCode}${requestId ? `, request_id=${requestId}` : ""})`,
    );
    this.name = "NullgateAPIError";
    this.statusCode = statusCode;
    this.requestId = requestId;
    Object.defineProperty(this, "errorInfo", {
      value: errorInfo,
      enumerable: false,
    });
    Object.defineProperty(this, "targetError", {
      value: targetError,
      enumerable: false,
    });
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
