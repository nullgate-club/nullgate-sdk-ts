import { setTimeout as sleep } from "node:timers/promises";
import { inspect } from "node:util";
import { NullgateError } from "./errors.js";
import { httpURL } from "./models.js";

export interface OperationOptions {
  readonly signal?: AbortSignal;
}
export type Reporter = (
  requestId: string,
  options?: OperationOptions,
) => Promise<boolean>;
interface ResultData {
  url: string;
  body: string;
  metadata1: string;
  headers: Readonly<Record<string, string>>;
  sendAt: number;
  requestId: string;
}
export function resultData(
  data: Record<string, unknown>,
  pageUrl: string,
  amazon = false,
): ResultData {
  const invalid = (): never => {
    throw new NullgateError(
      "protocol_error",
      "Malformed generated response",
      typeof data.request_id === "string" ? data.request_id : null,
    );
  };
  const request = amazon ? data : data.request;
  if (
    !request ||
    typeof request !== "object" ||
    Array.isArray(request) ||
    typeof data.request_id !== "string" ||
    !data.request_id
  )
    return invalid();
  const value = request as Record<string, unknown>;
  if (
    typeof value.send_at !== "number" ||
    !Number.isFinite(value.send_at) ||
    !value.headers ||
    typeof value.headers !== "object" ||
    Array.isArray(value.headers)
  )
    return invalid();
  const entries = Object.entries(value.headers);
  if (entries.some(([, field]) => typeof field !== "string")) return invalid();
  const headers = Object.fromEntries(entries) as Record<string, string>;
  try {
    // Preserve authoritative header casing and order, including case-distinct keys.
    if (!amazon) {
      headers.origin = new URL(pageUrl).origin;
      headers.referer = pageUrl;
      if (typeof value.url !== "string" || typeof value.body !== "string")
        return invalid();
      const url = httpURL(value.url, "request.url");
      if (url.username || url.password) return invalid();
    } else if (typeof value.metadata1 !== "string" || !value.metadata1)
      return invalid();
  } catch {
    return invalid();
  }
  return {
    url: amazon ? "" : (value.url as string),
    body: amazon ? "" : (value.body as string),
    metadata1: amazon ? (value.metadata1 as string) : "",
    headers: Object.freeze(headers),
    sendAt: value.send_at,
    requestId: data.request_id,
  };
}

class WaitableResult {
  readonly sendAt: number;
  constructor(sendAt: number) {
    this.sendAt = sendAt;
  }
  async wait(options: OperationOptions = {}): Promise<void> {
    options.signal?.throwIfAborted();
    let remaining = this.sendAt * 1000 - Date.now();
    while (remaining > 0) {
      await sleep(
        Math.min(remaining, 2_147_483_647),
        undefined,
        options.signal === undefined ? {} : { signal: options.signal },
      );
      remaining = this.sendAt * 1000 - Date.now();
    }
  }
}
class TimedResult extends WaitableResult {
  readonly headers: Readonly<Record<string, string>>;
  readonly requestId: string;
  readonly #reporter: Reporter;
  constructor(data: ResultData, reporter: Reporter) {
    super(data.sendAt);
    this.#reporter = reporter;
    this.headers = data.headers;
    this.requestId = data.requestId;
  }
  report(options: OperationOptions = {}): Promise<boolean> {
    return this.#reporter(this.requestId, options);
  }
}
export class AcicPowResult extends WaitableResult {
  readonly response: string;
  constructor(response: string, sendAt: number) {
    super(sendAt);
    this.response = response;
    Object.freeze(this);
  }
}
export class Request extends TimedResult {
  readonly url: string;
  readonly #body: string;
  constructor(data: ResultData, reporter: Reporter) {
    super(data, reporter);
    this.url = data.url;
    this.#body = data.body;
    Object.freeze(this);
  }
  get body(): string {
    return this.#body;
  }
  [inspect.custom](): string {
    return `Request { url: ${this.url}, body: [REDACTED] }`;
  }
}
export class FwcimResult extends TimedResult {
  readonly #metadata1: string;
  constructor(data: ResultData, reporter: Reporter) {
    super(data, reporter);
    this.#metadata1 = data.metadata1;
    Object.freeze(this);
  }
  get metadata1(): string {
    return this.#metadata1;
  }
  [inspect.custom](): string {
    return "FwcimResult { metadata1: [REDACTED] }";
  }
}
