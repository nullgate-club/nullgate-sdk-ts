import { randomUUID } from "node:crypto";
import type { Protection as AkamaiProtection } from "./akamai.js";
import type { ThreatMetrix, ThreatMetrixCollector } from "./threatmetrix.js";

export type Protection =
  | AkamaiProtection
  | ThreatMetrix
  | ThreatMetrixCollector;

export function httpURL(value: string, name: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError(`${name} must be an absolute HTTP(S) URL`);
  }
  if (!["http:", "https:"].includes(url.protocol) || !url.hostname) {
    throw new TypeError(`${name} must be an absolute HTTP(S) URL`);
  }
  return url;
}

export interface PageOptions {
  /** Caller-observed navigation start; defaults to the time of construction. */
  readonly startedAtMs?: number;
  readonly documentId?: string;
}

/** Caller-owned document. Discovery never fetches or executes its contents. */
export class Page {
  readonly url: string;
  readonly html: string;
  readonly documentId: string;
  readonly startedAtMs: number;

  constructor(url: string, html: string, options: PageOptions = {}) {
    httpURL(url, "Page.url");
    if (typeof html !== "string")
      throw new TypeError("Page.html must be a string");
    if (
      options.startedAtMs !== undefined &&
      (!Number.isSafeInteger(options.startedAtMs) || options.startedAtMs < 0)
    )
      throw new TypeError("Page.startedAtMs must be a nonnegative integer");
    if (
      options.documentId !== undefined &&
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
        options.documentId,
      )
    )
      throw new TypeError("Page.documentId must be a UUID");
    this.url = url;
    this.html = html;
    this.documentId = options.documentId ?? randomUUID();
    this.startedAtMs = options.startedAtMs ?? Date.now();
    Object.freeze(this);
  }
}

/** A classic script occurrence; columns and offsets use JavaScript UTF-16 indices. */
export interface ScriptReference {
  readonly rawSource: string;
  readonly tagIndex: number;
  readonly line: number;
  readonly column: number;
}

export type JsonValue =
  | string
  | number
  | boolean
  | null
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };
