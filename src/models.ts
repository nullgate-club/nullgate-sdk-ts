import { randomUUID } from "node:crypto";
import type { Protection as AkamaiProtection } from "./akamai.js";
import type { ThreatMetrix } from "./threatmetrix.js";

export type Protection = AkamaiProtection | ThreatMetrix;

export function httpURL(value: string, name: string): URL {
  if (typeof value !== "string" || !/^https?:\/\//i.test(value))
    throw new TypeError(`${name} must be an absolute HTTP(S) URL`);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError(`${name} must be an absolute HTTP(S) URL`);
  }
  if (
    !["http:", "https:"].includes(url.protocol) ||
    !url.hostname ||
    url.username ||
    url.password
  ) {
    throw new TypeError(`${name} must be an absolute HTTP(S) URL`);
  }
  return url;
}

export interface PageOptions {
  /** Caller-observed navigation start; defaults to the time of construction. */
  readonly startedAtMs?: number | null;
  readonly documentId?: string | null;
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
      options.startedAtMs != null &&
      (!Number.isInteger(options.startedAtMs) || options.startedAtMs < 0)
    )
      throw new TypeError("Page.startedAtMs must be a nonnegative integer");
    let documentId = options.documentId ?? randomUUID();
    if (typeof documentId !== "string")
      throw new TypeError("Page.documentId must be a UUID");
    documentId = documentId
      .replace(/^urn:uuid:/, "")
      .replace(/^\{+|\}+$/g, "")
      .replaceAll("-", "");
    if (!/^[0-9a-f]{32}$/i.test(documentId))
      throw new TypeError("Page.documentId must be a UUID");
    this.url = url;
    this.html = html;
    this.documentId = documentId
      .toLowerCase()
      .replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, "$1-$2-$3-$4-$5");
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
