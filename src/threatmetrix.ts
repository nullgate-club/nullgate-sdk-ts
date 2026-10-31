import {
  type Action,
  type InputField,
  prepareActions,
  prepareInputs,
} from "./akamai.js";
import { httpURL, Page, type ScriptReference } from "./models.js";
import {
  gatherRelay,
  parseTargetProxy,
  type RelayAllocation,
  type TargetProxy,
  type TurnServer,
} from "./turn.js";

/** @internal */
export function isThreatMetrixTagsURL(url: URL): boolean {
  return (
    ["http:", "https:"].includes(url.protocol) &&
    !url.username &&
    !url.password &&
    url.pathname.endsWith("/tags.js") &&
    ["org_id", "session_id"].every((name) => {
      const values = url.searchParams.getAll(name);
      return values.length === 1 && (values[0]?.trim().length ?? 0) > 0;
    })
  );
}

/** The actual tags script and its caller-owned document, never a source profile. */
export class ThreatMetrix {
  readonly provider = "threatmetrix";
  readonly kind = "profile";
  readonly scriptURL: string;
  readonly provenance: ScriptReference | undefined;
  readonly #page: Page;

  constructor(
    page: Page,
    tagsURL: string,
    options: { readonly provenance?: ScriptReference } = {},
  ) {
    if (!(page instanceof Page))
      throw new TypeError("ThreatMetrix requires a Page");
    let url: URL;
    try {
      url = new URL(tagsURL, page.url);
    } catch {
      throw new TypeError("ThreatMetrix requires a valid tags URL");
    }
    if (!isThreatMetrixTagsURL(url)) {
      throw new TypeError(
        "ThreatMetrix tags URL requires /tags.js and one nonempty org_id and session_id",
      );
    }
    url.hash = "";
    this.#page = page;
    this.scriptURL = url.href;
    this.provenance = options.provenance;
    Object.freeze(this);
  }

  get page(): Page {
    return this.#page;
  }
}

/** An explicit collector URL and IDs supplied by the caller, without tag discovery. */
export class ThreatMetrixCollector {
  readonly provider = "threatmetrix";
  readonly kind = "profile";
  readonly scriptURL: string;
  readonly orgId: string;
  readonly sessionId: string;
  readonly provenance = undefined;
  readonly #page: Page;

  constructor(page: Page, url: string, orgId: string, sessionId: string) {
    if (!(page instanceof Page))
      throw new TypeError("ThreatMetrixCollector requires a Page");
    if (
      typeof url !== "string" ||
      !/^https?:\/\/[^/?#]+/i.test(url) ||
      /^https?:\/\/[^/?#]*@/i.test(url) ||
      /[#\s\\]/.test(url)
    ) {
      throw new TypeError(
        "ThreatMetrixCollector requires an absolute HTTP(S) URL without userinfo, fragments, whitespace, or backslashes",
      );
    }
    httpURL(url, "ThreatMetrixCollector.url");
    for (const [name, value] of [
      ["orgId", orgId],
      ["sessionId", sessionId],
    ]) {
      if (typeof value !== "string" || !value.trim() || /[\r\n]/.test(value)) {
        throw new TypeError(
          `ThreatMetrixCollector.${name} must be a nonempty string without CR/LF`,
        );
      }
    }
    this.#page = page;
    this.scriptURL = url;
    this.orgId = orgId;
    this.sessionId = sessionId;
    Object.freeze(this);
  }

  get page(): Page {
    return this.#page;
  }
}

export interface ThreatMetrixOptions {
  readonly inputs?: readonly InputField[] | null;
  readonly actions?: readonly Action[] | null;
}

export class ThreatMetrixParams {
  readonly #protection: ThreatMetrix | ThreatMetrixCollector;
  readonly inputs: readonly InputField[] | null;
  readonly actions: readonly Action[] | null;

  constructor(
    protection: ThreatMetrix | ThreatMetrixCollector,
    options: ThreatMetrixOptions = {},
  ) {
    if (
      !(protection instanceof ThreatMetrix) &&
      !(protection instanceof ThreatMetrixCollector)
    )
      throw new TypeError(
        "ThreatMetrixParams requires a ThreatMetrix or ThreatMetrixCollector protection",
      );
    this.#protection = protection;
    this.inputs = options.inputs ?? null;
    this.actions = options.actions ?? null;
    Object.freeze(this);
  }

  get protection(): ThreatMetrix | ThreatMetrixCollector {
    return this.#protection;
  }

  /** @internal Snapshot and redact before queuing or opening a paid profile. */
  _startFrame(timezone: string | undefined): string {
    const protection = this.#protection;
    const page = protection.page;
    const start: Record<string, unknown> = {
      type: "start",
      at_ms: Date.now(),
      website: {
        url: page.url,
        html: page.html,
        document_id: page.documentId,
        started_at_ms: page.startedAtMs,
      },
      timezone: timezone ?? null,
    };
    if (protection instanceof ThreatMetrixCollector) {
      start.collector = {
        url: protection.scriptURL,
        org_id: protection.orgId,
        session_id: protection.sessionId,
      };
    } else {
      start.tags_url = protection.scriptURL;
    }
    if (this.inputs !== null) start.inputs = prepareInputs(this.inputs);
    if (this.actions !== null) start.actions = prepareActions(this.actions);
    return JSON.stringify(start);
  }
}

export interface TargetRequest {
  readonly role: string;
  readonly url: string;
  readonly method: string;
  readonly headers: Readonly<Record<string, string>>;
  /** Raw bytes; null means absent, an empty Uint8Array means a present empty body. */
  readonly body: Uint8Array | null;
  readonly credentials: "include" | "omit";
  readonly signal: AbortSignal;
}

export interface TargetResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Uint8Array;
}

/** Must honor signal, preserve response bytes, and use an isolated jar for omit. */
export type TargetFetch = (request: TargetRequest) => Promise<TargetResponse>;

/** Caller-owned HTTP transport plus the explicit, local-only TURN route. */
export class Target {
  readonly #fetch: TargetFetch;
  readonly #proxy: TargetProxy;

  constructor(fetch: TargetFetch, options: { readonly proxy: string | null }) {
    if (typeof fetch !== "function")
      throw new TypeError("Target requires a fetch callback");
    if (options === undefined || !Object.hasOwn(options, "proxy")) {
      throw new TypeError(
        "Target requires an explicit proxy URL or null for direct",
      );
    }
    this.#proxy = parseTargetProxy(options.proxy);
    this.#fetch = fetch;
    Object.freeze(this);
  }

  /** @internal */
  _fetch(request: TargetRequest): Promise<TargetResponse> {
    return this.#fetch(request);
  }

  /** @internal */
  _gather(
    server: TurnServer,
    signal: AbortSignal,
    timeoutMs: number,
  ): Promise<RelayAllocation> {
    return gatherRelay(server, this.#proxy, signal, timeoutMs);
  }
}
