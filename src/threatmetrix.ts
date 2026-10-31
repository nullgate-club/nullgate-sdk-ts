import {
  type Action,
  type InputField,
  prepareActions,
  prepareInputs,
} from "./akamai.js";
import { Page, type ScriptReference } from "./models.js";
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

export interface ThreatMetrixOptions {
  readonly inputs?: readonly InputField[] | null;
  readonly actions?: readonly Action[] | null;
}

export class ThreatMetrixParams {
  readonly #protection: ThreatMetrix;
  readonly inputs: readonly InputField[] | null;
  readonly actions: readonly Action[] | null;

  constructor(protection: ThreatMetrix, options: ThreatMetrixOptions = {}) {
    if (!(protection instanceof ThreatMetrix))
      throw new TypeError(
        "ThreatMetrixParams requires a ThreatMetrix protection",
      );
    this.#protection = protection;
    this.inputs = options.inputs ?? null;
    this.actions = options.actions ?? null;
    Object.freeze(this);
  }

  get protection(): ThreatMetrix {
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
      tags_url: protection.scriptURL,
      timezone: timezone ?? null,
    };
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
