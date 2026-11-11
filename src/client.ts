import { randomUUID } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";
import {
  type Action,
  type InputField,
  prepareActions,
  prepareInputs,
} from "./akamai.js";
import {
  documentFor,
  type FwcimAction,
  type FwcimInput,
  prepareFwcim,
  prepareFwcimInputs,
} from "./amazon.js";
import { findProtections } from "./discovery.js";
import { local, NullgateError, retryDelay } from "./errors.js";
import { Page as Document, httpURL, type Protection } from "./models.js";
import { Profile } from "./profile.js";
import { FwcimResult, Request, resultData } from "./solution.js";
import { Target, type TargetFetch } from "./threatmetrix.js";

export interface ClientOptions {
  readonly baseUrl?: string;
  readonly timeout?: number;
}
export interface SessionOptions {
  readonly userAgent: string;
  readonly profile?: string;
  readonly timezone?: string | null;
}
export type Cookies =
  | Readonly<Record<string, string>>
  | ReadonlyMap<string, string>
  | { getCookiesSync(url: string): readonly { key: string; value: string }[] }
  | {
      getCookies(
        url: string,
      ): Promise<readonly { key: string; value: string }[]>;
    };
export interface SensorOptions {
  readonly script: string;
  readonly scriptUrl?: string;
  readonly cookies: Cookies;
  readonly inputs?:
    | Readonly<Record<string, string>>
    | readonly InputField[]
    | null;
  readonly actions?: readonly Action[] | null;
}
export interface PixelOptions {
  readonly script: string;
  readonly scriptUrl?: string;
}
export interface SbsdOptions extends PixelOptions {
  readonly cookies: Cookies;
}
export interface FwcimOptions {
  readonly form: string;
  readonly timing: Readonly<Record<string, number>>;
  readonly inputs: Readonly<Record<string, string>> | readonly FwcimInput[];
  readonly actions?: readonly FwcimAction[] | null;
  readonly cookies?: Cookies;
  readonly scriptUrl?: string;
}
export interface ThreatMetrixOptions {
  readonly send: TargetFetch;
  readonly scriptUrl?: string;
  readonly proxy?: string | null;
}
export interface UsageOptions {
  readonly interval?: "hour" | "day";
  readonly start?: string;
  readonly end?: string;
}
export interface UsageTotal {
  readonly operation: string;
  readonly requests: number;
  readonly amount: string;
}
export interface Account {
  readonly id: string;
  readonly balance: string;
  readonly currency: string;
  readonly createdAt: string;
  readonly active: boolean;
  readonly pricesPer1000: Readonly<Record<string, string>>;
  readonly usage: readonly UsageTotal[];
}
export interface Usage {
  readonly currency: string;
  readonly interval: "hour" | "day";
  readonly start: string;
  readonly end: string;
  readonly buckets: readonly (UsageTotal & { readonly start: string })[];
}

async function cookiesFor(
  source: Cookies | undefined,
  names: readonly string[],
  url: string,
): Promise<Record<string, string>> {
  if (source === undefined) return {};
  if (source === null || typeof source !== "object" || Array.isArray(source))
    throw new NullgateError(
      "invalid_request",
      "cookies must be a mapping or cookie jar",
    );
  let entries: readonly (readonly [string, string])[];
  if (source instanceof Map) entries = [...source];
  else if (
    "getCookiesSync" in source &&
    typeof source.getCookiesSync === "function"
  )
    entries = source
      .getCookiesSync(url)
      .map((cookie) => [cookie.key, cookie.value]);
  else if ("getCookies" in source && typeof source.getCookies === "function")
    entries = (await source.getCookies(url)).map((cookie) => [
      cookie.key,
      cookie.value,
    ]);
  else entries = Object.entries(source) as [string, string][];
  const selected: Record<string, string> = {};
  for (const [name, value] of entries)
    if (names.includes(name)) {
      if (typeof value !== "string")
        throw new NullgateError(
          "invalid_request",
          "Cookie values must be strings",
        );
      selected[name] = value;
    }
  return selected;
}

export class Nullgate {
  readonly #key: string;
  readonly #base: string;
  readonly #timeout: number;
  constructor(
    apiKey: string | undefined = process.env.NULLGATE_API_KEY,
    options: ClientOptions = {},
  ) {
    if (typeof apiKey !== "string" || !apiKey || /[\r\n]/.test(apiKey))
      throw new NullgateError(
        "invalid_key",
        "Provide apiKey or NULLGATE_API_KEY",
      );
    this.#key = apiKey;
    const base = local(() =>
      httpURL(options.baseUrl ?? "https://api.nullgate.club", "baseUrl"),
    );
    if (base.username || base.password || base.search || base.hash)
      throw new NullgateError(
        "invalid_request",
        "baseUrl cannot contain credentials, query, or fragment",
      );
    this.#base = base.href.replace(/\/+$/, "");
    this.#timeout = (options.timeout ?? 30) * 1000;
    if (
      !Number.isFinite(this.#timeout) ||
      this.#timeout <= 0 ||
      this.#timeout > 2_147_483_647
    )
      throw new NullgateError(
        "invalid_request",
        "timeout must be positive seconds within the timer range",
      );
  }
  session(options: SessionOptions): Session {
    return new Session(this, options);
  }
  async account(): Promise<Account> {
    const data = await this._call("/account");
    const { created_at, prices_per_1000, ...fields } = data;
    return {
      ...fields,
      createdAt: created_at,
      pricesPer1000: prices_per_1000,
    } as unknown as Account;
  }
  async usage(options: UsageOptions = {}): Promise<Usage> {
    const query = new URLSearchParams(Object.entries(options));
    return (await this._call(
      `/account/usage${query.size ? `?${query}` : ""}`,
    )) as unknown as Usage;
  }
  /** @internal */
  async _call(
    path: string,
    body?: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const signal = AbortSignal.timeout(Math.ceil(this.#timeout));
    try {
      for (let attempt = 0; ; attempt++) {
        const response = await fetch(`${this.#base}${path}`, {
          method: body === undefined ? "GET" : "POST",
          headers: {
            Authorization: `Bearer ${this.#key}`,
            ...(body === undefined
              ? {}
              : { "Content-Type": "application/json" }),
          },
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
          redirect: "manual",
          credentials: "omit",
          signal,
        });
        let data: unknown;
        try {
          data = await response.json();
        } catch {
          signal.throwIfAborted();
          throw new NullgateError(
            "protocol_error",
            "Expected a JSON response",
            null,
            response.status,
          );
        }
        if (data === null || typeof data !== "object" || Array.isArray(data))
          throw new NullgateError(
            "protocol_error",
            "Expected a JSON object",
            null,
            response.status,
          );
        const value = data as Record<string, unknown>;
        if (response.ok) return value;
        if (
          typeof value.code !== "string" ||
          typeof value.message !== "string" ||
          typeof value.request_id !== "string"
        )
          throw new NullgateError(
            "protocol_error",
            "Malformed error response",
            null,
            response.status,
          );
        const retry = retryDelay(response.headers.get("Retry-After"));
        if (
          value.code === "maintenance" &&
          attempt < 2 &&
          retry !== undefined
        ) {
          await sleep(Math.min(retry * 1000, this.#timeout), undefined, {
            signal,
          });
          continue;
        }
        throw new NullgateError(
          value.code,
          value.message,
          value.request_id,
          response.status,
        );
      }
    } catch (error) {
      if (error instanceof NullgateError) throw error;
      throw new NullgateError(
        signal.aborted ? "timeout" : "transport_error",
        signal.aborted ? "API request timed out" : "API connection failed",
      );
    }
  }
  /** @internal */
  async _profile(
    start: Record<string, unknown>,
    send: TargetFetch,
    proxy: string | null,
    rotateState: (value: string) => void,
  ): Promise<Profile> {
    const url = new URL(`${this.#base}/threatmetrix/profile`);
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    const deadline = AbortSignal.timeout(Math.ceil(this.#timeout));
    const started = Date.now();
    for (let attempt = 0; ; attempt++) {
      const profile = Profile._connect({
        url: url.href,
        headers: { Authorization: `Bearer ${this.#key}` },
        start: JSON.stringify(start),
        target: local(() => new Target(send, { proxy })),
        signal: new AbortController().signal,
        timeoutMs: Math.max(1, this.#timeout - (Date.now() - started)),
        rotateState,
      });
      try {
        await profile._waitForReady();
        return profile;
      } catch (error) {
        await profile.close();
        if (attempt >= 2 || profile._maintenanceDelay === undefined)
          throw error;
        try {
          await sleep(
            Math.min(profile._maintenanceDelay * 1000, this.#timeout),
            undefined,
            { signal: deadline },
          );
        } catch {
          throw new NullgateError("timeout", "Profile startup timed out");
        }
      }
    }
  }
}

export class Session {
  readonly #client: Nullgate;
  readonly #options: SessionOptions & { profile: string };
  readonly #states = new Map<string, string>();
  readonly #pending = new Map<string, Promise<unknown>>();
  constructor(client: Nullgate, options: SessionOptions) {
    if (
      !options ||
      typeof options.userAgent !== "string" ||
      !options.userAgent ||
      /[\r\n]/.test(options.userAgent)
    )
      throw new NullgateError(
        "invalid_request",
        "userAgent must be a nonempty header value",
      );
    const profile = options.profile ?? randomUUID();
    if (
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
        profile,
      )
    )
      throw new NullgateError("invalid_request", "profile must be a UUID");
    if (options.timezone != null)
      local(
        () =>
          new Intl.DateTimeFormat("en", {
            timeZone: options.timezone ?? undefined,
          }),
      );
    this.#client = client;
    this.#options = { ...options, profile };
  }
  page(url: string, html: string): Page {
    return local(() => new Page(this, new Document(url, html)));
  }
  /** @internal */
  _run<T>(
    product: string,
    document: Document,
    fields: Record<string, unknown>,
    finish: (data: Record<string, unknown>) => T,
  ): Promise<T> {
    const pending = (this.#pending.get(product) ?? Promise.resolve())
      .catch(() => undefined)
      .then(async () => {
        const data = await this.#client._call(
          `/${product}/${fields.operation}`,
          {
            ...this._context(product, document),
            ...Object.fromEntries(
              Object.entries(fields).filter(([name]) => name !== "operation"),
            ),
          },
        );
        const result = finish(data);
        if (typeof data.session !== "string" || !data.session)
          throw new NullgateError("protocol_error", "Missing response session");
        this.#states.set(product, data.session);
        return result;
      });
    this.#pending.set(product, pending);
    return pending;
  }
  /** @internal */
  _context(product: string, document: Document): Record<string, unknown> {
    return {
      profile: this.#options.profile,
      session: this.#states.get(product) ?? null,
      user_agent: this.#options.userAgent,
      url: document.url,
      html: document.html,
      document_id: document.documentId,
      started_at_ms: document.startedAtMs,
      ...(this.#options.timezone == null
        ? {}
        : { timezone: this.#options.timezone }),
    };
  }
  /** @internal */
  _profile(
    document: Document,
    scriptUrl: string,
    options: ThreatMetrixOptions,
  ): Promise<Profile> {
    return this.#client._profile(
      {
        ...this._context("threatmetrix", document),
        type: "start",
        at_ms: Date.now(),
        tags_url: scriptUrl,
      },
      options.send,
      options.proxy ?? null,
      (session) => this.#states.set("threatmetrix", session),
    );
  }
}

export class Page {
  readonly #session: Session;
  readonly #document: Document;
  readonly #found: readonly Protection[];
  constructor(session: Session, document: Document) {
    this.#session = session;
    this.#document = document;
    this.#found = findProtections(document);
  }
  get sensorUrl(): string | null {
    return this.#candidate("sensor")?.scriptURL ?? null;
  }
  get pixelUrl(): string | null {
    return this.#candidate("pixel")?.scriptURL ?? null;
  }
  get sbsdUrl(): string | null {
    return this.#candidate("sbsd")?.scriptURL ?? null;
  }
  #candidate(kind: string, explicit?: string): Protection | undefined {
    const candidates = this.#found.filter(
      (candidate) =>
        candidate.kind === kind &&
        (explicit === undefined || candidate.scriptURL === explicit),
    );
    const unique = [
      ...new Map(
        candidates.map((candidate) => [
          `${candidate.scriptURL}${"challenge" in candidate ? `:${candidate.challenge}` : ""}`,
          candidate,
        ]),
      ).values(),
    ];
    if (unique.length > 1)
      throw new NullgateError(
        "ambiguous_protection",
        `Choose scriptUrl from: ${unique.map((candidate) => candidate.scriptURL).join(", ")}`,
      );
    return unique[0];
  }
  #script(kind: string, options: PixelOptions): string {
    if (!options || typeof options !== "object")
      throw new NullgateError(
        "invalid_request",
        "Provide script source options",
      );
    const url = options.scriptUrl ?? this.#candidate(kind)?.scriptURL;
    if (url === undefined)
      throw new NullgateError(
        "missing_protection",
        `No ${kind} script found; provide scriptUrl`,
      );
    local(() => httpURL(url, "scriptUrl"));
    if (typeof options.script !== "string" || !options.script)
      throw new NullgateError(
        "invalid_request",
        "script must be nonempty source text",
      );
    return url;
  }
  #inputs(
    inputs:
      | Readonly<Record<string, string>>
      | readonly InputField[]
      | null
      | undefined,
  ): InputField[] {
    return Array.isArray(inputs)
      ? [...inputs]
      : Object.entries(inputs ?? {}).map(([id, value]) => ({ id, value }));
  }
  async sensor(options: SensorOptions): Promise<Request> {
    const scriptUrl = this.#script("sensor", options);
    const inputs = local(() => {
      documentFor(this.#document);
      const fields = this.#inputs(options.inputs);
      return fields.map((field) => {
        if (
          field.type?.toLowerCase() === "password" ||
          /^(?:password|ap_password)$/i.test(field.id ?? field.name ?? "") ||
          /(?:current|new)-password/i.test(field.autocomplete ?? "")
        )
          throw new NullgateError(
            "invalid_request",
            "Password observations are not allowed",
          );
        if (field.id || field.name || field.selector) {
          const [observed] = prepareFwcimInputs(this.#document, [
            {
              ...(field.id === undefined ? {} : { id: field.id }),
              ...(field.name === undefined ? {} : { name: field.name }),
              ...(field.selector === undefined
                ? {}
                : { selector: field.selector }),
              value: field.value ?? "",
            },
          ]);
          if (observed === undefined)
            throw new NullgateError(
              "invalid_request",
              "Missing input observation",
            );
          return {
            attributes: {
              ...Object.fromEntries(
                Object.entries(field).filter(
                  ([name]) =>
                    !["id", "name", "value", "selector"].includes(name),
                ),
              ),
              ...observed.attributes,
            },
            value: observed.value,
            ...(observed.selector === undefined
              ? {}
              : { selector: observed.selector }),
          };
        }
        const [prepared] = prepareInputs([field]);
        if (prepared === undefined)
          throw new NullgateError(
            "invalid_request",
            "Missing input observation",
          );
        return prepared;
      });
    });
    const actions = local(() => prepareActions(options.actions ?? []));
    return this.#generate("sensor", {
      script_url: scriptUrl,
      script: options.script,
      cookies: await cookiesFor(
        options.cookies,
        ["_abck", "bm_sz"],
        this.#document.url,
      ),
      inputs,
      actions,
    });
  }
  async pixel(options: PixelOptions): Promise<Request> {
    const scriptUrl = this.#script("pixel", options);
    const candidate = this.#candidate("pixel", scriptUrl);
    if (candidate === undefined || !("challenge" in candidate))
      throw new NullgateError(
        "missing_protection",
        "No pixel challenge found in HTML",
      );
    return this.#generate("pixel", {
      script_url: scriptUrl,
      script: options.script,
      challenge: candidate.challenge,
    });
  }
  async sbsd(options: SbsdOptions): Promise<Request> {
    const scriptUrl = this.#script("sbsd", options);
    return this.#generate("sbsd", {
      script_url: scriptUrl,
      script: options.script,
      cookies: await cookiesFor(options.cookies, ["sbsd"], this.#document.url),
    });
  }
  #generate(
    operation: string,
    fields: Record<string, unknown>,
  ): Promise<Request> {
    local(() => documentFor(this.#document));
    return this.#session._run(
      "akamai",
      this.#document,
      { operation, ...fields },
      (data) => new Request(resultData(data, this.#document.url)),
    );
  }
  async fwcim(options: FwcimOptions): Promise<FwcimResult> {
    const inputs = local(() =>
      Array.isArray(options.inputs)
        ? options.inputs
        : Object.entries(options.inputs).map(([id, value]) => ({ id, value })),
    );
    const fields = local(() =>
      prepareFwcim(
        this.#document,
        options.form,
        options.timing,
        inputs,
        options.actions ?? [],
      ),
    );
    return this.#session._run(
      "amazon",
      this.#document,
      {
        operation: "fwcim",
        ...fields,
        started_at_ms: options.timing.navigationStart,
        cookies: await cookiesFor(
          options.cookies,
          ["session-id", "session-token", "ubid-main"],
          this.#document.url,
        ),
      },
      (data) => new FwcimResult(resultData(data, this.#document.url, true)),
    );
  }
  async threatmetrix(options: ThreatMetrixOptions): Promise<Profile> {
    if (!options || typeof options.send !== "function")
      throw new NullgateError(
        "invalid_request",
        "send must be a request callback",
      );
    local(() => documentFor(this.#document));
    const scriptUrl =
      options.scriptUrl ?? this.#candidate("profile")?.scriptURL;
    if (scriptUrl === undefined)
      throw new NullgateError(
        "missing_protection",
        "No ThreatMetrix tags script found; provide scriptUrl",
      );
    return this.#session._profile(this.#document, scriptUrl, options);
  }
}
