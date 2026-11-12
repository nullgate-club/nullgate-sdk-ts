import { createHash, randomUUID } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";
import {
  type Action,
  type InputField,
  type PreparedInput,
  prepareActions,
  validatePreparedInput,
} from "./akamai.js";
import {
  documentFor,
  type FwcimAction,
  type FwcimInput,
  inputFields,
  type PreparedFwcimInput,
  prepareFwcim,
  prepareFwcimInputs,
} from "./amazon.js";
import { findProtections } from "./discovery.js";
import { local, NullgateError, retryDelay } from "./errors.js";
import {
  Page as Document,
  httpURL,
  type PageOptions,
  type Protection,
} from "./models.js";
import { Profile } from "./profile.js";
import {
  FwcimResult,
  type OperationOptions,
  type Reporter,
  Request,
  resultData,
} from "./solution.js";
import {
  type Collector,
  prepareCollector,
  Target,
  type TargetFetch,
} from "./threatmetrix.js";

export interface ClientOptions {
  readonly baseUrl?: string;
  readonly timeout?: number;
  /** API HTTP requests only, never target requests or the ThreatMetrix socket. */
  readonly fetch?: typeof globalThis.fetch;
}
export interface SessionOptions {
  readonly userAgent: string;
  readonly profile?: string;
  readonly timezone?: string | null;
}
export type Cookies =
  | null
  | Readonly<Record<string, string>>
  | ReadonlyMap<string, string>
  | { readonly jar: Cookies }
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
    | readonly (InputField | PreparedInput)[]
    | null;
  readonly actions?: readonly Action[] | null;
}
export interface PixelOptions {
  readonly script: string;
  readonly scriptUrl?: string;
  readonly challenge?: string | null;
}
export interface SbsdOptions {
  readonly script: string;
  readonly scriptUrl?: string;
  readonly cookies: Cookies;
}
export interface FwcimOptions {
  readonly form?: string | null;
  readonly timing: Readonly<Record<string, number>>;
  readonly inputs?:
    | Readonly<Record<string, string>>
    | readonly (FwcimInput | PreparedFwcimInput)[]
    | null;
  readonly actions?: readonly FwcimAction[] | null;
  readonly cookies?: Cookies;
  readonly submitted?: boolean;
  readonly referrer?: string;
  readonly historyLength?: number | null;
}
export interface ThreatMetrixOptions {
  readonly send: TargetFetch;
  readonly scriptUrl?: string | null;
  readonly collector?: Collector | null;
  readonly proxy?: string | null;
  readonly inputs?: SensorOptions["inputs"];
  readonly actions?: readonly Action[] | null;
}
export interface UsageOptions {
  readonly interval?: string;
  readonly start?: string | Date | null;
  readonly end?: string | Date | null;
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
  if (!source) return {};
  if (typeof source !== "object")
    throw new NullgateError(
      "invalid_cookies",
      "cookies must be a mapping or cookie jar",
    );
  if ("jar" in source && source.jar !== null && typeof source.jar === "object")
    source = source.jar as Exclude<Cookies, null>;
  if (Array.isArray(source) && source.length > 0)
    throw new NullgateError(
      "invalid_cookies",
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
    if (names.includes(name) && typeof value === "string")
      selected[name] = value;
  return selected;
}

// Keep best-effort reports from hiding caller programming errors.
function networkFailure(error: unknown): boolean {
  const cause =
    error instanceof TypeError && error.cause !== undefined
      ? error.cause
      : error;
  if (cause instanceof AggregateError)
    return cause.errors.length > 0 && cause.errors.every(networkFailure);
  if (cause instanceof DOMException && cause.name === "NetworkError")
    return true;
  if (
    cause === null ||
    typeof cause !== "object" ||
    !("code" in cause) ||
    typeof cause.code !== "string"
  )
    return false;
  return /^(?:ECONNRESET|ECONNREFUSED|ECONNABORTED|ENOTFOUND|EAI_AGAIN|ETIMEDOUT|EPIPE|EHOSTUNREACH|ENETUNREACH|ENETDOWN|UND_ERR_(?:CONNECT_TIMEOUT|HEADERS_TIMEOUT|BODY_TIMEOUT|SOCKET|DESTROYED|CLOSED|HEADERS_OVERFLOW|RES_CONTENT_LENGTH_MISMATCH|TRAILER_MISMATCH)|HPE_[A-Z_]+|Z_DATA_ERROR|Z_BUF_ERROR|CERT_[A-Z_]+|ERR_TLS_[A-Z_]+|DEPTH_ZERO_SELF_SIGNED_CERT|SELF_SIGNED_CERT_IN_CHAIN|UNABLE_TO_VERIFY_LEAF_SIGNATURE)$/.test(
    cause.code,
  );
}

export class Nullgate {
  readonly #key: string;
  readonly #base: string;
  readonly #timeout: number;
  readonly #fetch: typeof globalThis.fetch | undefined;
  /** @internal */
  readonly _reporter: Reporter;
  constructor(
    apiKey: string | undefined = process.env.NULLGATE_API_KEY,
    options: ClientOptions = {},
  ) {
    if (typeof apiKey !== "string" || !apiKey.trim() || /[\r\n]/.test(apiKey))
      throw new NullgateError(
        "invalid_key",
        "Provide apiKey or NULLGATE_API_KEY",
      );
    this.#key = apiKey;
    const base = local(
      () => httpURL(options.baseUrl ?? "https://api.nullgate.club", "baseUrl"),
      "invalid_url",
    );
    if (base.username || base.password || base.search || base.hash)
      throw new NullgateError(
        "invalid_url",
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
    this.#fetch = options.fetch ?? undefined;
    if (this.#fetch !== undefined && typeof this.#fetch !== "function")
      throw new NullgateError(
        "invalid_request",
        "fetch must be a native-fetch-compatible function",
      );
    this._reporter = this.report.bind(this);
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
    const query = new URLSearchParams({ interval: options.interval ?? "hour" });
    for (const [name, value] of Object.entries({
      start: options.start,
      end: options.end,
    }))
      if (value != null)
        query.set(name, value instanceof Date ? value.toISOString() : value);
    return (await this._call(
      `/account/usage${query.size ? `?${query}` : ""}`,
    )) as unknown as Usage;
  }
  /** True means HTTP delivery, not target acceptance or a refund. */
  async report(
    requestId: string,
    options: OperationOptions = {},
  ): Promise<boolean> {
    if (typeof requestId !== "string" || !requestId)
      throw new NullgateError(
        "invalid_request",
        "requestId must be a nonempty string",
      );
    options.signal?.throwIfAborted();
    const signal = AbortSignal.any([
      AbortSignal.timeout(Math.ceil(Math.min(3000, this.#timeout))),
      ...(options.signal === undefined ? [] : [options.signal]),
    ]);
    try {
      const response = await (this.#fetch ?? globalThis.fetch)(
        `${this.#base}/analytics/report`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ request_id: requestId }),
          redirect: "manual",
          credentials: "omit",
          signal,
        },
      );
      await response.arrayBuffer();
      options.signal?.throwIfAborted();
      return !signal.aborted && response.ok;
    } catch (error) {
      options.signal?.throwIfAborted();
      if (signal.aborted || networkFailure(error)) return false;
      throw error;
    }
  }
  /** @internal */
  async _call(
    path: string,
    body?: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const signal = AbortSignal.timeout(Math.ceil(this.#timeout));
    try {
      for (let attempt = 0; ; attempt++) {
        const response = await (this.#fetch ?? globalThis.fetch)(
          `${this.#base}${path}`,
          {
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
          },
        );
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
        reporter: this._reporter,
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
  #sensorRetention:
    | { document: Document; session: string; digest: string }
    | undefined;
  constructor(client: Nullgate, options: SessionOptions) {
    if (
      !options ||
      typeof options.userAgent !== "string" ||
      !options.userAgent.trim() ||
      /[\r\n]/.test(options.userAgent)
    )
      throw new NullgateError(
        "invalid_request",
        "userAgent must be a nonempty header value",
      );
    const rawProfile = String(options.profile ?? randomUUID())
      .replace(/^urn:uuid:/, "")
      .replace(/^\{+|\}+$/g, "")
      .replaceAll("-", "");
    if (!/^[0-9a-f]{32}$/i.test(rawProfile))
      throw new NullgateError("invalid_request", "profile must be a UUID");
    const profile = rawProfile
      .toLowerCase()
      .replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, "$1-$2-$3-$4-$5");
    this.#client = client;
    this.#options = { ...options, profile };
  }
  page(url: string, html: string, options: PageOptions = {}): Page {
    local(() => httpURL(url, "page URL"), "invalid_url");
    return local(() => {
      const document = new Document(url, html, options);
      documentFor(document);
      return new Page(this, document, options.startedAtMs != null);
    }, "invalid_page");
  }
  /** @internal */
  _run<T>(
    product: string,
    document: Document,
    fields: Record<string, unknown>,
    finish: (data: Record<string, unknown>, reporter: Reporter) => T,
  ): Promise<T> {
    const pending = (this.#pending.get(product) ?? Promise.resolve())
      .catch(() => undefined)
      .then(async () => {
        const body = {
          ...this._context(product, document),
          ...Object.fromEntries(
            Object.entries(fields).filter(([name]) => name !== "operation"),
          ),
        };
        const sensor = product === "akamai" && fields.operation === "sensor";
        const digest =
          sensor && typeof fields.script === "string"
            ? createHash("sha256").update(fields.script, "utf8").digest("hex")
            : undefined;
        if (
          digest !== undefined &&
          this.#sensorRetention?.document === document &&
          this.#sensorRetention.session === body.session &&
          this.#sensorRetention.digest === digest
        ) {
          delete body.script;
          body.script_digest = digest;
        } else if (sensor) {
          this.#sensorRetention = undefined;
        }
        let data: Record<string, unknown>;
        try {
          data = await this.#client._call(
            `/${product}/${fields.operation}`,
            body,
          );
        } catch (error) {
          if (
            !sensor ||
            !(error instanceof NullgateError) ||
            error.code !== "script_required"
          )
            throw error;
          this.#sensorRetention = undefined;
          delete body.script_digest;
          body.script = fields.script;
          data = await this.#client._call(
            `/${product}/${fields.operation}`,
            body,
          );
        }
        const result = finish(data, this.#client._reporter);
        if (typeof data.session !== "string" || !data.session)
          throw new NullgateError("protocol_error", "Missing response session");
        this.#states.set(product, data.session);
        if (sensor) {
          this.#sensorRetention =
            data.script_retained === true && digest !== undefined
              ? { document, session: data.session, digest }
              : undefined;
        } else if (
          product === "akamai" &&
          (fields.operation === "pixel" ||
            this.#sensorRetention?.document !== document ||
            this.#sensorRetention?.session !== data.session)
        ) {
          this.#sensorRetention = undefined;
        }
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
    entry: Record<string, unknown>,
    options: ThreatMetrixOptions,
  ): Promise<Profile> {
    return this.#client._profile(
      {
        ...this._context("threatmetrix", document),
        type: "start",
        at_ms: Date.now(),
        ...entry,
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
  readonly #pixelChallenges: readonly string[];
  readonly #pixelUrls: readonly string[];
  readonly #explicitStartedAt: boolean;
  constructor(session: Session, document: Document, explicitStartedAt = false) {
    this.#explicitStartedAt = explicitStartedAt;
    this.#session = session;
    this.#document = document;
    const discovery = findProtections(document);
    this.#found = discovery.found;
    this.#pixelChallenges = discovery.challenges;
    this.#pixelUrls = discovery.pixelUrls;
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
  #resolve(value: string): string {
    return local(() => {
      const resolved = /^[A-Za-z][A-Za-z0-9+.-]*:/.test(value)
        ? value
        : value.startsWith("//")
          ? new URL(this.#document.url).protocol + value
          : new URL(value, this.#document.url).href;
      httpURL(resolved, "scriptUrl");
      return resolved;
    }, "invalid_url");
  }
  #candidate(
    kind: string,
    explicit?: string,
  ): { scriptURL: string; challenge?: string } | undefined {
    const resolved =
      explicit === undefined ? undefined : this.#resolve(explicit);
    const candidates =
      kind === "pixel" && resolved !== undefined
        ? this.#pixelChallenges.map((challenge) => ({
            scriptURL: resolved,
            challenge,
          }))
        : this.#found.filter(
            (candidate) =>
              candidate.kind === kind &&
              (resolved === undefined || candidate.scriptURL === resolved),
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
    if (resolved !== undefined && kind !== "pixel")
      return { scriptURL: resolved };
    return unique[0];
  }
  #script(kind: string, options: PixelOptions): string {
    if (!options || typeof options !== "object")
      throw new NullgateError(
        "invalid_request",
        "Provide script source options",
      );
    const url = this.#candidate(kind, options.scriptUrl)?.scriptURL;
    if (url === undefined)
      throw new NullgateError(
        "protection_not_found",
        `No ${kind} script found; provide scriptUrl`,
      );
    return url;
  }
  #inputs(
    inputs:
      | Readonly<Record<string, string>>
      | readonly (InputField | PreparedInput)[]
      | null
      | undefined,
  ): (InputField | PreparedInput)[] {
    return (
      Array.isArray(inputs)
        ? [...inputs]
        : inputFields(
            this.#document,
            inputs as Readonly<Record<string, string>> | null | undefined,
          )
    ) as (InputField | PreparedInput)[];
  }
  #prepareInputs(inputs: SensorOptions["inputs"]): PreparedInput[] {
    return local(() => {
      documentFor(this.#document);
      const fields = this.#inputs(inputs);
      return fields.map((field) => {
        if ("attributes" in field || typeof field.value === "object")
          return validatePreparedInput(field);
        if (
          field.type?.trim().toLowerCase() === "password" ||
          [field.id, field.name].some((value) =>
            ["password", "ap_password"].includes(
              value?.trim().toLowerCase() ?? "",
            ),
          ) ||
          (field.autocomplete ?? "")
            .trim()
            .toLowerCase()
            .split(/\s+/)
            .some((token) =>
              ["current-password", "new-password"].includes(token),
            )
        )
          throw new NullgateError(
            "invalid_inputs",
            "Password observations are not allowed",
          );
        if (Object.values(field).some((value) => typeof value !== "string"))
          throw new NullgateError(
            "invalid_inputs",
            "Input attributes must contain strings",
          );
        {
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
              "invalid_inputs",
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
              ...Object.fromEntries(
                Object.entries(field).filter(([name]) =>
                  ["id", "name"].includes(name),
                ),
              ),
            },
            value: observed.value,
            ...(observed.selector === undefined
              ? {}
              : { selector: observed.selector }),
          };
        }
      });
    }, "invalid_inputs");
  }
  async sensor(options: SensorOptions): Promise<Request> {
    const scriptUrl = this.#script("sensor", options);
    const inputs =
      options.inputs == null ? undefined : this.#prepareInputs(options.inputs);
    const actions =
      options.actions == null
        ? undefined
        : local(() => prepareActions(options.actions ?? []), "invalid_actions");
    return this.#generate("sensor", {
      script_url: scriptUrl,
      script: options.script,
      cookies: await cookiesFor(
        options.cookies,
        ["_abck", "bm_sz"],
        this.#document.url,
      ),
      ...(inputs === undefined ? {} : { inputs }),
      ...(actions === undefined ? {} : { actions }),
    });
  }
  async pixel(options: PixelOptions): Promise<Request> {
    if (options.challenge != null) {
      if (
        typeof options.challenge !== "string" ||
        !/^\p{Decimal_Number}+$/u.test(options.challenge)
      )
        throw new NullgateError(
          "invalid_request",
          "challenge must be a nonempty decimal string",
        );
      const urls =
        options.scriptUrl === undefined
          ? [...new Set(this.#pixelUrls)]
          : [this.#resolve(options.scriptUrl)];
      if (urls.length > 1)
        throw new NullgateError(
          "ambiguous_protection",
          `Choose scriptUrl from: ${urls.join(", ")}`,
        );
      if (urls[0] === undefined)
        throw new NullgateError(
          "protection_not_found",
          "No pixel script found; provide scriptUrl",
        );
      return this.#generate("pixel", {
        script_url: urls[0],
        script: options.script,
        challenge: options.challenge,
      });
    }
    const scriptUrl = this.#script("pixel", options);
    const candidate = this.#candidate("pixel", scriptUrl);
    if (candidate === undefined || !("challenge" in candidate))
      throw new NullgateError(
        "protection_not_found",
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
      cookies: await cookiesFor(
        options.cookies,
        ["bm_so", "sbsd_o", "bm_s"],
        this.#document.url,
      ),
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
      (data, reporter) =>
        new Request(resultData(data, this.#document.url), reporter),
    );
  }
  async fwcim(options: FwcimOptions): Promise<FwcimResult> {
    const inputs = local(
      () =>
        options.inputs == null
          ? null
          : inputFields(this.#document, options.inputs),
      "invalid_inputs",
    );
    const fields = local(() => {
      if (
        this.#explicitStartedAt &&
        options.timing?.navigationStart !== this.#document.startedAtMs
      )
        throw new TypeError(
          "timing.navigationStart must match the explicit page start",
        );
      return prepareFwcim(
        this.#document,
        options.form ?? null,
        options.timing,
        inputs,
        options.actions,
        options,
      );
    }, "invalid_inputs");
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
      (data, reporter) =>
        new FwcimResult(resultData(data, this.#document.url, true), reporter),
    );
  }
  async threatmetrix(options: ThreatMetrixOptions): Promise<Profile> {
    if (!options || typeof options.send !== "function")
      throw new NullgateError(
        "invalid_request",
        "send must be a request callback",
      );
    local(() => documentFor(this.#document));
    const observations = {
      ...(options.inputs == null
        ? {}
        : { inputs: this.#prepareInputs(options.inputs) }),
      ...(options.actions == null
        ? {}
        : {
            actions: local(
              () => prepareActions(options.actions ?? []),
              "invalid_actions",
            ),
          }),
    };
    if (options.collector != null) {
      if (options.scriptUrl != null)
        throw new NullgateError(
          "invalid_request",
          "Provide exactly one scriptUrl or collector",
        );
      return this.#session._profile(
        this.#document,
        { collector: prepareCollector(options.collector), ...observations },
        options,
      );
    }
    const scriptUrl = this.#candidate(
      "profile",
      options.scriptUrl ?? undefined,
    )?.scriptURL;
    if (scriptUrl === undefined)
      throw new NullgateError(
        "protection_not_found",
        "No ThreatMetrix tags script found; provide scriptUrl",
      );
    return this.#session._profile(
      this.#document,
      { tags_url: scriptUrl, ...observations },
      options,
    );
  }
}
