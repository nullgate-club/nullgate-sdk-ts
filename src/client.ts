import { randomUUID } from "node:crypto";
import type { Params } from "./akamai.js";
import { type FindOptions, findProtections } from "./discovery.js";
import { NullgateClosedError, NullgateTransportError } from "./errors.js";
import { httpURL, type Page, type Protection } from "./models.js";
import { Profile } from "./profile.js";
import {
  normalizeResponse,
  type PreparedRequest,
  prepareRequest,
} from "./protocol.js";
import { type OperationOptions, Solution } from "./solution.js";
import { Target, ThreatMetrixParams } from "./threatmetrix.js";

export interface ClientOptions {
  readonly apiKey: string;
  readonly baseURL?: string;
  readonly analyticsURL?: string;
  readonly profileBaseURL?: string;
  readonly timeoutMs?: number;
  readonly reportTimeoutMs?: number;
  /** Native-fetch-compatible seam for a caller-owned transport or local tests. */
  readonly fetch?: typeof globalThis.fetch;
}

export interface SessionOptions {
  readonly identity: string;
  readonly userAgent: string;
  readonly timezone?: string | null;
}

function serviceURL(value: string, name: string): string {
  const url = httpURL(value, name);
  if (url.username || url.password || url.search || url.hash) {
    throw new TypeError(
      `${name} cannot contain credentials, a query, or a fragment`,
    );
  }
  return url.href.replace(/\/+$/, "");
}

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
  ) {
    return false;
  }
  return /^(?:ECONNRESET|ECONNREFUSED|ECONNABORTED|ENOTFOUND|EAI_AGAIN|ETIMEDOUT|EPIPE|EHOSTUNREACH|ENETUNREACH|ENETDOWN|UND_ERR_(?:CONNECT_TIMEOUT|HEADERS_TIMEOUT|BODY_TIMEOUT|SOCKET|DESTROYED|CLOSED|HEADERS_OVERFLOW|RES_CONTENT_LENGTH_MISMATCH|TRAILER_MISMATCH)|HPE_[A-Z_]+|Z_DATA_ERROR|Z_BUF_ERROR|CERT_[A-Z_]+|ERR_TLS_[A-Z_]+|DEPTH_ZERO_SELF_SIGNED_CERT|SELF_SIGNED_CERT_IN_CHAIN|UNABLE_TO_VERIFY_LEAF_SIGNATURE)$/.test(
    cause.code,
  );
}

function abortable<T>(pending: Promise<T>, signal: AbortSignal): Promise<T> {
  const { promise, resolve, reject } = Promise.withResolvers<T>();
  if (signal.aborted) {
    reject(signal.reason);
    return promise;
  }
  const onAbort = () => {
    reject(signal.reason);
  };
  signal.addEventListener("abort", onAbort, { once: true });
  pending.then(
    (value) => {
      signal.removeEventListener("abort", onAbort);
      resolve(value);
    },
    (error: unknown) => {
      signal.removeEventListener("abort", onAbort);
      reject(error);
    },
  );
  return promise;
}

/** A reusable Nullgate API client, deliberately separate from the target transport. */
export class NullgateClient {
  readonly #apiKey: string;
  readonly #baseURL: string;
  readonly #analyticsURL: string;
  readonly #profileBaseURL: string;
  readonly #timeoutMs: number;
  readonly #reportTimeoutMs: number;
  readonly #fetch: typeof globalThis.fetch;
  readonly #lifetime = new AbortController();
  readonly #profiles = new Set<Profile>();

  constructor(options: ClientOptions) {
    if (
      typeof options.apiKey !== "string" ||
      !options.apiKey ||
      /[\r\n]/.test(options.apiKey)
    ) {
      throw new TypeError("apiKey must be a nonempty credential string");
    }
    this.#apiKey = options.apiKey;
    this.#baseURL = serviceURL(
      options.baseURL ?? "https://akamai.nullgate.club",
      "baseURL",
    );
    this.#analyticsURL = serviceURL(
      options.analyticsURL ?? "https://analytics.nullgate.club",
      "analyticsURL",
    );
    this.#profileBaseURL = serviceURL(
      options.profileBaseURL ?? "https://threatmetrix.nullgate.club",
      "profileBaseURL",
    );
    this.#timeoutMs = options.timeoutMs ?? 30_000;
    this.#reportTimeoutMs = options.reportTimeoutMs ?? 3_000;
    for (const timeout of [this.#timeoutMs, this.#reportTimeoutMs]) {
      if (
        !Number.isInteger(timeout) ||
        timeout <= 0 ||
        timeout > 2_147_483_647
      ) {
        throw new RangeError(
          "Timeouts must be positive finite milliseconds within the timer range",
        );
      }
    }
    this.#fetch = options.fetch ?? globalThis.fetch;
    if (typeof this.#fetch !== "function")
      throw new TypeError("A native-fetch-compatible transport is required");
  }

  get isClosed(): boolean {
    return this.#lifetime.signal.aborted;
  }

  /** @internal */
  get _signal(): AbortSignal {
    return this.#lifetime.signal;
  }

  open(options: SessionOptions): NullgateSession {
    this.#lifetime.signal.throwIfAborted();
    return new NullgateSession(this, options);
  }

  findProtections(page: Page, options: FindOptions = {}): Protection[] {
    return findProtections(page, options);
  }

  /** @internal */
  async _generate(
    identity: string,
    userAgent: string,
    stateId: string | undefined,
    request: PreparedRequest,
    signal: AbortSignal,
    rotateState: (stateId: string) => void,
  ): Promise<{ response: Response; body: unknown }> {
    const deadline = AbortSignal.any([
      signal,
      AbortSignal.timeout(this.#timeoutMs),
    ]);
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.#apiKey}`,
      "User-Agent": userAgent,
      "Content-Type": "application/json",
    };
    if (stateId !== undefined) headers["X-State-ID"] = stateId;
    try {
      const response = await this.#fetch(
        `${this.#baseURL}/v1/${identity}/generate?type=${request.operation}`,
        {
          method: "POST",
          headers,
          body: request.body,
          redirect: "manual",
          credentials: "omit",
          signal: deadline,
        },
      );
      const nextStateId = response.headers.get("X-State-ID");
      if (nextStateId !== null) rotateState(nextStateId);
      const text = await response.text();
      deadline.throwIfAborted();
      let body: unknown;
      try {
        body = JSON.parse(text);
      } catch {
        body = text;
      }
      return { response, body };
    } catch (error) {
      deadline.throwIfAborted();
      if (networkFailure(error)) throw new NullgateTransportError();
      throw error;
    }
  }

  /** @internal */
  async _profile(
    identity: string,
    userAgent: string,
    stateId: string | undefined,
    start: string,
    target: Target,
    signal: AbortSignal,
    rotateState: (stateId: string) => void,
  ): Promise<Profile> {
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.#apiKey}`,
      "User-Agent": userAgent,
    };
    if (stateId !== undefined) headers["X-State-ID"] = stateId;
    const url = new URL(`${this.#profileBaseURL}/v1/${identity}/profile`);
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    const profile = Profile._connect({
      url: url.href,
      headers,
      start,
      target,
      signal,
      timeoutMs: this.#timeoutMs,
      rotateState,
      reporter: this.report.bind(this),
    });
    this.#profiles.add(profile);
    void profile._closed.then(() => this.#profiles.delete(profile));
    try {
      await profile._waitForReady();
      return profile;
    } catch (error) {
      await profile.close();
      throw error;
    }
  }

  /** Best-effort HTTP delivery only; never sends API credentials or session state. */
  async report(
    requestId: string,
    options: OperationOptions = {},
  ): Promise<boolean> {
    this.#lifetime.signal.throwIfAborted();
    options.signal?.throwIfAborted();
    if (typeof requestId !== "string" || !requestId)
      throw new TypeError("requestId must be a nonempty string");
    const timeout = AbortSignal.timeout(this.#reportTimeoutMs);
    const signal = AbortSignal.any([
      this.#lifetime.signal,
      timeout,
      ...(options.signal === undefined ? [] : [options.signal]),
    ]);
    try {
      const response = await this.#fetch(`${this.#analyticsURL}/report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ request_id: requestId }),
        redirect: "manual",
        credentials: "omit",
        signal,
      });
      await response.arrayBuffer();
      options.signal?.throwIfAborted();
      this.#lifetime.signal.throwIfAborted();
      if (timeout.aborted) return false;
      return response.ok;
    } catch (error) {
      options.signal?.throwIfAborted();
      this.#lifetime.signal.throwIfAborted();
      if (networkFailure(error)) return false;
      if (
        timeout.aborted &&
        (error === timeout.reason ||
          (error instanceof DOMException &&
            (error.name === "AbortError" || error.name === "TimeoutError")))
      )
        return false;
      throw error;
    }
  }

  close(): void {
    this.#lifetime.abort(new NullgateClosedError("client"));
  }

  async [Symbol.asyncDispose](): Promise<void> {
    this.close();
    await Promise.all(Array.from(this.#profiles, (profile) => profile.close()));
  }
}

/** Sequential document continuations; independent sessions can run concurrently. */
export class NullgateSession {
  readonly identity: string;
  readonly userAgent: string;
  readonly timezone: string | undefined;
  readonly #client: NullgateClient;
  readonly #lifetime = new AbortController();
  #stateId: string | undefined = randomUUID();
  #pending: Promise<void> = Promise.resolve();
  readonly #profiles = new Set<Profile>();

  /** @internal */
  constructor(client: NullgateClient, options: SessionOptions) {
    if (
      typeof options.identity !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
        options.identity,
      )
    ) {
      throw new TypeError("identity must be a UUID string");
    }
    if (
      typeof options.userAgent !== "string" ||
      !options.userAgent ||
      /[\r\n]/.test(options.userAgent)
    ) {
      throw new TypeError("userAgent must be a nonempty HTTP header value");
    }
    if (options.timezone != null && typeof options.timezone !== "string") {
      throw new TypeError("timezone must be a string or null");
    }
    this.identity = options.identity.toLowerCase();
    this.userAgent = options.userAgent;
    this.timezone = options.timezone ?? undefined;
    this.#client = client;
    Object.freeze(this);
  }

  get isClosed(): boolean {
    return this.#lifetime.signal.aborted || this.#client.isClosed;
  }

  async solve(
    params: Params,
    options: OperationOptions = {},
  ): Promise<Solution> {
    const signal = AbortSignal.any([
      this.#lifetime.signal,
      this.#client._signal,
      ...(options.signal === undefined ? [] : [options.signal]),
    ]);
    signal.throwIfAborted();
    const request = prepareRequest(params, this.timezone);
    const pending = this.#pending.then(async () => {
      signal.throwIfAborted();
      const generated = await this.#client._generate(
        this.identity,
        this.userAgent,
        this.#stateId,
        request,
        signal,
        (stateId) => {
          this.#stateId = stateId;
        },
      );
      signal.throwIfAborted();
      return new Solution(
        normalizeResponse(generated.response, generated.body, request),
        this.#client.report.bind(this.#client),
      );
    });
    this.#pending = pending.then(
      () => undefined,
      () => undefined,
    );
    return abortable(pending, signal);
  }

  async profile(
    params: ThreatMetrixParams,
    target: Target,
    options: OperationOptions = {},
  ): Promise<Profile> {
    if (!(params instanceof ThreatMetrixParams))
      throw new TypeError("profile requires ThreatMetrixParams");
    if (!(target instanceof Target))
      throw new TypeError("profile requires a Target");
    const signal = AbortSignal.any([
      this.#lifetime.signal,
      this.#client._signal,
      ...(options.signal === undefined ? [] : [options.signal]),
    ]);
    signal.throwIfAborted();
    const start = params._startFrame(this.timezone);
    const pending = this.#pending.then(async () => {
      signal.throwIfAborted();
      const profile = await this.#client._profile(
        this.identity,
        this.userAgent,
        this.#stateId,
        start,
        target,
        signal,
        (stateId) => {
          this.#stateId = stateId;
        },
      );
      this.#profiles.add(profile);
      void profile._closed.then(() => this.#profiles.delete(profile));
      return profile;
    });
    this.#pending = pending.then(
      () => undefined,
      () => undefined,
    );
    return abortable(pending, signal);
  }

  close(): void {
    this.#lifetime.abort(new NullgateClosedError("session"));
    this.#stateId = undefined;
  }

  async [Symbol.asyncDispose](): Promise<void> {
    this.close();
    await this.#pending;
    await Promise.all(Array.from(this.#profiles, (profile) => profile.close()));
  }
}
