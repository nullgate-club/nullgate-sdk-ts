import WebSocket, { type RawData } from "ws";
import {
  NullgateAPIError,
  NullgateClosedError,
  NullgateProtocolError,
  NullgateTransportError,
} from "./errors.js";
import type { OperationOptions, Reporter } from "./solution.js";
import {
  Target,
  type TargetRequest,
  type TargetResponse,
} from "./threatmetrix.js";
import type { RelayAllocation, TurnServer } from "./turn.js";

export interface PagehideOptions extends OperationOptions {
  readonly atMs?: number;
  readonly persisted?: boolean;
}

interface ProfileConnection {
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly start: string;
  readonly target: Target;
  readonly timeoutMs: number;
  readonly signal: AbortSignal;
  readonly rotateState: (stateId: string) => void;
  readonly reporter: Reporter;
}

interface IceOperation {
  readonly abort: AbortController;
  allocation: RelayAllocation | undefined;
  released: boolean;
}

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function headers(value: unknown): value is Record<string, string> {
  return (
    object(value) &&
    Object.entries(value).every(
      ([name, value]) =>
        /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) &&
        typeof value === "string" &&
        !/[\r\n\0]/.test(value),
    )
  );
}

function isRequestId(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{32}$/.test(value);
}

function abortable<T>(pending: Promise<T>, signal: AbortSignal): Promise<T> {
  const { promise, resolve, reject } = Promise.withResolvers<T>();
  const aborted = () => reject(signal.reason);
  signal.addEventListener("abort", aborted, { once: true });
  pending.then(
    (value) => {
      signal.removeEventListener("abort", aborted);
      resolve(value);
    },
    (error: unknown) => {
      signal.removeEventListener("abort", aborted);
      reject(error);
    },
  );
  if (signal.aborted) aborted();
  return promise;
}

/** An active document. ready, collection completion, and departure are distinct. */
export class Profile {
  readonly #socket: WebSocket;
  readonly #target: Target;
  readonly #reporter: Reporter;
  readonly #signal: AbortSignal;
  readonly #timeoutMs: number;
  readonly #operations = new AbortController();
  readonly #ready = Promise.withResolvers<void>();
  readonly #collected = Promise.withResolvers<void>();
  readonly #closed = Promise.withResolvers<void>();
  readonly #ids = new Set<number>();
  readonly #ice = new Map<number, IceOperation>();
  readonly #tasks = new Set<Promise<void>>();
  readonly #aborted: () => void;
  #startupTimer: NodeJS.Timeout | undefined;
  #writeTail: Promise<void> = Promise.resolve();
  #pagehide: PromiseWithResolvers<void> | undefined;
  #requestId: string | undefined;
  #isReady = false;
  #isCollected = false;
  #stopped = false;
  #failure: unknown;

  private constructor(connection: ProfileConnection) {
    this.#target = connection.target;
    this.#reporter = connection.reporter;
    this.#signal = connection.signal;
    this.#timeoutMs = connection.timeoutMs;
    this.#aborted = () => this.#fail(this.#signal.reason);
    // agent:false prevents environment proxy adoption on the API connection.
    this.#socket = new WebSocket(connection.url, {
      headers: { ...connection.headers },
      agent: false,
      followRedirects: false,
      perMessageDeflate: false,
      handshakeTimeout: connection.timeoutMs,
    });
    // Startup/background failures are retained for the caller without unhandled rejections.
    void this.#ready.promise.catch(() => undefined);
    void this.#collected.promise.catch(() => undefined);
    this.#socket.on("error", () => {
      if (!this.#stopped)
        this.#fail(new NullgateTransportError(this.#requestId ?? null));
    });
    this.#socket.once("unexpected-response", (_request, response) => {
      response.resume();
      const id = response.headers["x-request-id"];
      this.#fail(
        new NullgateAPIError(
          response.statusCode ?? 0,
          typeof id === "string" ? id : (this.#requestId ?? null),
          "Profile WebSocket handshake was rejected",
        ),
      );
    });
    this.#socket.once("close", () => {
      if (!this.#stopped)
        this.#fail(new NullgateTransportError(this.#requestId ?? null));
    });
    this.#socket.on("message", (data: RawData, binary: boolean) => {
      if (this.#stopped) return;
      try {
        if (binary) throw this.#protocol("expected a JSON text message");
        const bytes = Array.isArray(data)
          ? Buffer.concat(data)
          : data instanceof ArrayBuffer
            ? Buffer.from(data)
            : data;
        let message: unknown;
        try {
          message = JSON.parse(bytes.toString("utf8"));
        } catch {
          throw this.#protocol("malformed JSON message");
        }
        this.#receive(message, connection.rotateState);
      } catch (error) {
        this.#fail(error);
      }
    });
    this.#socket.once("open", () => {
      if (this.#stopped) return;
      this.#run(this.#send(connection.start));
    });
    this.#startupTimer = setTimeout(() => {
      this.#fail(new NullgateTransportError(this.#requestId ?? null));
    }, connection.timeoutMs);
    this.#signal.addEventListener("abort", this.#aborted, { once: true });
    if (this.#signal.aborted) this.#aborted();
  }

  /** @internal */
  static _connect(connection: ProfileConnection): Profile {
    connection.signal.throwIfAborted();
    if (!(connection.target instanceof Target))
      throw new TypeError("profile requires a Target");
    return new Profile(connection);
  }

  /** @internal */
  async _waitForReady(): Promise<void> {
    await this.#ready.promise;
    this.#assertActive();
  }

  /** @internal */
  get _closed(): Promise<void> {
    return this.#closed.promise;
  }

  get requestId(): string {
    if (this.#requestId === undefined)
      throw this.#protocol("profile has no request ID");
    return this.#requestId;
  }

  get isCollected(): boolean {
    return this.#isCollected;
  }

  get isClosed(): boolean {
    return this.#stopped;
  }

  /** Background failures remain observable even after collection has finished. */
  get error(): unknown {
    return this.#failure;
  }

  async waitForCollected(options: OperationOptions = {}): Promise<void> {
    this.#assertActive();
    options.signal?.throwIfAborted();
    await (options.signal === undefined
      ? this.#collected.promise
      : abortable(this.#collected.promise, options.signal));
    this.#assertActive();
  }

  async pagehide(options: PagehideOptions = {}): Promise<void> {
    this.#assertActive();
    options.signal?.throwIfAborted();
    const atMs = options.atMs ?? Date.now();
    const persisted = options.persisted ?? false;
    if (!Number.isFinite(atMs) || atMs < 0)
      throw new RangeError(
        "pagehide atMs must be finite nonnegative milliseconds",
      );
    if (typeof persisted !== "boolean")
      throw new TypeError("pagehide persisted must be a boolean");
    if (this.#pagehide !== undefined)
      throw new TypeError("A pagehide is already awaiting acknowledgement");
    const completion = Promise.withResolvers<void>();
    this.#pagehide = completion;
    void completion.promise.catch(() => undefined);
    const aborted = () => this.#fail(options.signal?.reason);
    options.signal?.addEventListener("abort", aborted, { once: true });
    try {
      if (options.signal?.aborted) aborted();
      await this.#send({ type: "pagehide", at_ms: atMs, persisted });
      await completion.promise;
      this.#assertActive();
    } catch (error) {
      this.#fail(error);
      throw error;
    } finally {
      options.signal?.removeEventListener("abort", aborted);
    }
  }

  /** True means analytics HTTP delivery, not target acceptance or a refund. */
  report(options: OperationOptions = {}): Promise<boolean> {
    return this.#reporter(this.requestId, options);
  }

  close(): Promise<void> {
    return this.#stop(undefined, true);
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }

  #assertActive(): void {
    if (this.#failure !== undefined) throw this.#failure;
    if (this.#stopped) throw new NullgateClosedError("profile");
  }

  #protocol(message: string): NullgateProtocolError {
    return new NullgateProtocolError(message, 0, this.#requestId ?? null);
  }

  #correlation(value: unknown): number {
    if (
      typeof value !== "number" ||
      !Number.isSafeInteger(value) ||
      this.#ids.has(value)
    )
      throw this.#protocol("invalid or duplicate operation ID");
    this.#ids.add(value);
    return value;
  }

  #receive(message: unknown, rotateState: (stateId: string) => void): void {
    if (!object(message) || typeof message.type !== "string")
      throw this.#protocol("malformed profile message");
    if (message.type === "error") {
      if (
        typeof message.status !== "number" ||
        !Number.isInteger(message.status) ||
        message.status < 400 ||
        message.status > 599 ||
        typeof message.detail !== "string" ||
        (message.request_id !== null && !isRequestId(message.request_id))
      ) {
        throw this.#protocol("malformed service error");
      }
      if (
        this.#requestId !== undefined &&
        message.request_id !== this.#requestId
      )
        throw this.#protocol("service error request ID changed");
      throw new NullgateAPIError(
        message.status,
        message.request_id,
        message.detail,
      );
    }
    if (message.type === "hello") {
      if (
        this.#requestId !== undefined ||
        !isRequestId(message.request_id) ||
        typeof message.state_id !== "string" ||
        !message.state_id ||
        /[\r\n]/.test(message.state_id)
      ) {
        throw this.#protocol("malformed or duplicate hello");
      }
      this.#requestId = message.request_id;
      rotateState(message.state_id);
      return;
    }
    if (this.#requestId === undefined)
      throw this.#protocol("message received before hello");
    switch (message.type) {
      case "ready":
        if (this.#isReady || message.request_id !== this.#requestId)
          throw this.#protocol("malformed or duplicate ready");
        this.#isReady = true;
        clearTimeout(this.#startupTimer);
        this.#startupTimer = undefined;
        this.#ready.resolve();
        return;
      case "collected":
        if (
          !this.#isReady ||
          this.#isCollected ||
          message.request_id !== this.#requestId
        )
          throw this.#protocol("malformed or duplicate collected");
        this.#isCollected = true;
        this.#collected.resolve();
        return;
      case "http": {
        const id = this.#correlation(message.id);
        const request = this.#httpRequest(message.request);
        this.#run(this.#http(id, request));
        return;
      }
      case "ice": {
        const id = this.#correlation(message.id);
        const server = this.#turnServer(message.server);
        const operation: IceOperation = {
          abort: new AbortController(),
          allocation: undefined,
          released: false,
        };
        this.#ice.set(id, operation);
        this.#run(this.#gather(id, server, operation));
        return;
      }
      case "ice.release": {
        if (typeof message.id !== "number" || !Number.isSafeInteger(message.id))
          throw this.#protocol("invalid ICE release ID");
        const operation = this.#ice.get(message.id);
        if (operation === undefined || operation.released)
          throw this.#protocol("unknown or duplicate ICE release ID");
        operation.released = true;
        operation.abort.abort(new NullgateClosedError("profile"));
        if (operation.allocation !== undefined)
          this.#run(operation.allocation.close());
        return;
      }
      case "pagehide.done":
        if (this.#pagehide === undefined)
          throw this.#protocol("unexpected pagehide acknowledgement");
        this.#pagehide.resolve();
        this.#pagehide = undefined;
        return;
      default:
        throw this.#protocol("unknown profile message type");
    }
  }

  #httpRequest(value: unknown): TargetRequest {
    if (
      !object(value) ||
      typeof value.role !== "string" ||
      !value.role ||
      typeof value.url !== "string" ||
      typeof value.method !== "string" ||
      !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(value.method) ||
      !headers(value.headers) ||
      (value.credentials !== "include" && value.credentials !== "omit") ||
      (value.body !== null && typeof value.body !== "string")
    ) {
      throw this.#protocol("malformed target HTTP request");
    }
    let url: URL;
    try {
      url = new URL(value.url);
    } catch {
      throw this.#protocol("invalid target HTTP URL");
    }
    if (
      !["http:", "https:"].includes(url.protocol) ||
      url.username ||
      url.password
    )
      throw this.#protocol("invalid target HTTP URL");
    if (
      value.credentials === "omit" &&
      Object.keys(value.headers).some((name) =>
        /^(?:cookie|cookie2)$/i.test(name),
      )
    ) {
      throw this.#protocol("omit request contains a Cookie header");
    }
    let body: Buffer | null = null;
    if (value.body !== null) {
      body = Buffer.from(value.body, "base64");
      if (body.toString("base64") !== value.body)
        throw this.#protocol("target HTTP body is not strict standard base64");
    }
    return Object.freeze({
      role: value.role,
      url: value.url,
      method: value.method,
      headers: Object.freeze({ ...value.headers }),
      body,
      credentials: value.credentials,
      signal: this.#operations.signal,
    });
  }

  #turnServer(value: unknown): TurnServer {
    if (
      !object(value) ||
      typeof value.host !== "string" ||
      !value.host ||
      /[\s\r\n\0/\\]/.test(value.host) ||
      typeof value.port !== "number" ||
      !Number.isInteger(value.port) ||
      value.port < 1 ||
      value.port > 65535 ||
      value.transport !== "tcp" ||
      typeof value.username !== "string" ||
      typeof value.credential !== "string"
    ) {
      throw this.#protocol("malformed TURN/TCP server");
    }
    return {
      host: value.host,
      port: value.port,
      transport: "tcp",
      username: value.username,
      credential: value.credential,
    };
  }

  async #http(id: number, request: TargetRequest): Promise<void> {
    let response: TargetResponse;
    try {
      response = await abortable(this.#target._fetch(request), request.signal);
    } catch {
      if (!this.#stopped)
        await this.#send({
          type: "http.error",
          id,
          detail: "Target request failed",
        });
      return;
    }
    const receivedAtMs = Date.now();
    if (this.#stopped) return;
    if (
      !object(response) ||
      !Number.isInteger(response.status) ||
      response.status < 100 ||
      response.status > 599 ||
      !headers(response.headers) ||
      !(response.body instanceof Uint8Array)
    ) {
      throw this.#protocol("target fetch returned an invalid response");
    }
    await this.#send({
      type: "http.result",
      id,
      response: {
        status: response.status,
        headers: response.headers,
        body: Buffer.from(
          response.body.buffer,
          response.body.byteOffset,
          response.body.byteLength,
        ).toString("base64"),
        received_at_ms: receivedAtMs,
      },
    });
  }

  async #gather(
    id: number,
    server: TurnServer,
    operation: IceOperation,
  ): Promise<void> {
    const signal = AbortSignal.any([
      this.#operations.signal,
      operation.abort.signal,
    ]);
    try {
      operation.allocation = await this.#target._gather(
        server,
        signal,
        this.#timeoutMs,
      );
    } catch {
      if (!this.#stopped && !operation.released)
        await this.#send({ type: "ice.result", id, observation: null });
      return;
    }
    if (this.#stopped || operation.released) {
      await operation.allocation.close();
      return;
    }
    await this.#send({
      type: "ice.result",
      id,
      observation: operation.allocation.observation,
    });
    const completion = await operation.allocation.completion;
    if (completion === "failed" && !this.#stopped && !operation.released)
      throw new NullgateTransportError(this.#requestId ?? null);
  }

  #run(task: Promise<void>): void {
    this.#tasks.add(task);
    task.then(
      () => this.#tasks.delete(task),
      (error: unknown) => {
        this.#tasks.delete(task);
        if (!this.#stopped) this.#fail(error);
      },
    );
  }

  #send(message: object | string, closing = false): Promise<void> {
    const encoded =
      typeof message === "string" ? message : JSON.stringify(message);
    const sending = this.#writeTail.then(() => {
      if (this.#stopped && !closing) this.#assertActive();
      if (this.#socket.readyState !== WebSocket.OPEN)
        throw new NullgateTransportError(this.#requestId ?? null);
      const { promise, resolve, reject } = Promise.withResolvers<void>();
      try {
        this.#socket.send(encoded, (error) => {
          if (error)
            reject(new NullgateTransportError(this.#requestId ?? null));
          else resolve();
        });
      } catch {
        reject(new NullgateTransportError(this.#requestId ?? null));
      }
      return promise;
    });
    this.#writeTail = sending.catch(() => undefined);
    return sending;
  }

  #fail(error: unknown): void {
    void this.#stop(error, false);
  }

  #stop(error: unknown, notify: boolean): Promise<void> {
    if (this.#stopped) return this.#closed.promise;
    this.#stopped = true;
    this.#failure = error;
    clearTimeout(this.#startupTimer);
    this.#startupTimer = undefined;
    this.#signal.removeEventListener("abort", this.#aborted);
    const reason = error ?? new NullgateClosedError("profile");
    this.#operations.abort(reason);
    this.#ready.reject(reason);
    this.#collected.reject(reason);
    this.#pagehide?.reject(reason);
    this.#pagehide = undefined;
    const disconnected = Promise.withResolvers<void>();
    const timer = setTimeout(() => this.#socket.terminate(), 1_000);
    this.#socket.once("close", () => {
      clearTimeout(timer);
      disconnected.resolve();
    });
    if (this.#socket.readyState === WebSocket.CLOSED) {
      clearTimeout(timer);
      disconnected.resolve();
    }
    const cleanup = async () => {
      try {
        if (notify && this.#socket.readyState === WebSocket.OPEN) {
          try {
            await this.#send({ type: "close" }, true);
          } catch {
            // Closing the socket still cancels the server's document work.
          }
        }
        if (this.#socket.readyState === WebSocket.OPEN)
          this.#socket.close(1000);
        else if (this.#socket.readyState === WebSocket.CONNECTING)
          this.#socket.terminate();
        await Promise.allSettled([
          ...this.#tasks,
          ...Array.from(this.#ice.values(), (operation) =>
            operation.allocation?.close(),
          ),
          this.#writeTail,
          disconnected.promise,
        ]);
      } finally {
        clearTimeout(timer);
        this.#closed.resolve();
      }
    };
    void cleanup();
    return this.#closed.promise;
  }
}
