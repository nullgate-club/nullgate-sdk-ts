import { NullgateError } from "./errors.js";

export type SolverProduct =
  | "akamai"
  | "threatmetrix"
  | "pingone"
  | "amazon_acic";

export interface SolverCookie {
  name: string;
  value: string;
  domain?: string;
  path?: string;
  secure?: boolean;
  httpOnly?: boolean;
  expires?: number | null;
  hostOnly?: boolean;
  sameSite?: string | null;
}

export interface SolverTransport {
  emulation?: string;
  tlsOptions?: Readonly<Record<string, unknown>>;
  http2Options?: Readonly<Record<string, unknown>>;
  headersOrder?: readonly string[];
}

export interface SolverRequest<T extends SolverProduct = SolverProduct> {
  type: T;
  url: string;
  userAgent?: string;
  proxy?: string;
  session?: string;
  cookies?: readonly SolverCookie[];
  transport?: SolverTransport;
  headers?: Readonly<Record<string, string>>;
  scriptUrl?: string;
  html?: string;
  pixelIframe?: boolean;
  collector?: { url: string; orgId: string; sessionId: string };
  pingone?: {
    sdkConfig?: Readonly<Record<string, unknown>>;
    jwtDeviceAttributes?: string;
    jwtAgentPayload?: string;
    clientToken?: string;
    tokenHost?: string;
    behavioral?: Readonly<Record<string, unknown>>;
  };
  signal?: AbortSignal;
}

export interface SolverResults {
  akamai: { accepted: boolean };
  threatmetrix: { collected: boolean };
  pingone: {
    data: string;
    deviceId: string;
    sdkVersion: string;
    requestId: string;
  };
  amazon_acic: { status: string; url: string; statusCode: number };
}

export interface SolverResponse<T extends SolverProduct = SolverProduct> {
  cookies: SolverCookie[];
  result: SolverResults[T];
}

export interface SolverOptions {
  baseUrl?: string;
  timeoutMs?: number;
  fetch?: typeof fetch;
}

export class SolverError extends NullgateError {
  readonly stage: string;
  override readonly cause: unknown;

  constructor(
    code: string,
    message: string,
    stage: string,
    requestId: string | null = null,
    status: number | null = null,
    cause?: unknown,
  ) {
    super(code, message, requestId, status);
    this.name = "SolverError";
    this.stage = stage;
    this.cause = cause;
  }
}

export class Solver {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetch: typeof fetch;

  constructor(options: SolverOptions = {}) {
    let parsed: URL;
    try {
      parsed = new URL(options.baseUrl ?? "http://127.0.0.1:8191");
    } catch {
      throw new SolverError(
        "invalid_request",
        "baseUrl must be an absolute HTTP(S) URL",
        "validate",
      );
    }
    if (
      !["http:", "https:"].includes(parsed.protocol) ||
      parsed.username ||
      parsed.password ||
      parsed.search ||
      parsed.hash
    ) {
      throw new SolverError(
        "invalid_request",
        "baseUrl cannot contain credentials, query or fragment",
        "validate",
      );
    }
    this.baseUrl = parsed.href.replace(/\/$/, "");
    this.timeoutMs = options.timeoutMs ?? 190_000;
    if (
      !Number.isInteger(this.timeoutMs) ||
      this.timeoutMs <= 0 ||
      this.timeoutMs > 4_294_967_295
    ) {
      throw new SolverError(
        "invalid_request",
        "timeoutMs must be a positive integer in timer range",
        "validate",
      );
    }
    this.fetch = options.fetch ?? globalThis.fetch;
  }

  async solve<T extends SolverProduct>(
    request: SolverRequest<T>,
  ): Promise<SolverResponse<T>> {
    const {
      signal,
      userAgent,
      scriptUrl,
      pixelIframe,
      collector,
      pingone,
      transport,
      cookies,
      ...common
    } = request;
    const body = {
      ...common,
      user_agent: userAgent,
      script_url: scriptUrl,
      pixel_iframe: pixelIframe,
      collector: collector && {
        url: collector.url,
        org_id: collector.orgId,
        session_id: collector.sessionId,
      },
      pingone: pingone && {
        sdk_config: pingone.sdkConfig,
        jwt_device_attributes: pingone.jwtDeviceAttributes,
        jwt_agent_payload: pingone.jwtAgentPayload,
        client_token: pingone.clientToken,
        token_host: pingone.tokenHost,
        behavioral: pingone.behavioral,
      },
      transport: transport && {
        emulation: transport.emulation,
        tls_options: transport.tlsOptions,
        http2_options: transport.http2Options,
        headers_order: transport.headersOrder,
      },
      cookies: cookies?.map(({ httpOnly, hostOnly, sameSite, ...cookie }) => ({
        ...cookie,
        http_only: httpOnly,
        host_only: hostOnly,
        same_site: sameSite,
      })),
    };
    let encoded: string;
    try {
      encoded = JSON.stringify(body);
    } catch {
      throw new SolverError(
        "invalid_request",
        "Solve options must contain JSON values",
        "validate",
      );
    }
    const timeout = AbortSignal.timeout(this.timeoutMs);
    const combined = signal ? AbortSignal.any([signal, timeout]) : timeout;
    let response: Response;
    let data: unknown;
    try {
      response = await this.fetch(`${this.baseUrl}/solve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: encoded,
        signal: combined,
        redirect: "error",
      });
      if (!response.body)
        throw new SolverError(
          "invalid_response",
          "Local API returned an empty response",
          "response",
        );
      const reader = response.body.getReader();
      const decoder = new TextDecoder("utf-8", { fatal: true });
      let size = 0;
      let text = "";
      try {
        while (true) {
          const part = await reader.read();
          if (part.done) break;
          size += part.value.byteLength;
          if (size > 4 * 1024 * 1024) {
            await reader.cancel();
            throw new SolverError(
              "invalid_response",
              "Local API response exceeds 4 MiB",
              "response",
            );
          }
          try {
            text += decoder.decode(part.value, { stream: true });
          } catch {
            throw new SolverError(
              "invalid_response",
              "Local API returned invalid UTF-8",
              "response",
            );
          }
        }
      } finally {
        reader.releaseLock();
      }
      try {
        data = JSON.parse(text + decoder.decode());
      } catch {
        throw new SolverError(
          "invalid_response",
          "Local API returned invalid JSON",
          "response",
        );
      }
    } catch (error) {
      if (error instanceof SolverError) throw error;
      const cause = error instanceof Error ? error.name : typeof error;
      if (signal?.aborted)
        throw new SolverError(
          "cancelled",
          "Solve was cancelled",
          "transport",
          null,
          null,
          cause,
        );
      if (timeout.aborted)
        throw new SolverError(
          "timeout",
          "Local API request exceeded its deadline",
          "transport",
          null,
          null,
          cause,
        );
      throw new SolverError(
        "transport_error",
        "Cannot reach the local HTTP API. Start nullgate-http-api and check its address.",
        "transport",
        null,
        null,
        cause,
      );
    }
    if (!response.ok) {
      if (
        typeof data === "object" &&
        data !== null &&
        "code" in data &&
        "message" in data &&
        typeof data.code === "string" &&
        typeof data.message === "string"
      ) {
        const details = data as Record<string, unknown>;
        throw new SolverError(
          data.code,
          data.message,
          typeof details.stage === "string" ? details.stage : "response",
          typeof details.request_id === "string" ? details.request_id : null,
          response.status,
          typeof details.cause === "string" ? details.cause : undefined,
        );
      }
      throw new SolverError(
        "invalid_response",
        "Local solver returned an invalid error response",
        "response",
        null,
        response.status,
      );
    }
    if (
      typeof data !== "object" ||
      data === null ||
      !("cookies" in data) ||
      !Array.isArray(data.cookies) ||
      !("result" in data) ||
      typeof data.result !== "object" ||
      data.result === null ||
      Array.isArray(data.result)
    ) {
      throw new SolverError(
        "invalid_response",
        "Local solver returned an invalid response",
        "response",
        null,
        response.status,
      );
    }
    const result = data.result as Record<string, unknown>;
    const validResult =
      request.type === "akamai"
        ? result.accepted === true
        : request.type === "threatmetrix"
          ? result.collected === true
          : request.type === "pingone"
            ? ["data", "device_id", "sdk_version", "request_id"].every(
                (key) => typeof result[key] === "string" && result[key] !== "",
              )
            : result.status === "PASS" &&
              typeof result.url === "string" &&
              result.url !== "" &&
              Number.isInteger(result.status_code) &&
              (result.status_code as number) >= 200 &&
              (result.status_code as number) < 300;
    if (
      !validResult ||
      data.cookies.some(
        (cookie: unknown) =>
          typeof cookie !== "object" ||
          cookie === null ||
          typeof (cookie as Record<string, unknown>).name !== "string" ||
          typeof (cookie as Record<string, unknown>).value !== "string",
      )
    ) {
      throw new SolverError(
        "invalid_response",
        "Local solver returned invalid product data or cookies",
        "response",
        null,
        response.status,
      );
    }
    const converted =
      request.type === "pingone"
        ? {
            data: result.data,
            deviceId: result.device_id,
            sdkVersion: result.sdk_version,
            requestId: result.request_id,
          }
        : request.type === "amazon_acic"
          ? {
              status: result.status,
              url: result.url,
              statusCode: result.status_code,
            }
          : result;
    return {
      cookies: data.cookies.map((cookie: Record<string, unknown>) => {
        const { http_only, host_only, same_site, ...rest } = cookie;
        return {
          ...rest,
          ...(http_only !== undefined && { httpOnly: http_only }),
          ...(host_only !== undefined && { hostOnly: host_only }),
          ...(same_site !== undefined && { sameSite: same_site }),
        } as SolverCookie;
      }),
      result: converted as SolverResults[T],
    };
  }
}
