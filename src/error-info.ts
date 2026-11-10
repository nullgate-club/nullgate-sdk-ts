export interface ErrorTarget {
  readonly role: string;
  readonly method: string;
  readonly host: string;
}

export interface TransportCause {
  readonly kind:
    | "timeout"
    | "dns"
    | "tls"
    | "proxy"
    | "connection"
    | "cancelled"
    | "invalid_response"
    | "unknown";
  readonly type?: string;
  readonly code?: string;
}

export interface ErrorInfo {
  readonly code: string;
  readonly origin: "client" | "request" | "service" | "upstream";
  readonly message: string;
  readonly retryable: boolean | null;
  readonly stage?: string;
  readonly target?: ErrorTarget;
  readonly cause?: TransportCause;
  readonly commandId?: number;
}

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

const kinds: Readonly<Record<string, true>> = {
  timeout: true,
  dns: true,
  tls: true,
  proxy: true,
  connection: true,
  cancelled: true,
  invalid_response: true,
  unknown: true,
};

export function parseErrorInfo(value: unknown): ErrorInfo | undefined {
  if (!object(value)) return undefined;
  if (
    typeof value.code !== "string" ||
    !value.code ||
    typeof value.origin !== "string" ||
    !["client", "request", "service", "upstream"].includes(value.origin) ||
    typeof value.message !== "string" ||
    !(value.retryable === null || typeof value.retryable === "boolean") ||
    (value.stage !== undefined && typeof value.stage !== "string") ||
    (Object.hasOwn(value, "command_id") &&
      !(
        typeof value.command_id === "number" &&
        Number.isSafeInteger(value.command_id) &&
        value.command_id > 0
      ))
  )
    return undefined;
  let target: ErrorTarget | undefined;
  if (value.target !== undefined) {
    if (
      !object(value.target) ||
      typeof value.target.role !== "string" ||
      typeof value.target.method !== "string" ||
      typeof value.target.host !== "string"
    )
      return undefined;
    target = Object.freeze({
      role: value.target.role,
      method: value.target.method,
      host: value.target.host,
    });
  }
  let cause: TransportCause | undefined;
  if (value.cause !== undefined) {
    if (
      !object(value.cause) ||
      typeof value.cause.kind !== "string" ||
      !Object.hasOwn(kinds, value.cause.kind) ||
      (value.cause.type !== undefined &&
        !(
          typeof value.cause.type === "string" &&
          /^[A-Za-z0-9_.-]{1,128}$/.test(value.cause.type)
        )) ||
      (value.cause.code !== undefined &&
        !(
          typeof value.cause.code === "string" &&
          /^[A-Za-z0-9_.-]{1,64}$/.test(value.cause.code)
        ))
    )
      return undefined;
    cause = Object.freeze({
      kind: value.cause.kind as TransportCause["kind"],
      ...(typeof value.cause.type === "string"
        ? { type: value.cause.type }
        : {}),
      ...(typeof value.cause.code === "string"
        ? { code: value.cause.code }
        : {}),
    });
  }
  return Object.freeze({
    code: value.code,
    origin: value.origin as ErrorInfo["origin"],
    message: value.message,
    retryable: value.retryable,
    ...(typeof value.stage === "string" ? { stage: value.stage } : {}),
    ...(target ? { target } : {}),
    ...(cause ? { cause } : {}),
    ...(typeof value.command_id === "number"
      ? { commandId: value.command_id }
      : {}),
  });
}

const codes: Readonly<Record<string, TransportCause["kind"]>> = {
  ETIMEDOUT: "timeout",
  ESOCKETTIMEDOUT: "timeout",
  UND_ERR_CONNECT_TIMEOUT: "timeout",
  UND_ERR_HEADERS_TIMEOUT: "timeout",
  UND_ERR_BODY_TIMEOUT: "timeout",
  ENOTFOUND: "dns",
  EAI_AGAIN: "dns",
  CERT_HAS_EXPIRED: "tls",
  DEPTH_ZERO_SELF_SIGNED_CERT: "tls",
  ERR_TLS_CERT_ALTNAME_INVALID: "tls",
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: "tls",
  ECONNREFUSED: "connection",
  ECONNRESET: "connection",
  EPIPE: "connection",
  ENETUNREACH: "connection",
  EHOSTUNREACH: "connection",
  UND_ERR_SOCKET: "connection",
  ERR_PROXY_CONNECTION_FAILED: "proxy",
};

export function transportCause(error: unknown): TransportCause {
  let current = error;
  for (let depth = 0; depth < 4 && current instanceof Error; depth++) {
    if (current instanceof DOMException) {
      if (current.name === "AbortError")
        return { kind: "cancelled", type: "DOMException" };
      if (current.name === "TimeoutError")
        return { kind: "timeout", type: "DOMException" };
    }
    if (
      "code" in current &&
      typeof current.code === "string" &&
      Object.hasOwn(codes, current.code)
    ) {
      return {
        kind: codes[current.code] ?? "unknown",
        type: "Error",
        code: current.code,
      };
    }
    current = current.cause;
  }
  return { kind: "unknown" };
}
