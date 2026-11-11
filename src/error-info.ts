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
