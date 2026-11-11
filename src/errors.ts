export class NullgateError extends Error {
  readonly code: string;
  readonly requestId: string | null;
  readonly status: number | null;

  constructor(
    code: string,
    message: string,
    requestId: string | null = null,
    status: number | null = null,
  ) {
    super(message);
    this.name = "NullgateError";
    this.code = code;
    this.requestId = requestId;
    this.status = status;
  }
}

export function local<T>(action: () => T, code = "invalid_request"): T {
  try {
    return action();
  } catch (error) {
    if (error instanceof NullgateError) throw error;
    throw new NullgateError(
      code,
      error instanceof Error ? error.message : "Invalid input",
    );
  }
}

export function retryDelay(value: string | null): number | undefined {
  if (value === null) return undefined;
  if (/^\d+(?:\.\d+)?$/.test(value)) {
    const delay = Number(value);
    return Number.isFinite(delay) ? delay : undefined;
  }
  if (
    !/^[A-Za-z]{3}, \d{2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(value)
  )
    return undefined;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp)
    ? Math.max(0, (timestamp - Date.now()) / 1000)
    : undefined;
}
