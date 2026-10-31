import {
  type Params,
  PixelParams,
  prepareActions,
  prepareInputs,
  SbsdParams,
  SensorParams,
} from "./akamai.js";
import { NullgateAPIError, NullgateProtocolError } from "./errors.js";
import { httpURL } from "./models.js";
import type { SolutionData } from "./solution.js";

export interface PreparedRequest {
  readonly operation: "pixel" | "akamai" | "sbsd";
  readonly body: string;
  readonly scriptURL: string;
}

/** Snapshot caller inputs before a queued solve; raw values never enter the request. */
export function prepareRequest(
  params: Params,
  timezone: string | undefined,
): PreparedRequest {
  let operation: PreparedRequest["operation"];
  let values: Record<string, unknown>;
  if (params instanceof PixelParams) {
    operation = "pixel";
    values = { challenge: params.protection.challenge };
  } else if (params instanceof SensorParams) {
    operation = "akamai";
    values = { cookies: { ...params.cookies } };
    if (params.inputs !== null) values.inputs = prepareInputs(params.inputs);
    if (params.actions !== null)
      values.actions = prepareActions(params.actions);
  } else if (params instanceof SbsdParams) {
    operation = "sbsd";
    values = { cookies: { ...params.cookies } };
  } else {
    throw new TypeError(
      "solve requires PixelParams, SensorParams, or SbsdParams",
    );
  }
  const protection = params.protection;
  values.website = {
    url: protection.page.url,
    html: protection.page.html,
    document_id: protection.page.documentId,
    started_at_ms: protection.page.startedAtMs,
  };
  values.script = { source: protection.scriptURL, text: params.script };
  if (timezone !== undefined) values.timezone = timezone;
  return {
    operation,
    body: JSON.stringify(values),
    scriptURL: protection.scriptURL,
  };
}

export function normalizeResponse(
  response: Response,
  body: unknown,
  request: PreparedRequest,
): SolutionData {
  const requestId = response.headers.get("X-Request-ID");
  if (!response.ok) {
    throw new NullgateAPIError(
      response.status,
      requestId,
      body !== null && typeof body === "object" && "detail" in body
        ? body.detail
        : body,
    );
  }
  const invalid = (message: string): never => {
    throw new NullgateProtocolError(message, response.status, requestId);
  };
  if (!requestId) return invalid("missing X-Request-ID");
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    return invalid("expected a JSON object");
  }
  const data = body as {
    send_at?: unknown;
    headers?: unknown;
    sensor_data?: unknown;
    url?: unknown;
    body?: unknown;
  };
  if (typeof data.send_at !== "number" || !Number.isFinite(data.send_at)) {
    return invalid("send_at must be a finite Unix timestamp");
  }
  if (
    data.headers === null ||
    typeof data.headers !== "object" ||
    Array.isArray(data.headers)
  ) {
    return invalid("headers must be a string mapping");
  }
  const headers = new Headers();
  for (const [name, value] of Object.entries(data.headers)) {
    if (typeof value !== "string")
      return invalid("headers must be a string mapping");
    try {
      headers.set(name, value);
    } catch {
      return invalid("headers contain an invalid HTTP field");
    }
  }
  headers.set(
    "Content-Type",
    request.operation === "akamai"
      ? "text/plain;charset=UTF-8"
      : request.operation === "pixel"
        ? "application/x-www-form-urlencoded"
        : "application/json",
  );
  let url: string;
  let targetBody: string;
  if (request.operation === "akamai") {
    if (typeof data.sensor_data !== "string")
      return invalid("sensor_data must be a string");
    url = request.scriptURL;
    targetBody = JSON.stringify({ sensor_data: data.sensor_data });
  } else {
    if (typeof data.url !== "string" || typeof data.body !== "string") {
      return invalid("url and body must be strings");
    }
    try {
      httpURL(data.url, "Generated target URL");
    } catch {
      return invalid("url must be an absolute HTTP(S) URL");
    }
    url = data.url;
    targetBody = data.body;
  }
  return {
    url,
    body: targetBody,
    headers: Object.fromEntries(headers),
    sendAt: data.send_at,
    requestId,
  };
}
