import assert from "node:assert/strict";
import test from "node:test";
import { NullgateAPIError } from "@nullgate/sdk";

const { transportCause } =
  /** @type {typeof import("../src/error-info.js")} */ (
    await import(new URL("../dist/error-info.js", import.meta.url).href)
  );

for (const [code, kind] of [
  ["ETIMEDOUT", "timeout"],
  ["ENOTFOUND", "dns"],
  ["ERR_TLS_CERT_ALTNAME_INVALID", "tls"],
  ["ECONNREFUSED", "connection"],
  ["ERR_PROXY_CONNECTION_FAILED", "proxy"],
]) {
  test(`known transport code ${code} is safe without exposing messages`, () => {
    const underlying = Object.assign(new Error("private URL and credentials"), {
      code,
    });
    const error = new TypeError("private wrapper", { cause: underlying });
    assert.deepEqual(transportCause(error), { kind, type: "Error", code });
    assert.equal(
      JSON.stringify(transportCause(error)).includes("private"),
      false,
    );
  });
}

test("raw strings, messages and arbitrary code tokens do not imply a transport cause", () => {
  for (const error of [
    "timeout DNS TLS ECONNREFUSED private",
    new Error("timeout DNS TLS ECONNREFUSED private"),
    Object.assign(new Error("private"), { code: "https://user:private@host" }),
    { code: "ETIMEDOUT" },
    new NullgateAPIError(502, null, "private"),
  ]) {
    assert.deepEqual(transportCause(error), { kind: "unknown" });
  }
});

test("DOM cancellation and timeout causes use known exception types", () => {
  assert.deepEqual(transportCause(new DOMException("private", "AbortError")), {
    kind: "cancelled",
    type: "DOMException",
  });
  assert.deepEqual(
    transportCause(new DOMException("private", "TimeoutError")),
    {
      kind: "timeout",
      type: "DOMException",
    },
  );
});

for (const commandId of [1, 2, null, true, 0, -1, "1", 1.5]) {
  test(`HTTP command ID metadata is strict: ${commandId}`, () => {
    const error = new NullgateAPIError(502, null, "legacy failure", {
      code: "FUTURE_ERROR",
      origin: "service",
      message: "safe",
      retryable: null,
      command_id: commandId,
    });
    assert.equal(error.statusCode, 502);
    assert.equal(error.detail, "legacy failure");
    if (
      typeof commandId === "number" &&
      Number.isSafeInteger(commandId) &&
      commandId > 0
    ) {
      assert.equal(error.errorInfo?.commandId, commandId);
    } else {
      assert.equal(error.errorInfo, undefined);
    }
  });
}

test("structured failure rendering leads with classification, not private text", () => {
  const error = new NullgateAPIError(
    502,
    "diagnostic",
    "private detail",
    {
      code: "CLIENT_TRANSPORT_ERROR",
      origin: "client",
      message: "private metadata message",
      retryable: null,
      command_id: 1,
    },
    new Error("private target URL"),
  );
  assert.ok(error.message.startsWith("[CLIENT_TRANSPORT_ERROR/client]"));
  assert.ok(error.message.includes("Target HTTP transport failed"));
  assert.ok(error.message.includes("diagnostic"));
  assert.equal(error.message.includes("private"), false);
  const legacy = new NullgateAPIError(502, null, "private detail");
  assert.ok(legacy.message.startsWith("Unclassified Nullgate HTTP failure"));
});
