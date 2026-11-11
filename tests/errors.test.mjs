import assert from "node:assert/strict";
import test from "node:test";
import { Nullgate, NullgateError } from "@nullgate/sdk";

for (const [code, status] of [
  ["invalid_request", 400],
  ["invalid_page", 400],
  ["invalid_script", 400],
  ["invalid_key", 401],
  ["insufficient_balance", 402],
  ["forbidden", 403],
  ["not_found", 404],
  ["session_busy", 409],
  ["rate_limited", 429],
  ["internal", 500],
  ["upstream", 502],
  ["maintenance", 503],
  ["unavailable", 503],
]) {
  test(`maps ${code} without retrying or losing correlation`, async (t) => {
    let calls = 0;
    t.mock.method(globalThis, "fetch", async () => {
      calls++;
      return Response.json(
        { code, message: "Safe explanation", request_id: "correlation" },
        { status: Number(status) },
      );
    });
    await assert.rejects(new Nullgate("fake").account(), (error) => {
      assert.ok(error instanceof NullgateError);
      assert.equal(error.code, code);
      assert.equal(error.message, "Safe explanation");
      assert.equal(error.requestId, "correlation");
      assert.equal(error.status, status);
      return true;
    });
    assert.equal(calls, 1);
  });
}

for (const response of [
  new Response("not JSON"),
  Response.json({ request: {} }),
  Response.json({ code: "missing message" }, { status: 400 }),
]) {
  test(`rejects malformed response ${response.status} with one error type`, async (t) => {
    t.mock.method(globalThis, "fetch", async () => response);
    const ng = new Nullgate("fake");
    await assert.rejects(
      response.ok
        ? ng
            .session({ userAgent: "browser" })
            .page("https://shop.example", '<script src="/sensor"></script>')
            .sensor({ script: "source", cookies: {} })
        : ng.account(),
      { code: "protocol_error" },
    );
  });
}

test("maps transport failures without exposing credentials or causes", async (t) => {
  t.mock.method(globalThis, "fetch", async () => {
    throw new TypeError("secret key and proxy");
  });
  await assert.rejects(new Nullgate("fake").account(), {
    name: "NullgateError",
    code: "transport_error",
    message: "API connection failed",
  });
});
