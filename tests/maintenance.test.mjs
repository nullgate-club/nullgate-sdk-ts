import assert from "node:assert/strict";
import test from "node:test";
import { Nullgate } from "@nullgate/sdk";

for (const retryAfter of ["0", "Wed, 01 Jan 2020 00:00:00 GMT"]) {
  test(`maintenance retries at most twice with ${retryAfter}`, async (t) => {
    let calls = 0;
    t.mock.method(globalThis, "fetch", async () => {
      calls++;
      return Response.json(
        { code: "maintenance", message: "Updating", request_id: "id" },
        { status: 503, headers: { "Retry-After": retryAfter } },
      );
    });
    await assert.rejects(new Nullgate("fake").account(), {
      code: "maintenance",
      status: 503,
    });
    assert.equal(calls, 3);
  });
}
for (const retryAfter of ["invalid", "-1", ""]) {
  test(`invalid Retry-After ${JSON.stringify(retryAfter)} does not retry`, async (t) => {
    let calls = 0;
    t.mock.method(globalThis, "fetch", async () => {
      calls++;
      return Response.json(
        { code: "maintenance", message: "Updating", request_id: "id" },
        { status: 503, headers: { "Retry-After": retryAfter } },
      );
    });
    await assert.rejects(new Nullgate("fake").account(), {
      code: "maintenance",
    });
    assert.equal(calls, 1);
  });
}

test("maintenance waiting respects the total operation timeout", async (t) => {
  let calls = 0;
  t.mock.method(globalThis, "fetch", async () => {
    calls++;
    return Response.json(
      { code: "maintenance", message: "Updating", request_id: "id" },
      { status: 503, headers: { "Retry-After": "10" } },
    );
  });
  await assert.rejects(new Nullgate("fake", { timeout: 0.01 }).account(), {
    code: "timeout",
  });
  assert.equal(calls, 1);
});

test("maintenance success preserves the original wire body", async (t) => {
  /** @type {string[]} */ const bodies = [];
  t.mock.method(
    globalThis,
    "fetch",
    async (
      /** @type {RequestInfo | URL} */ _input,
      /** @type {RequestInit | undefined} */ init,
    ) => {
      bodies.push(String(init?.body));
      return bodies.length === 1
        ? Response.json(
            { code: "maintenance", message: "Updating", request_id: "id" },
            { status: 503, headers: { "Retry-After": "0" } },
          )
        : Response.json({
            request: {
              url: "https://shop.example/sensor",
              body: "generated",
              headers: {},
              send_at: 0,
            },
            session: "next",
            request_id: "id",
          });
    },
  );
  const result = await new Nullgate("fake")
    .session({ userAgent: "browser" })
    .page("https://shop.example", '<script src="/sensor"></script>')
    .sensor({ script: "source", cookies: {} });
  assert.equal(result.body, "generated");
  assert.equal(bodies.length, 2);
  assert.equal(bodies[0], bodies[1]);
});
