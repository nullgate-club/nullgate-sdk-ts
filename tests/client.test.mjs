import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { inspect } from "node:util";
import { Nullgate, NullgateError } from "@nullgate/sdk";

const wire = JSON.parse(
  readFileSync(new URL("./fixtures/wire.json", import.meta.url), "utf8"),
);

const profile = "00000000-0000-0000-0000-00000000004a";
const url = "https://shop.example/login";
const html =
  '<form id="login"><input id="email"></form><script src="/sensor"></script><script>bazadebezolkohpepadr="123"</script><script src="/akam/13/abc"></script><script src="/sbsd?v=00000000-0000-0000-0000-00000000004a"></script>';
// Expected wire fields come from the exported Akamai and Amazon OpenAPI examples.
for (const operation of ["sensor", "pixel", "sbsd", "fwcim"]) {
  test(`${operation} sends flat wire fields and returns the exact target payload`, async (t) => {
    t.mock.timers.enable({ apis: ["Date"], now: 1800000001000 });
    const service = operation === "fwcim" ? "amazon" : "akamai";
    const schemaName =
      operation === "fwcim"
        ? "FwcimRequest"
        : `${operation[0]?.toUpperCase()}${operation.slice(1)}Request`;
    const schema = wire[service].components.schemas[schemaName];
    const responseExample =
      operation === "fwcim"
        ? wire.amazon.components.schemas.Generated.examples[0]
        : wire.akamai.paths[`/akamai/${operation}`].post.responses["200"]
            .content["application/json"].example;
    /** @type {Record<string, unknown>[]} */
    const seen = [];
    t.mock.method(
      globalThis,
      "fetch",
      async (
        /** @type {RequestInfo | URL} */ input,
        /** @type {RequestInit | undefined} */ init,
      ) => {
        const body = JSON.parse(String(init?.body));
        seen.push(body);
        assert.ok(
          Object.keys(body).every((key) =>
            Object.hasOwn(schema.properties, key),
          ),
        );
        assert.ok(
          schema.required.every((/** @type {string} */ key) =>
            Object.hasOwn(body, key),
          ),
        );
        assert.equal(
          String(input),
          `https://api.nullgate.club/${operation === "fwcim" ? "amazon" : "akamai"}/${operation}`,
        );
        assert.equal(
          new Headers(init?.headers).get("authorization"),
          "Bearer fake-key",
        );
        assert.equal(new Headers(init?.headers).has("x-state-id"), false);
        return Response.json(responseExample);
      },
    );
    const page = new Nullgate("fake-key")
      .session({ userAgent: "browser", profile })
      .page(url, html);
    const result =
      operation === "sensor"
        ? await page.sensor({
            script: "source",
            cookies: { _abck: "observed", bm_sz: "size", private: "omit" },
          })
        : operation === "pixel"
          ? await page.pixel({ script: "source" })
          : operation === "sbsd"
            ? await page.sbsd({
                script: "source",
                cookies: new Map([
                  ["sbsd", "observed"],
                  ["private", "omit"],
                ]),
              })
            : await page.fwcim({
                form: "#login",
                timing: { navigationStart: 1800000000000 },
                inputs: {},
                cookies: {},
              });
    const actual = { ...seen[0] };
    assert.match(String(actual.document_id), /^[0-9a-f-]{36}$/);
    assert.equal(typeof actual.started_at_ms, "number");
    if (operation === "fwcim")
      assert.equal(actual.started_at_ms, 1800000000000);
    delete actual.document_id;
    delete actual.started_at_ms;
    const common = { profile, session: null, user_agent: "browser", url, html };
    const expected =
      operation === "sensor"
        ? {
            script_url: "https://shop.example/sensor",
            script: "source",
            cookies: { _abck: "observed", bm_sz: "size" },
            inputs: [],
            actions: [],
          }
        : operation === "pixel"
          ? {
              script_url: "https://shop.example/akam/13/abc",
              script: "source",
              challenge: "123",
            }
          : operation === "sbsd"
            ? {
                script_url:
                  "https://shop.example/sbsd?v=00000000-0000-0000-0000-00000000004a",
                script: "source",
                cookies: { sbsd: "observed" },
              }
            : {
                form_selector: "#login",
                performance_timing: { navigationStart: 1800000000000 },
                inputs: [],
                actions: [],
                cookies: {},
              };
    assert.deepEqual(actual, { ...common, ...expected });
    assert.equal(result.requestId, "request-id");
    await result.wait();
    if ("body" in result) {
      assert.equal(result.body, responseExample.request.body);
      assert.equal(result.url, responseExample.request.url);
      assert.equal(result.headers.referer, url);
      assert.equal(result.headers.origin, "https://shop.example");
      assert.ok(!inspect(result).includes(responseExample.request.body));
    } else {
      assert.equal(result.metadata1, responseExample.metadata1);
      assert.ok(!inspect(result).includes(responseExample.metadata1));
    }
  });
}

test("continuation is shared by Akamai operations and isolated from Amazon", async (t) => {
  /** @type {(string | null)[]} */ const sessions = [];
  t.mock.method(
    globalThis,
    "fetch",
    async (
      /** @type {RequestInfo | URL} */ input,
      /** @type {RequestInit | undefined} */ init,
    ) => {
      sessions.push(JSON.parse(String(init?.body)).session);
      return Response.json({
        ...(String(input).includes("amazon")
          ? { metadata1: "metadata", headers: {}, send_at: 0 }
          : { request: { url, body: "body", headers: {}, send_at: 0 } }),
        session: `session-${sessions.length}`,
        request_id: "id",
      });
    },
  );
  const page = new Nullgate("fake")
    .session({ userAgent: "browser" })
    .page(url, html);
  await Promise.all([
    page.sensor({ script: "source", cookies: {} }),
    page.sbsd({ script: "source", cookies: {} }),
  ]);
  await page.fwcim({
    form: "#login",
    timing: { navigationStart: 1 },
    inputs: {},
  });
  await page.sensor({ script: "source", cookies: {} });
  assert.deepEqual(sessions, [null, "session-1", null, "session-2"]);
});

test("account and usage use the canonical authenticated GET routes", async (t) => {
  /** @type {string[]} */ const urls = [];
  t.mock.method(
    globalThis,
    "fetch",
    async (
      /** @type {RequestInfo | URL} */ input,
      /** @type {RequestInit | undefined} */ init,
    ) => {
      urls.push(String(input));
      assert.equal(init?.method, "GET");
      assert.equal(init?.body, undefined);
      return Response.json(
        String(input).includes("/usage")
          ? wire.accounts.components.schemas.UsageResponse.examples[0]
          : wire.accounts.components.schemas.Profile.examples[0],
      );
    },
  );
  const ng = new Nullgate("fake");
  const { created_at, prices_per_1000, ...accountFields } =
    wire.accounts.components.schemas.Profile.examples[0];
  assert.deepEqual(await ng.account(), {
    ...accountFields,
    createdAt: created_at,
    pricesPer1000: prices_per_1000,
  });
  assert.deepEqual(
    (
      await ng.usage({
        interval: "day",
        start: "2026-11-01T00:00:00Z",
        end: "2026-11-02T00:00:00Z",
      })
    ).buckets,
    [],
  );
  assert.deepEqual(urls, [
    "https://api.nullgate.club/account",
    "https://api.nullgate.club/account/usage?interval=day&start=2026-11-01T00%3A00%3A00Z&end=2026-11-02T00%3A00%3A00Z",
  ]);
});

test("missing credentials and invalid configuration use the one error type", () => {
  assert.throws(() => new Nullgate(""), {
    name: "NullgateError",
    code: "invalid_key",
  });
  assert.throws(() => new Nullgate("fake", { timeout: 0 }), NullgateError);
  assert.throws(
    () => new Nullgate("fake").session({ userAgent: "" }),
    NullgateError,
  );
});
