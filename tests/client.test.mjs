import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { inspect } from "node:util";
import { gunzipSync } from "node:zlib";
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
                  ["bm_so", "observed"],
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
                cookies: { bm_so: "observed" },
              }
            : {
                form_selector: "#login",
                performance_timing: { navigationStart: 1800000000000 },
                referrer: "",
                submitted: true,
                inputs: [],
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

for (const operation of ["sensor", "fwcim"]) {
  for (const hasLowercase of [false, true]) {
    test(`${operation} preserves server header casing and order, lowercase overrides: ${hasLowercase}`, async (t) => {
      /** @type {[string, string][]} */
      const serverEntries = [
        ["Z-Trace", "first"],
        ["Accept-Language", "en-US,en;q=0.9"],
        ["Origin", "server-cased-origin"],
        ...(hasLowercase
          ? /** @type {[string, string][]} */ ([
              ["origin", "server-lowercase-origin"],
            ])
          : []),
        ["Referer", "server-cased-referer"],
        ...(hasLowercase
          ? /** @type {[string, string][]} */ ([
              ["referer", "server-lowercase-referer"],
            ])
          : []),
        ["A-Trace", "last"],
      ];
      t.mock.method(globalThis, "fetch", async () =>
        Response.json({
          ...(operation === "fwcim"
            ? {
                metadata1: "metadata",
                headers: Object.fromEntries(serverEntries),
                send_at: 0,
              }
            : {
                request: {
                  url: "https://shop.example/sensor",
                  body: "payload",
                  headers: Object.fromEntries(serverEntries),
                  send_at: 0,
                },
              }),
          session: "next",
          request_id: "id",
        }),
      );
      const page = new Nullgate("fake")
        .session({ userAgent: "browser" })
        .page(url, html);
      const result =
        operation === "fwcim"
          ? await page.fwcim({
              form: "#login",
              timing: { navigationStart: 1 },
              inputs: {},
            })
          : await page.sensor({ script: "source", cookies: {} });
      const expected =
        operation === "fwcim"
          ? serverEntries
          : hasLowercase
            ? [
                ["Z-Trace", "first"],
                ["Accept-Language", "en-US,en;q=0.9"],
                ["Origin", "server-cased-origin"],
                ["origin", "https://shop.example"],
                ["Referer", "server-cased-referer"],
                ["referer", url],
                ["A-Trace", "last"],
              ]
            : [
                ...serverEntries,
                ["origin", "https://shop.example"],
                ["referer", url],
              ];
      assert.deepEqual(Object.entries(result.headers), expected);
    });
  }
}

// Dropping an observed product cookie changes generation; unrelated cookies must stay local.
for (const [operation, expected] of Object.entries({
  sensor: { _abck: "abck", bm_sz: "size" },
  sbsd: { bm_so: "so", sbsd_o: "observed", bm_s: "s" },
  fwcim: {
    "session-id": "visit",
    "session-token": "token",
    "ubid-main": "browser",
  },
})) {
  test(`${operation} forwards exactly its server-consumed v1 cookie set`, async (t) => {
    const allCookies = {
      _abck: "abck",
      bm_sz: "size",
      bm_so: "so",
      sbsd_o: "observed",
      bm_s: "s",
      sbsd: "obsolete",
      "session-id": "visit",
      "session-token": "token",
      "ubid-main": "browser",
      customer_auth: "private",
    };
    t.mock.method(
      globalThis,
      "fetch",
      async (
        /** @type {RequestInfo | URL} */ _input,
        /** @type {RequestInit | undefined} */ init,
      ) => {
        assert.deepEqual(JSON.parse(String(init?.body)).cookies, expected);
        return Response.json(
          operation === "fwcim"
            ? wire.amazon.components.schemas.Generated.examples[0]
            : wire.akamai.paths[`/akamai/${operation}`].post.responses["200"]
                .content["application/json"].example,
        );
      },
    );
    const document = new Nullgate("fake")
      .session({ userAgent: "browser" })
      .page(url, html);
    const cookies = new Map(Object.entries(allCookies));
    if (operation === "fwcim")
      await document.fwcim({
        form: "#login",
        timing: { navigationStart: 1000 },
        inputs: [],
        cookies,
      });
    else if (operation === "sensor")
      await document.sensor({ script: "source", cookies });
    else await document.sbsd({ script: "source", cookies });
  });
}

test("injected fetch receives every API operation and maintenance attempt", async () => {
  /** @type {string[]} */ const paths = [];
  const client = new Nullgate("fake", {
    fetch: async (url) => {
      const path = new URL(String(url)).pathname;
      paths.push(path);
      if (
        path === "/akamai/sensor" &&
        paths.filter((value) => value === path).length === 1
      )
        return Response.json(
          { code: "maintenance", message: "Try later", request_id: "id" },
          { status: 503, headers: { "Retry-After": "0" } },
        );
      if (path.startsWith("/account"))
        return Response.json({
          created_at: "2026-01-01T00:00:00Z",
          prices_per_1000: {},
        });
      return Response.json(
        path === "/amazon/fwcim"
          ? wire.amazon.components.schemas.Generated.examples[0]
          : wire.akamai.paths[path].post.responses["200"].content[
              "application/json"
            ].example,
      );
    },
  });
  await client.account();
  await client.usage();
  const page = client.session({ userAgent: "browser" }).page(url, html);
  await page.sensor({ script: "source", cookies: {} });
  await page.pixel({ script: "source" });
  await page.sbsd({ script: "source", cookies: {} });
  await page.fwcim({
    form: "#login",
    timing: { navigationStart: 1 },
    inputs: [],
  });
  assert.deepEqual(paths, [
    "/account",
    "/account/usage",
    "/akamai/sensor",
    "/akamai/sensor",
    "/akamai/pixel",
    "/akamai/sbsd",
    "/amazon/fwcim",
  ]);
});
for (const failure of ["http", "transport"]) {
  test(`injected fetch ${failure} failure uses the public error`, async () => {
    const client = new Nullgate("fake", {
      fetch: async () => {
        if (failure === "transport")
          throw new Error("private transport details");
        return Response.json(
          {
            code: "invalid_request",
            message: "Invalid request",
            request_id: "failed",
          },
          { status: 400 },
        );
      },
    });
    await assert.rejects(client.account(), {
      name: "NullgateError",
      code: failure === "http" ? "invalid_request" : "transport_error",
      status: failure === "http" ? 400 : null,
      requestId: failure === "http" ? "failed" : null,
    });
  });
}

for (const operation of ["sensor", "fwcim"]) {
  for (const { observations, expected } of [
    { observations: {}, expected: {} },
    { observations: { inputs: null, actions: null }, expected: {} },
    {
      observations: { inputs: [], actions: [] },
      expected: { inputs: [], actions: [] },
    },
    { observations: { inputs: [], actions: null }, expected: { inputs: [] } },
    { observations: { inputs: null, actions: [] }, expected: { actions: [] } },
  ]) {
    test(`${operation} preserves observation omission ${JSON.stringify(observations)}`, async () => {
      const client = new Nullgate("fake", {
        fetch: async (_url, init) => {
          const body = JSON.parse(String(init?.body));
          assert.deepEqual(
            Object.fromEntries(
              Object.entries(body).filter(([key]) =>
                ["inputs", "actions"].includes(key),
              ),
            ),
            expected,
          );
          return Response.json(
            operation === "fwcim"
              ? wire.amazon.components.schemas.Generated.examples[0]
              : wire.akamai.paths["/akamai/sensor"].post.responses["200"]
                  .content["application/json"].example,
          );
        },
      });
      const page = client.session({ userAgent: "browser" }).page(url, html);
      if (operation === "sensor")
        await page.sensor({ script: "source", cookies: {}, ...observations });
      else
        await page.fwcim({ timing: { navigationStart: 1 }, ...observations });
    });
  }
}

for (const options of [
  {},
  { documentId: "00000000-0000-0000-0000-00000000004a" },
  { startedAtMs: 0 },
  {
    documentId: "urn:uuid:00000000-0000-0000-0000-00000000004A",
    startedAtMs: 1000,
  },
  { documentId: null, startedAtMs: null },
]) {
  test(`page identity preserves caller facts and stable defaults ${JSON.stringify(options)}`, async (t) => {
    t.mock.timers.enable({ apis: ["Date"], now: 2000 });
    /** @type {Record<string, any>[]} */ const bodies = [];
    const client = new Nullgate("fake", {
      fetch: async (_url, init) => {
        bodies.push(JSON.parse(String(init?.body)));
        return Response.json(
          wire.akamai.paths["/akamai/sensor"].post.responses["200"].content[
            "application/json"
          ].example,
        );
      },
    });
    const page = client
      .session({ userAgent: "browser" })
      .page(url, html, options);
    await page.sensor({ script: "source", cookies: {} });
    await page.sensor({ script: "source", cookies: {} });
    assert.equal(bodies[0]?.started_at_ms, options.startedAtMs ?? 2000);
    assert.match(
      bodies[0]?.document_id,
      /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/,
    );
    if (options.documentId != null)
      assert.equal(
        bodies[0]?.document_id,
        "00000000-0000-0000-0000-00000000004a",
      );
    assert.equal(bodies[1]?.document_id, bodies[0]?.document_id);
    assert.equal(bodies[1]?.started_at_ms, bodies[0]?.started_at_ms);
  });
}
for (const options of [
  { documentId: "invalid" },
  { startedAtMs: -1 },
  { startedAtMs: 1.5 },
  { startedAtMs: true },
]) {
  test(`invalid caller page identity fails locally ${JSON.stringify(options)}`, () => {
    assert.throws(
      () =>
        new Nullgate("fake")
          .session({ userAgent: "browser" })
          .page(url, html, /** @type {any} */ (options)),
      { code: "invalid_page" },
    );
  });
}

for (const { markup, options, expectedUrl, expectedChallenge } of [
  {
    markup: '<script src="/akam/13/abc"></script>',
    options: { challenge: "00123" },
    expectedUrl: "https://shop.example/akam/13/abc",
    expectedChallenge: "00123",
  },
  {
    markup:
      '<script>bazadebezolkohpepadr="1";bazadebezolkohpepadr="2"</script><script src="/akam/13/abc"></script>',
    options: { challenge: "٣" },
    expectedUrl: "https://shop.example/akam/13/abc",
    expectedChallenge: "٣",
  },
  {
    markup: "",
    options: { challenge: "0", scriptUrl: "/observed.js?opaque=%2f" },
    expectedUrl: "https://shop.example/observed.js?opaque=%2f",
    expectedChallenge: "0",
  },
  {
    markup: html,
    options: { challenge: null },
    expectedUrl: "https://shop.example/akam/13/abc",
    expectedChallenge: "123",
  },
]) {
  test(`pixel sends the observed explicit or discovered challenge ${JSON.stringify(options)}`, async () => {
    const client = new Nullgate("fake", {
      fetch: async (_url, init) => {
        const body = JSON.parse(String(init?.body));
        assert.equal(body.challenge, expectedChallenge);
        assert.equal(body.script_url, expectedUrl);
        assert.equal(Object.hasOwn(body, "challenge_offset"), false);
        return Response.json(
          wire.akamai.paths["/akamai/pixel"].post.responses["200"].content[
            "application/json"
          ].example,
        );
      },
    });
    await client
      .session({ userAgent: "browser" })
      .page(url, markup)
      .pixel({ script: "source", ...options });
  });
}
for (const challenge of ["", "-1", "1.5", 1]) {
  test(`pixel rejects a nondecimal explicit challenge ${JSON.stringify(challenge)}`, async () => {
    const page = new Nullgate("fake", {
      fetch: async () => assert.fail("must not send"),
    })
      .session({ userAgent: "browser" })
      .page(url, html);
    await assert.rejects(
      page.pixel({
        script: "source",
        challenge: /** @type {any} */ (challenge),
      }),
      { code: "invalid_request" },
    );
  });
}
test("explicit pixel challenge still requires a unique script URL", async () => {
  const page = new Nullgate("fake", {
    fetch: async () => assert.fail("must not send"),
  })
    .session({ userAgent: "browser" })
    .page(
      url,
      '<script src="/akam/13/abc"></script><script src="/akam/13/def"></script>',
    );
  await assert.rejects(page.pixel({ script: "source", challenge: "1" }), {
    code: "ambiguous_protection",
  });
});
for (const token of ["", "&t=", "&t=observed%2Btoken"]) {
  test(`SBSD retains URL-derived blocking without inventing a field ${token}`, async () => {
    const scriptUrl = `https://shop.example/probe?v=${profile}${token}`;
    const client = new Nullgate("fake", {
      fetch: async (_url, init) => {
        const body = JSON.parse(String(init?.body));
        assert.equal(body.script_url, scriptUrl);
        assert.equal(Object.hasOwn(body, "blocking"), false);
        return Response.json(
          wire.akamai.paths["/akamai/sbsd"].post.responses["200"].content[
            "application/json"
          ].example,
        );
      },
    });
    await client
      .session({ userAgent: "browser" })
      .page(url, "")
      .sbsd({ script: "source", scriptUrl, cookies: {} });
  });
}

// Missing or stale script acknowledgements must never omit a script the server needs.
const sourceDigest =
  "41cf6794ba4200b839c53531555f0f3998df4cbb01a4d5cb0b94e3ca5e23947d";
const sensorResponse =
  wire.akamai.paths["/akamai/sensor"].post.responses["200"].content[
    "application/json"
  ].example;

test("queued sensor calls replace only the acknowledged script with its digest", async () => {
  /** @type {Record<string, unknown>[]} */ const bodies = [];
  const session = new Nullgate("fake", {
    fetch: async (_url, init) => {
      bodies.push(JSON.parse(String(init?.body)));
      return Response.json({
        ...sensorResponse,
        session: "retained-session",
        script_retained: true,
      });
    },
  }).session({ userAgent: "browser", profile });
  const page = session.page(url, html, {
    documentId: profile,
    startedAtMs: 1000,
  });
  await Promise.all([
    page.sensor({ script: "source", cookies: { _abck: "first" } }),
    page.sensor({ script: "source", cookies: { _abck: "later" } }),
  ]);
  const common = {
    profile,
    user_agent: "browser",
    url,
    html,
    document_id: profile,
    started_at_ms: 1000,
    script_url: "https://shop.example/sensor",
  };
  assert.deepEqual(bodies, [
    { ...common, session: null, script: "source", cookies: { _abck: "first" } },
    {
      ...common,
      session: "retained-session",
      script_digest: sourceDigest,
      cookies: { _abck: "later" },
    },
  ]);
});

for (const retained of [undefined, false, "true"]) {
  test(`sensor sends the full script without a true acknowledgement: ${retained}`, async () => {
    /** @type {Record<string, unknown>[]} */ const bodies = [];
    const page = new Nullgate("fake", {
      fetch: async (_url, init) => {
        bodies.push(JSON.parse(String(init?.body)));
        return Response.json({
          ...sensorResponse,
          ...(bodies.length === 1
            ? { script_retained: true }
            : { script_retained: retained }),
        });
      },
    })
      .session({ userAgent: "browser" })
      .page(url, html);
    for (let i = 0; i < 3; i++)
      await page.sensor({ script: "source", cookies: {} });
    assert.deepEqual(
      bodies.map(({ script, script_digest }) => ({ script, script_digest })),
      [
        { script: "source", script_digest: undefined },
        { script: undefined, script_digest: sourceDigest },
        { script: "source", script_digest: undefined },
      ],
    );
  });
}

for (const reset of [
  "script",
  "page",
  "document",
  "session",
  "other-page",
  "pixel",
  "rotated-session",
]) {
  test(`sensor retention resets after ${reset} changes`, async () => {
    /** @type {Record<string, unknown>[]} */ const bodies = [];
    const session = new Nullgate("fake", {
      fetch: async (_url, init) => {
        bodies.push(JSON.parse(String(init?.body)));
        return Response.json({
          ...sensorResponse,
          session:
            reset === "rotated-session" && bodies.length > 1
              ? "rotated"
              : "stable",
          script_retained: true,
        });
      },
    }).session({ userAgent: "browser" });
    const original = session.page(url, html, { documentId: profile });
    await original.sensor({ script: "source", cookies: {} });
    let page = original;
    if (reset === "page")
      page = session.page(url, html, { documentId: profile });
    if (reset === "document") page = session.page(url, html);
    if (reset === "session")
      page = new Nullgate("fake", {
        fetch: async (_url, init) => {
          bodies.push(JSON.parse(String(init?.body)));
          return Response.json({ ...sensorResponse, script_retained: true });
        },
      })
        .session({ userAgent: "browser" })
        .page(url, html, { documentId: profile });
    if (reset === "other-page")
      await session.page(url, html).sensor({ script: "source", cookies: {} });
    if (reset === "pixel") await original.pixel({ script: "source" });
    if (reset === "rotated-session")
      await original.sbsd({ script: "source", cookies: {} });
    const script = reset === "script" ? "changed" : "source";
    await page.sensor({ script, cookies: {} });
    assert.equal(bodies.at(-1)?.script, script);
    assert.equal(Object.hasOwn(bodies.at(-1) ?? {}, "script_digest"), false);
    if (reset === "script") {
      await page.sensor({ script: "source", cookies: {} });
      assert.equal(bodies.at(-1)?.script, "source");
    }
  });
}

for (const failsAgain of [false, true]) {
  test(`script_required retries the same sensor call once, repeated failure: ${failsAgain}`, async () => {
    /** @type {Record<string, unknown>[]} */ const bodies = [];
    const page = new Nullgate("fake", {
      fetch: async (_url, init) => {
        bodies.push(JSON.parse(String(init?.body)));
        if (bodies.length === 2 || (failsAgain && bodies.length === 3))
          return Response.json(
            {
              code: "script_required",
              message: "Send the script for this document.",
              request_id: "missing-script",
            },
            { status: 428 },
          );
        return Response.json({ ...sensorResponse, script_retained: true });
      },
    })
      .session({ userAgent: "browser" })
      .page(url, html);
    await page.sensor({ script: "source", cookies: {} });
    const pending = page.sensor({
      script: "source",
      cookies: { _abck: "observed" },
      inputs: [],
      actions: [],
    });
    if (failsAgain)
      await assert.rejects(pending, { code: "script_required", status: 428 });
    else await pending;
    assert.equal(bodies.length, 3);
    const omitted = { ...bodies[1] };
    delete omitted.script_digest;
    assert.deepEqual(bodies[2], { ...omitted, script: "source" });
    await page.sensor({ script: "source", cookies: {} });
    assert.equal(bodies[3]?.script, failsAgain ? "source" : undefined);
    assert.equal(
      bodies[3]?.script_digest,
      failsAgain ? undefined : sourceDigest,
    );
  });
}

test("an older server never causes sensor scripts to be omitted", async () => {
  /** @type {Record<string, unknown>[]} */ const bodies = [];
  const page = new Nullgate("fake", {
    fetch: async (_url, init) => {
      bodies.push(JSON.parse(String(init?.body)));
      return Response.json(sensorResponse);
    },
  })
    .session({ userAgent: "browser" })
    .page(url, html);
  await page.sensor({ script: "source", cookies: {} });
  await page.sensor({ script: "source", cookies: {} });
  assert.deepEqual(
    bodies.map(({ script, script_digest }) => ({ script, script_digest })),
    [
      { script: "source", script_digest: undefined },
      { script: "source", script_digest: undefined },
    ],
  );
});

test("the first large request uses gzip with its compressed byte length", async () => {
  /** @type {RequestInit | undefined} */ let sent;
  const client = new Nullgate("fake", {
    fetch: async (_url, init) => {
      sent = init;
      return Response.json(sensorResponse);
    },
  });
  await client
    .session({ userAgent: "browser" })
    .page(url, html)
    .sensor({
      script: "source".repeat(300),
      cookies: {},
    });
  const bytes = /** @type {Buffer} */ (sent?.body);
  assert.equal(new Headers(sent?.headers).get("Content-Encoding"), "gzip");
  assert.equal(
    new Headers(sent?.headers).get("Content-Length"),
    String(bytes.byteLength),
  );
  assert.equal(
    JSON.parse(gunzipSync(bytes).toString()).script,
    "source".repeat(300),
  );
});

for (const size of /** @type {(number | "utf8")[]} */ ([1023, 1024, "utf8"])) {
  test(`gzip threshold uses UTF-8 bytes and preserves exact JSON: ${size}`, async () => {
    const context = {
      profile,
      session: null,
      user_agent: "browser",
      url,
      html: "",
      document_id: profile,
      started_at_ms: 0,
      script_url: "https://shop.example/sensor",
      script: "",
      cookies: {},
    };
    const overhead = Buffer.byteLength(JSON.stringify(context));
    const script =
      size === "utf8" ? "é".repeat(500) : "x".repeat(size - overhead);
    const expected = JSON.stringify({ ...context, script });
    /** @type {RequestInit | undefined} */ let sent;
    const client = new Nullgate("fake", {
      fetch: async (_target, init) => {
        sent = init;
        return Response.json(sensorResponse);
      },
    });
    await client
      .session({ userAgent: "browser", profile })
      .page(url, "", {
        documentId: profile,
        startedAtMs: 0,
      })
      .sensor({ script, scriptUrl: "/sensor", cookies: {} });
    const compressed = size !== 1023;
    assert.equal(
      new Headers(sent?.headers).get("Content-Encoding"),
      compressed ? "gzip" : null,
    );
    assert.equal(
      compressed
        ? gunzipSync(/** @type {Buffer} */ (sent?.body)).toString()
        : sent?.body,
      expected,
    );
    if (typeof size === "number")
      assert.equal(Buffer.byteLength(expected), size);
    else {
      assert.ok(expected.length < 1024);
      assert.ok(Buffer.byteLength(expected) >= 1024);
    }
  });
}

test("reporting and GET remain uncompressed", async () => {
  /** @type {RequestInit[]} */ const seen = [];
  const client = new Nullgate("fake", {
    fetch: async (target, init) => {
      seen.push(init ?? {});
      if (String(target).endsWith("/account"))
        return Response.json(
          { code: "invalid_request", message: "Invalid", request_id: "id" },
          {
            status: 400,
          },
        );
      return Response.json(sensorResponse);
    },
  });
  await assert.rejects(client.account(), { code: "invalid_request" });
  await client
    .session({ userAgent: "browser" })
    .page(url, html)
    .sensor({ script: "source".repeat(300), cookies: {} });
  await client.report("r".repeat(2000));
  await assert.rejects(client.account(), { code: "invalid_request" });
  assert.deepEqual(
    seen.map((request) => new Headers(request.headers).get("Content-Encoding")),
    [null, "gzip", null, null],
  );
  assert.equal(typeof seen[2]?.body, "string");
  assert.equal(seen[3]?.body, undefined);
});

for (const status of [413, 415]) {
  for (const failsAgain of [false, true]) {
    test(`gzip ${status} retries identical JSON uncompressed once, repeated failure: ${failsAgain}`, async () => {
      /** @type {RequestInit[]} */ const seen = [];
      const client = new Nullgate("fake", {
        fetch: async (_target, init) => {
          seen.push(init ?? {});
          if (seen.length === 1)
            return new Response("proxy rejection", { status });
          if (failsAgain && seen.length === 2)
            return Response.json(
              {
                code: "invalid_request",
                message: "Rejected",
                request_id: "id",
              },
              { status },
            );
          return Response.json(sensorResponse);
        },
      });
      const page = client.session({ userAgent: "browser" }).page(url, html);
      const call = page.sensor({ script: "source".repeat(300), cookies: {} });
      if (failsAgain) await assert.rejects(call, { status });
      else await call;
      assert.equal(seen.length, 2);
      assert.equal(
        gunzipSync(/** @type {Buffer} */ (seen[0]?.body)).toString(),
        seen[1]?.body,
      );
      assert.equal(new Headers(seen[1]?.headers).has("Content-Length"), false);
      assert.equal(
        new Headers(seen[1]?.headers).has("Content-Encoding"),
        false,
      );
      await page.sensor({ script: "source".repeat(300), cookies: {} });
      assert.equal(
        new Headers(seen[2]?.headers).get("Content-Encoding"),
        status === 413 ? "gzip" : null,
      );
    });
  }
}

for (const order of ["gzip-first", "script-first", "budget"]) {
  test(`gzip and script recovery share three attempts: ${order}`, async () => {
    /** @type {RequestInit[]} */ const seen = [];
    const client = new Nullgate("fake", {
      fetch: async (_target, init) => {
        seen.push(init ?? {});
        const attempt = seen.length - 1;
        if (attempt === 1 && order === "budget")
          return Response.json(
            { code: "maintenance", message: "Wait", request_id: "id" },
            { status: 503, headers: { "Retry-After": "0" } },
          );
        if (
          (attempt === 1 && order === "gzip-first") ||
          (attempt === 2 && order !== "gzip-first")
        )
          return new Response("proxy rejection", { status: 413 });
        if (
          (attempt === 1 && order === "script-first") ||
          (attempt === 2 && order === "gzip-first") ||
          (attempt === 3 && order === "budget")
        )
          return Response.json(
            {
              code: "script_required",
              message: "Send the script for this document.",
              request_id: "id",
            },
            { status: 428 },
          );
        return Response.json({ ...sensorResponse, script_retained: true });
      },
    });
    const page = client
      .session({ userAgent: "browser" })
      .page(url, html.repeat(10));
    await page.sensor({ script: "source", cookies: {} });
    const call = page.sensor({
      script: "source",
      cookies: {},
      inputs: [],
      actions: [],
    });
    if (order === "budget")
      await assert.rejects(call, { code: "script_required" });
    else await call;
    assert.equal(seen.length, 4);
    const attempts = seen.slice(1).map((request) => ({
      compressed:
        new Headers(request.headers).get("Content-Encoding") === "gzip",
      body: JSON.parse(
        typeof request.body === "string"
          ? request.body
          : gunzipSync(/** @type {Buffer} */ (request.body)).toString(),
      ),
    }));
    assert.deepEqual(
      attempts.map(({ compressed, body }) => [
        compressed,
        body.script ?? "digest",
      ]),
      order === "gzip-first"
        ? [
            [true, "digest"],
            [false, "digest"],
            [false, "source"],
          ]
        : order === "script-first"
          ? [
              [true, "digest"],
              [true, "source"],
              [false, "source"],
            ]
          : [
              [true, "digest"],
              [true, "digest"],
              [false, "digest"],
            ],
    );
    for (const { body } of attempts) {
      assert.deepEqual(body.inputs, []);
      assert.deepEqual(body.actions, []);
    }
  });
}
