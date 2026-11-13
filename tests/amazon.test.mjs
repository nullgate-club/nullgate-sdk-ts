import assert from "node:assert/strict";
import test from "node:test";
import { gunzipSync } from "node:zlib";
import {
  acicWafVerificationBody,
  Nullgate,
  prepareInputs,
} from "@nullgate/sdk";

const html =
  '<form id="signin"><input id="ap_email"><input name="nickname"><input id="password" type="password"></form><input id="outside">';
for (const inputs of [
  { ap_email: "abc" },
  { nickname: "abc" },
  [
    {
      id: "ap_email",
      value: "abc",
      geometry: { width: 10, height: 20 },
      text: "abc",
    },
  ],
]) {
  test(`Amazon summarizes actual controls and preserves observed geometry: ${JSON.stringify(inputs)}`, async (t) => {
    t.mock.method(
      globalThis,
      "fetch",
      async (
        /** @type {RequestInfo | URL} */ _url,
        /** @type {RequestInit | undefined} */ init,
      ) => {
        const body = JSON.parse(String(init?.body));
        assert.equal(body.inputs[0].checksum, 891568578);
        assert.equal(body.inputs[0].value.hash31, 96354);
        assert.equal(body.inputs[0].value.length, 3);
        assert.deepEqual(body.cookies, {
          "session-id": "session",
          "session-token": "token",
          "ubid-main": "ubid",
        });
        assert.equal(body.inputs[0].attributes.value, undefined);
        assert.deepEqual(body.actions, [{ type: "click", x: 1, y: 2 }]);
        if (Array.isArray(inputs)) {
          assert.deepEqual(body.inputs[0].geometry, { width: 10, height: 20 });
          assert.equal(body.inputs[0].text, "abc");
        }
        return Response.json({
          metadata1: "metadata",
          headers: {},
          send_at: 0,
          session: "next",
          request_id: "id",
        });
      },
    );
    const page = new Nullgate("fake")
      .session({ userAgent: "browser" })
      .page("https://shop.example", html);
    const result = await page.fwcim({
      form: "#signin",
      timing: { navigationStart: 1 },
      inputs,
      actions: [{ type: "click", x: 1, y: 2 }],
      cookies: {
        "session-id": "session",
        "session-token": "token",
        "ubid-main": "ubid",
        secret: "omit",
      },
    });
    assert.equal(result.metadata1, "metadata");
  });
}
for (const inputs of [
  [{ id: "outside", value: "abc" }],
  [{ id: "missing", value: "abc" }],
  [{ id: "ap_email", value: "abc", text: "different" }],
  [{ id: "password", value: "private" }],
  [{ id: "ap_email", value: "abc", geometry: { width: -1, height: 20 } }],
]) {
  test(`refuses invalid Amazon observations before sending: ${JSON.stringify(inputs)}`, async (t) => {
    let sent = false;
    t.mock.method(globalThis, "fetch", async () => {
      sent = true;
      throw new Error("must not send");
    });
    const page = new Nullgate("fake")
      .session({ userAgent: "browser" })
      .page("https://shop.example", html);
    await assert.rejects(
      page.fwcim({ form: "#signin", timing: { navigationStart: 1 }, inputs }),
      { code: "invalid_inputs" },
    );
    assert.equal(sent, false);
  });
}

for (const additions of [
  {},
  {
    checksum: 0,
    text: "",
    geometry: { width: 0, height: 0, left: -1, top: -2 },
  },
  { checksum: 2 ** 32 - 1, text: "observed" },
  { checksum: null, text: null, geometry: null },
]) {
  test(`Amazon preserves prepared nonpassword facts ${JSON.stringify(additions)}`, async () => {
    const [summary] = prepareInputs([{ id: "ap_email", value: "observed" }]);
    assert.ok(summary);
    const input = { ...summary, ...additions };
    const client = new Nullgate("fake", {
      fetch: async (_url, init) => {
        assert.deepEqual(JSON.parse(String(init?.body)).inputs, [input]);
        return Response.json({
          metadata1: "opaque",
          headers: {},
          send_at: 0,
          session: "next",
          request_id: "id",
        });
      },
    });
    await client
      .session({ userAgent: "browser" })
      .page("https://shop.example", html)
      .fwcim({
        form: "#signin",
        timing: { navigationStart: 1 },
        inputs: [input],
      });
  });
}
for (const [
  id,
  additions,
] of /** @type {[string, Record<string, unknown>][]} */ ([
  ["password", { checksum: 0 }],
  ["password", { checksum: null }],
  ["password", { text: "" }],
  ["password", { text: null }],
  ["outside", {}],
  ["missing", {}],
  ["ap_email", { checksum: -1 }],
  ["ap_email", { checksum: 2 ** 32 }],
  ["ap_email", { checksum: 1.5 }],
  ["ap_email", { geometry: { width: -1, height: 2 } }],
  ["ap_email", { geometry: { width: 1, height: Infinity } }],
  ["ap_email", { attributes: { id: "ap_email", type: "text" } }],
  ["ap_email", { extra: "unsupported" }],
])) {
  test(`Amazon rejects invalid prepared facts ${id} ${JSON.stringify(additions)}`, async () => {
    const [summary] = prepareInputs([{ id, value: "observed" }]);
    assert.ok(summary);
    const page = new Nullgate("fake", {
      fetch: async () => assert.fail("must not send"),
    })
      .session({ userAgent: "browser" })
      .page("https://shop.example", html);
    await assert.rejects(
      page.fwcim({
        form: "#signin",
        timing: { navigationStart: 1 },
        inputs: /** @type {any} */ ([{ ...summary, ...additions }]),
      }),
      { code: "invalid_inputs" },
    );
  });
}

for (const { options, expected } of [
  { options: {}, expected: { submitted: true, referrer: "" } },
  {
    options: { form: null, historyLength: null },
    expected: { submitted: true, referrer: "" },
  },
  {
    options: {
      form: "#signin",
      submitted: false,
      referrer: "https://shop.example/previous",
      historyLength: 1,
    },
    expected: {
      form_selector: "#signin",
      submitted: false,
      referrer: "https://shop.example/previous",
      history_length: 1,
    },
  },
]) {
  test(`Amazon preserves optional form/context facts ${JSON.stringify(options)}`, async () => {
    const client = new Nullgate("fake", {
      fetch: async (_url, init) => {
        const body = JSON.parse(String(init?.body));
        assert.deepEqual(
          Object.fromEntries(
            Object.entries(body).filter(([key]) =>
              [
                "form_selector",
                "submitted",
                "referrer",
                "history_length",
              ].includes(key),
            ),
          ),
          expected,
        );
        return Response.json({
          metadata1: "opaque",
          headers: {},
          send_at: 0,
          session: "next",
          request_id: "id",
        });
      },
    });
    await client
      .session({ userAgent: "browser" })
      .page("https://shop.example", html)
      .fwcim({ timing: { navigationStart: 1 }, ...options });
  });
}
for (const options of [
  { submitted: null },
  { submitted: 0 },
  { referrer: null },
  { referrer: 1 },
  { historyLength: 0 },
  { historyLength: 1.5 },
  { form: "" },
  { form: "#missing" },
]) {
  test(`Amazon rejects invalid form/context facts ${JSON.stringify(options)}`, async () => {
    const page = new Nullgate("fake", {
      fetch: async () => assert.fail("must not send"),
    })
      .session({ userAgent: "browser" })
      .page("https://shop.example", html);
    await assert.rejects(
      page.fwcim(
        /** @type {any} */ ({ timing: { navigationStart: 1 }, ...options }),
      ),
      { code: "invalid_inputs" },
    );
  });
}
for (const { options, navigationStart, accepted } of [
  { options: {}, navigationStart: 1000, accepted: true },
  { options: { startedAtMs: 1000 }, navigationStart: 1000, accepted: true },
  { options: { startedAtMs: 1000 }, navigationStart: 1001, accepted: false },
]) {
  test(`Amazon respects an explicit page start ${JSON.stringify(options)} ${navigationStart}`, async () => {
    const client = new Nullgate("fake", {
      fetch: async (_url, init) => {
        assert.equal(
          accepted,
          true,
          "mismatched clocks must not reach the API",
        );
        assert.equal(
          JSON.parse(String(init?.body)).started_at_ms,
          navigationStart,
        );
        return Response.json({
          metadata1: "opaque",
          headers: {},
          send_at: 0,
          session: "next",
          request_id: "id",
        });
      },
    });
    const page = client
      .session({ userAgent: "browser" })
      .page("https://shop.example", html, options);
    const pending = page.fwcim({ timing: { navigationStart } });
    if (accepted) assert.equal((await pending).metadata1, "opaque");
    else await assert.rejects(pending, { code: "invalid_inputs" });
  });
}

test("ACIC sends compressed PoW and WAF bodies and returns solutions", async () => {
  const problem = {
    state: "state",
    key: "key",
    hmac_tag: "tag",
    assets: { images: "x".repeat(2048) },
  };
  /** @type {{url: string, body: unknown}[]} */
  const calls = [];
  const client = new Nullgate("fake", {
    baseUrl: "http://localhost:8080",
    fetch: async (url, init) => {
      assert.equal(init?.method, "POST");
      const headers = new Headers(init?.headers);
      assert.equal(headers.get("authorization"), "Bearer fake");
      assert.equal(headers.get("content-type"), "application/json");
      assert.equal(headers.get("content-encoding"), "gzip");
      const body = JSON.parse(
        gunzipSync(/** @type {Uint8Array} */ (init?.body)).toString(),
      );
      calls.push({ url: String(url), body });
      return Response.json(
        String(url).endsWith("/pow")
          ? { response: '{"proof":1}', request_id: "one" }
          : { client_solution: [0, 2, 3, 6, 8], request_id: "two" },
      );
    },
  });
  assert.deepEqual(
    await client.acicPow({ challengeType: "POW", html: "h".repeat(2048) }),
    { response: '{"proof":1}' },
  );
  const solution = await client.acicWaf({ problem });
  assert.deepEqual(solution, { clientSolution: [0, 2, 3, 6, 8] });
  assert.deepEqual(calls, [
    {
      url: "http://localhost:8080/amazon/acic/pow",
      body: { challenge_type: "POW", html: "h".repeat(2048) },
    },
    { url: "http://localhost:8080/amazon/acic/waf", body: { problem } },
  ]);
  assert.deepEqual(
    acicWafVerificationBody({
      problem,
      solution: solution.clientSolution,
      elapsedMs: 1234.8,
      locale: "en-US",
    }),
    {
      state: "state",
      key: "key",
      hmac_tag: "tag",
      client_solution: [0, 2, 3, 6, 8],
      metrics: { solve_time_millis: 1234 },
      locale: "en-US",
    },
  );
});

test("ACIC PoW uses a 90 second default timeout and accepts an override", async (t) => {
  /** @type {number[]} */
  const timeouts = [];
  const original = AbortSignal.timeout;
  t.mock.method(AbortSignal, "timeout", (/** @type {number} */ ms) => {
    timeouts.push(ms);
    return original(ms);
  });
  const client = new Nullgate("fake", {
    timeout: 5,
    fetch: async () => Response.json({ response: "proof" }),
  });
  await client.acicPow({ challengeType: "POW", html: "html" });
  await client.acicPow({
    challengeType: "POW",
    html: "html",
    timeoutMs: 120000,
  });
  assert.deepEqual(timeouts, [90000, 120000]);
});

for (const [status, code] of /** @type {const} */ ([
  [501, "unsupported"],
  [503, "maintenance"],
  [415, "invalid_request"],
])) {
  test(`ACIC maps ${code} without retrying a charged POST`, async () => {
    let count = 0;
    const client = new Nullgate("fake", {
      fetch: async () => {
        count++;
        return Response.json(
          { code, message: "failure", request_id: "req" },
          { status, headers: { "Retry-After": "0" } },
        );
      },
    });
    await assert.rejects(
      client.acicPow({ challengeType: "POW", html: "h".repeat(2048) }),
      { code, status, requestId: "req" },
    );
    await assert.rejects(client.acicWaf({ problem: {} }), {
      code,
      status,
      requestId: "req",
    });
    assert.equal(count, 2);
  });
}
