import assert from "node:assert/strict";
import test from "node:test";
import { Nullgate, prepareInputs } from "@nullgate/sdk";

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
