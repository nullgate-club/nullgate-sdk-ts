import assert from "node:assert/strict";
import test from "node:test";
import { Nullgate } from "@nullgate/sdk";

const url = "https://shop.example/login";
const html =
  '<form id="login"><input name="email"><input id="named"></form><template><input id="inert"></template>';
function result() {
  return Response.json({
    request: { url, body: "payload", headers: {}, send_at: 0 },
    metadata1: "metadata",
    headers: {},
    send_at: 0,
    session: "next",
    request_id: "id",
  });
}

test("session normalizes Python UUID spellings and defers timezone validation to the API", async (t) => {
  /** @type {typeof fetch} */
  const api = async (_url, init) => {
    const data = JSON.parse(String(init?.body));
    assert.equal(data.profile, "00000000-0000-0000-0000-00000000004a");
    assert.equal(data.timezone, "not-an-IANA-zone");
    return result();
  };
  t.mock.method(globalThis, "fetch", api);
  for (const profile of [
    "0000000000000000000000000000004A",
    "{00000000-0000-0000-0000-00000000004A}",
    "urn:uuid:00000000-0000-0000-0000-00000000004A",
  ]) {
    const page = new Nullgate("fake")
      .session({ userAgent: "browser", profile, timezone: "not-an-IANA-zone" })
      .page(url, html);
    await page.sensor({ script: "", scriptUrl: "/sensor.js", cookies: {} });
  }
  assert.throws(() => new Nullgate("fake").session({ userAgent: "   " }), {
    code: "invalid_request",
  });
});

test("usage sends the Python default interval and omits null range limits", async (t) => {
  /** @type {string[]} */ const urls = [];
  /** @type {typeof fetch} */ const api = async (input) => {
    urls.push(String(input));
    return Response.json({ buckets: [] });
  };
  t.mock.method(globalThis, "fetch", api);
  const ng = new Nullgate("fake");
  await ng.usage();
  await ng.usage({
    interval: "server-validated",
    start: null,
    end: "2026-11-02T00:00:00Z",
  });
  assert.deepEqual(urls, [
    "https://api.nullgate.club/account/usage?interval=hour",
    "https://api.nullgate.club/account/usage?interval=server-validated&end=2026-11-02T00%3A00%3A00Z",
  ]);
});

test("input mappings use id then name but explicit array identities never fall back", async (t) => {
  /** @type {typeof fetch} */ const api = async (_url, init) => {
    const data = JSON.parse(String(init?.body));
    assert.deepEqual(data.inputs[0].attributes, { name: "email" });
    assert.deepEqual(data.cookies, {});
    return result();
  };
  t.mock.method(globalThis, "fetch", api);
  const page = new Nullgate("fake")
    .session({ userAgent: "browser" })
    .page(url, html);
  await page.sensor({
    script: "source",
    scriptUrl: "/sensor",
    cookies: /** @type {any} */ ({ _abck: 123 }),
    inputs: { email: "abc" },
  });
  await assert.rejects(
    page.sensor({
      script: "source",
      scriptUrl: "/sensor",
      cookies: {},
      inputs: [{ id: "email", value: "abc" }],
    }),
    { code: "invalid_inputs" },
  );
  await assert.rejects(
    page.sensor({
      script: "source",
      scriptUrl: "/sensor",
      cookies: {},
      inputs: [{ value: "abc" }],
    }),
    { code: "invalid_inputs" },
  );
  await assert.rejects(
    page.sensor({
      script: "source",
      scriptUrl: "/sensor",
      cookies: {},
      inputs: { inert: "abc" },
    }),
    { code: "invalid_inputs" },
  );
});

test("Amazon sends Python defaults and accepts nullable form, inputs, geometry and typeless actions", async (t) => {
  /** @type {typeof fetch} */ const api = async (_url, init) => {
    const data = JSON.parse(String(init?.body));
    assert.equal(data.submitted, true);
    assert.equal(data.referrer, "");
    assert.equal(data.form_selector, undefined);
    assert.equal(data.inputs[0].geometry, null);
    assert.deepEqual(data.actions, [{}]);
    return result();
  };
  t.mock.method(globalThis, "fetch", api);
  const page = new Nullgate("fake")
    .session({ userAgent: "browser" })
    .page(url, html);
  await page.fwcim({
    form: null,
    timing: { navigationStart: 100, fetchStart: 100 },
    inputs: [{ name: "email", value: "abc", geometry: null }],
    actions: [{}],
  });
  await assert.rejects(
    page.fwcim({
      form: "#login",
      timing: { navigationStart: 100, fetchStart: 99 },
      inputs: null,
    }),
    { code: "invalid_inputs" },
  );
});

test("cookies accept null and jar wrappers but reject non-cookie arrays", async (t) => {
  /** @type {Record<string, string>[]} */ const selected = [];
  /** @type {typeof fetch} */ const api = async (_url, init) => {
    selected.push(JSON.parse(String(init?.body)).cookies);
    return result();
  };
  t.mock.method(globalThis, "fetch", api);
  const page = new Nullgate("fake")
    .session({ userAgent: "browser" })
    .page(url, html);
  for (const cookies of [
    null,
    { jar: { _abck: "selected", private: "omitted" } },
  ])
    await page.sensor({ script: "", scriptUrl: "/sensor", cookies });
  await assert.rejects(
    page.sensor({
      script: "",
      scriptUrl: "/sensor",
      cookies: /** @type {any} */ ([1]),
    }),
    { code: "invalid_cookies" },
  );
  assert.deepEqual(selected, [{}, { _abck: "selected" }]);
});

test("raw action values remain blocked even on non-input events", async () => {
  const page = new Nullgate("fake")
    .session({ userAgent: "browser" })
    .page(url, html);
  await assert.rejects(
    page.sensor({
      script: "",
      scriptUrl: "/sensor",
      cookies: {},
      actions: /** @type {any} */ ([{ type: "click", value: "private" }]),
    }),
    { code: "invalid_actions" },
  );
});
