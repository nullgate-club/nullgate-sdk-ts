import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { abckCounters, isEnough, Nullgate, prepareInputs } from "@nullgate/sdk";

for (const [value, counts, hash31, trimmedHash31, trimmedLength] of [
  ["A_9 😀İ\u00a0", [8, 3, 2, 1], -902761640, 386520648, 7],
  ["\ud800", [1, 1, 0, 0], 55296, 55296, 1],
  ["", [0, 0, 0, 0], 0, 0, 0],
]) {
  test(`summarizes UTF-16 inputs locally: ${JSON.stringify(value)}`, async (t) => {
    /** @type {Record<string, any>} */ let body = {};
    t.mock.method(
      globalThis,
      "fetch",
      async (
        /** @type {RequestInfo | URL} */ _url,
        /** @type {RequestInit | undefined} */ init,
      ) => {
        body = JSON.parse(String(init?.body));
        return Response.json({
          request: {
            url: "https://shop.example/sensor",
            body: "payload",
            headers: {},
            send_at: 0,
          },
          session: "next",
          request_id: "id",
        });
      },
    );
    const page = new Nullgate("fake")
      .session({ userAgent: "browser" })
      .page(
        "https://shop.example",
        '<input id="email"><script src="/sensor"></script>',
      );
    await page.sensor({
      script: "source",
      cookies: {},
      inputs: { email: String(value) },
    });
    assert.deepEqual(body.inputs[0].value, {
      length: String(value).length,
      hash: createHash("sha256").update(String(value), "utf16le").digest("hex"),
      counts,
      hash31,
      trimmed_hash31: trimmedHash31,
      trimmed_length: trimmedLength,
    });
    assert.deepEqual(body.inputs[0].attributes, { id: "email" });
  });
}

for (const html of [
  '<input id="secret" type="password">',
  '<input id="secret" autocomplete="current-password">',
  '<input id="secret" name="ap_password">',
  '<input type="password" value="" value="secret">',
  '<template><input type="password" value="secret"></template>',
  '<textarea autocomplete="new-password">secret</textarea>',
]) {
  test(`refuses password observations and HTML: ${html}`, async (t) => {
    let calls = 0;
    t.mock.method(globalThis, "fetch", async () => {
      calls++;
      throw new Error("must not send");
    });
    const session = new Nullgate("fake").session({ userAgent: "browser" });
    const createPage = () =>
      session.page(
        "https://shop.example",
        `<form id="login">${html}</form><script src="/sensor"></script>`,
      );
    if (html.includes('value="secret"') || html.includes(">secret<")) {
      assert.throws(createPage, { code: "invalid_page" });
      return;
    }
    const page = createPage();
    await assert.rejects(
      page.sensor({
        script: "source",
        cookies: {},
        inputs: { secret: "private" },
      }),
      { code: "invalid_inputs" },
    );
    await assert.rejects(
      page.fwcim({
        form: "#login",
        timing: { navigationStart: 1 },
        inputs: { secret: "private" },
      }),
      { code: "invalid_inputs" },
    );
    assert.equal(calls, 0);
  });
}

test("cookie jars select only product cookies for the actual page URL", async (t) => {
  /** @type {string[]} */ const requested = [];
  t.mock.method(
    globalThis,
    "fetch",
    async (
      /** @type {RequestInfo | URL} */ _url,
      /** @type {RequestInit | undefined} */ init,
    ) => {
      assert.deepEqual(JSON.parse(String(init?.body)).cookies, {
        _abck: "observed",
      });
      return Response.json({
        request: {
          url: "https://shop.example/sensor",
          body: "payload",
          headers: {},
          send_at: 0,
        },
        session: "next",
        request_id: "id",
      });
    },
  );
  const page = new Nullgate("fake")
    .session({ userAgent: "browser" })
    .page("https://shop.example/login", '<script src="/sensor"></script>');
  await page.sensor({
    script: "source",
    cookies: {
      async getCookies(url) {
        requested.push(url);
        return [
          { key: "_abck", value: "observed" },
          { key: "private", value: "omit" },
        ];
      },
    },
  });
  assert.deepEqual(requested, ["https://shop.example/login"]);
});

// A prepared password observation must keep v1 UTF-16 facts without sending its raw value.
const preparedPassword = {
  attributes: { id: "secret" },
  value: {
    length: 4,
    hash: createHash("sha256")
      .update(Buffer.from("73003dd811dd2600", "hex"))
      .digest("hex"),
    counts: [4, 3, 1, 0],
    hash31: 58378463,
    trimmed_hash31: 58378463,
    trimmed_length: 4,
  },
};
test("public prepareInputs retains the v1 password summary", () => {
  assert.deepEqual(prepareInputs([{ id: "secret", value: "s🔑&" }]), [
    preparedPassword,
  ]);
});
for (const operation of ["sensor", "fwcim"]) {
  for (const attributes of [
    'type="password"',
    'autocomplete="new-password"',
    'name="ap_password"',
  ]) {
    test(`${operation} accepts a prepared password summary for ${attributes}`, async () => {
      const client = new Nullgate("fake", {
        fetch: async (_url, init) => {
          const body = JSON.parse(String(init?.body));
          assert.deepEqual(body.inputs[0], preparedPassword);
          assert.equal(String(init?.body).includes("s🔑&"), false);
          assert.equal(body.inputs[1].value.hash31, 96354);
          return Response.json(
            operation === "sensor"
              ? {
                  request: {
                    url: "https://shop.example/sensor",
                    body: "opaque",
                    headers: {},
                    send_at: 0,
                  },
                  session: "next",
                  request_id: "id",
                }
              : {
                  metadata1: "opaque",
                  headers: {},
                  send_at: 0,
                  session: "next",
                  request_id: "id",
                },
          );
        },
      });
      const page = client
        .session({ userAgent: "browser" })
        .page(
          "https://shop.example",
          `<form id="login"><input id="secret" ${attributes}><input id="email"></form><script src="/sensor"></script>`,
        );
      const inputs = [
        ...prepareInputs([{ id: "secret", value: "s🔑&" }]),
        { id: "email", value: "abc" },
      ];
      if (operation === "sensor")
        await page.sensor({ script: "source", cookies: {}, inputs });
      else
        await page.fwcim({
          form: "#login",
          timing: { navigationStart: 1 },
          inputs,
        });
    });
  }
  test(`${operation} preserves absent optional summary members`, async () => {
    const input = {
      attributes: { id: "secret" },
      value: { length: 4, hash: preparedPassword.value.hash },
    };
    const client = new Nullgate("fake", {
      fetch: async (_url, init) => {
        assert.deepEqual(JSON.parse(String(init?.body)).inputs, [input]);
        return Response.json(
          operation === "sensor"
            ? {
                request: {
                  url: "https://shop.example/sensor",
                  body: "opaque",
                  headers: {},
                  send_at: 0,
                },
                session: "next",
                request_id: "id",
              }
            : {
                metadata1: "opaque",
                headers: {},
                send_at: 0,
                session: "next",
                request_id: "id",
              },
        );
      },
    });
    const page = client
      .session({ userAgent: "browser" })
      .page(
        "https://shop.example",
        '<form id="login"><input id="secret" type="password"></form><script src="/sensor"></script>',
      );
    if (operation === "sensor")
      await page.sensor({ script: "source", cookies: {}, inputs: [input] });
    else
      await page.fwcim({
        form: "#login",
        timing: { navigationStart: 1 },
        inputs: [input],
      });
  });
}

/** @type {unknown[]} */
const malformedSummaries = [
  {},
  { value: preparedPassword.value },
  { attributes: { id: "secret" } },
  { ...preparedPassword, raw: "secret" },
  { ...preparedPassword, attributes: { id: "secret", value: "secret" } },
  { ...preparedPassword, attributes: { id: 1 } },
  { ...preparedPassword, attributes: [] },
  { ...preparedPassword, selector: "" },
  { ...preparedPassword, selector: null },
  ...[
    "raw password",
    null,
    {},
    { length: 1, hash: "bad" },
    { length: -1, hash: "0".repeat(64) },
    { length: true, hash: "0".repeat(64) },
    { length: 0.5, hash: "0".repeat(64) },
    { length: 1, hash: "A".repeat(64) },
    { length: 1, hash: "0".repeat(64), raw: "secret" },
    { length: 1, hash: "0".repeat(64), counts: null },
    { length: 1, hash: "0".repeat(64), counts: [1, 0, 0] },
    { length: 1, hash: "0".repeat(64), counts: [2, 0, 0, 0] },
    { length: 1, hash: "0".repeat(64), counts: [1, -1, 0, 0] },
    { length: 1, hash: "0".repeat(64), counts: [1, 0, true, 0] },
    { length: 1, hash: "0".repeat(64), counts: [1, 1, 0, 1] },
    { length: 1, hash: "0".repeat(64), counts: [1, 0, 1, 1] },
    { length: 1, hash: "0".repeat(64), hash31: 2 ** 31 },
    { length: 1, hash: "0".repeat(64), trimmed_hash31: -(2 ** 31) - 1 },
    { length: 1, hash: "0".repeat(64), trimmed_length: 2 },
    { length: 1, hash: "0".repeat(64), trimmed_length: 0, trimmed_hash31: 1 },
  ].map((value) => ({ attributes: { id: "secret" }, value })),
];
for (const [index, summary] of malformedSummaries.entries()) {
  test(`malformed prepared summary ${index} is rejected before API transport`, async () => {
    const page = new Nullgate("fake", {
      fetch: async () => assert.fail("must not send"),
    })
      .session({ userAgent: "browser" })
      .page(
        "https://shop.example",
        '<form id="login"><input id="secret"></form><script src="/sensor"></script>',
      );
    await assert.rejects(
      page.sensor({
        script: "source",
        cookies: {},
        inputs: /** @type {any} */ ([summary]),
      }),
      { code: "invalid_inputs" },
    );
    await assert.rejects(
      page.fwcim({
        form: "#login",
        timing: { navigationStart: 1 },
        inputs: /** @type {any} */ ([summary]),
      }),
      { code: "invalid_inputs" },
    );
  });
}

test("cookie counters retain v1 URI decoding and decimal prefix semantics", () => {
  for (const [
    value,
    expected,
  ] of /** @type {[string | null | undefined, number[]][]} */ ([
    ["x%7E%20%2B2tail%7Ez%7E3rest", [2, 3]],
    ["x~9007199254740993~z~0", [9007199254740992, 0]],
    ["x~0x10~z~-2tail", [0, -2]],
    ["x~\u00852~z~4", [-1, 4]],
    ...[undefined, null, "", "a~2", "a%~2~c~4", "a~2~c~%FF"].map((value) => [
      value,
      [-1, -1],
    ]),
  ]))
    assert.deepEqual(abckCounters(value), expected);
});
test("isEnough retains the v1 ordinary-send eligibility table", () => {
  for (const [
    value,
    count,
    expected,
  ] of /** @type {[string | null | undefined, number | undefined, boolean][]} */ ([
    ["x~2~z~0", 1, false],
    ["x~2~z~0", 2, true],
    ["x~0~z~0", undefined, true],
    ["x~-2~z~0", undefined, true],
    ...[undefined, null, "", "a~2", "a%~2~c~4", "a~2~c~%FF"].map((value) => [
      value,
      99,
      false,
    ]),
  ]))
    assert.equal(isEnough(value, count), expected);
});
