import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { Nullgate } from "@nullgate/sdk";

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
