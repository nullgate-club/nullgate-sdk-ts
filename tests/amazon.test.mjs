import assert from "node:assert/strict";
import test from "node:test";
import { Nullgate } from "@nullgate/sdk";

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
      { code: "invalid_request" },
    );
    assert.equal(sent, false);
  });
}
