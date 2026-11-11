import assert from "node:assert/strict";
import test from "node:test";
import { Nullgate } from "@nullgate/sdk";

const session = new Nullgate("fake").session({ userAgent: "browser" });
for (const [html, sensor, pixel, sbsd] of [
  [
    '<html><script src="/sensor?a=1&amp;b=2#fragment"></script></html>',
    "https://shop.example/sensor?a=1&b=2",
    null,
    null,
  ],
  [
    '<base href="/assets/"><script src="collector"></script>',
    "https://shop.example/assets/collector",
    null,
    null,
  ],
  [
    '<script>bazadebezolkohpepadr = "123"</script><script src="/akam/13/ab12"></script>',
    null,
    "https://shop.example/akam/13/ab12",
    null,
  ],
  [
    '<script src="/guard?v=00000000-0000-0000-0000-00000000004a&t="></script>',
    null,
    null,
    "https://shop.example/guard?v=00000000-0000-0000-0000-00000000004a&t=",
  ],
  [
    '<template><script src="/inert"></script></template><noscript><script src="/inert"></script></noscript><script type="module" src="/module"></script><script src="https://other.example/foreign"></script><script src="/bundle.js"></script>',
    null,
    null,
    null,
  ],
  [
    '<script src="/sensor"></script><script src="/sensor"></script>',
    "https://shop.example/sensor",
    null,
    null,
  ],
]) {
  test(`discovers observed classic scripts: ${String(html).slice(0, 45)}`, () => {
    const page = session.page("https://shop.example/login", String(html));
    assert.deepEqual(
      [page.sensorUrl, page.pixelUrl, page.sbsdUrl],
      [sensor, pixel, sbsd],
    );
  });
}

test("ambiguous discovery lists candidates and allows an explicit scriptUrl", async (t) => {
  const page = session.page(
    "https://shop.example/login",
    '<script src="/first"></script><script src="/second"></script>',
  );
  assert.throws(() => page.sensorUrl, {
    code: "ambiguous_protection",
    message: /https:\/\/shop.example\/first.*https:\/\/shop.example\/second/,
  });
  t.mock.method(
    globalThis,
    "fetch",
    async (
      /** @type {RequestInfo | URL} */ _input,
      /** @type {RequestInit | undefined} */ init,
    ) => {
      assert.equal(
        JSON.parse(String(init?.body)).script_url,
        "https://shop.example/second",
      );
      return Response.json({
        request: {
          url: "https://shop.example/second",
          body: "payload",
          headers: {},
          send_at: 0,
        },
        session: "next",
        request_id: "id",
      });
    },
  );
  assert.equal(
    (
      await page.sensor({
        script: "source",
        scriptUrl: "https://shop.example/second",
        cookies: {},
      })
    ).url,
    "https://shop.example/second",
  );
});

test("absent protections stay null and operations explain how to provide a URL", async () => {
  const page = session.page("https://shop.example", "<html></html>");
  assert.deepEqual(
    [page.sensorUrl, page.pixelUrl, page.sbsdUrl],
    [null, null, null],
  );
  await assert.rejects(page.sensor({ script: "source", cookies: {} }), {
    code: "missing_protection",
  });
});
