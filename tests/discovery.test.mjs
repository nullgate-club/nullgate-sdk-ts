import assert from "node:assert/strict";
import test from "node:test";
import { findProtections, Page, Pixel, Sbsd, Sensor } from "@nullgate/sdk";

const version = "11111111-2222-4333-8444-555555555555";

test("discovery preserves source queries, duplicate occurrences, and challenge ambiguity", () => {
  const page = new Page(
    "https://target.example/login/index",
    [
      '<base href="/resources/">',
      '<script>bazadebezolkohpepadr="0012";bazadebezolkohpepadr="34";</script>',
      '<script src="/akam/13/aB09?x=a%2Fb+z&amp;x=two#ignored"></script>',
      `<script src="opaque/block?v=${version}&amp;t="></script>`,
      '<script src="opaque/sensor?first=%2f&amp;second=+value"></script>',
      '<script src="opaque/sensor?first=%2f&amp;second=+value"></script>',
    ].join("\n"),
  );
  const found = findProtections(page);
  assert.deepEqual(
    found.map((item) => item.kind),
    ["pixel", "pixel", "sbsd", "sensor", "sensor"],
  );
  const [first, second, blocking, sensor, duplicate] = found;
  assert.ok(first instanceof Pixel && second instanceof Pixel);
  assert.equal(first.page, page);
  assert.deepEqual([first.challenge, second.challenge], ["0012", "34"]);
  assert.equal(
    first.scriptURL,
    "https://target.example/akam/13/aB09?x=a%2Fb+z&x=two",
  );
  assert.deepEqual(first.provenance, {
    rawSource: "/akam/13/aB09?x=a%2Fb+z&x=two#ignored",
    tagIndex: 1,
    line: 3,
    column: 0,
  });
  assert.ok(first.challengeOffset !== undefined);
  assert.ok(
    page.html.slice(first.challengeOffset).startsWith("bazadebezolkohpepadr"),
  );
  assert.ok(blocking instanceof Sbsd && blocking.blocking);
  assert.ok(sensor instanceof Sensor && duplicate instanceof Sensor);
  assert.equal(
    sensor.scriptURL,
    "https://target.example/resources/opaque/sensor?first=%2f&second=+value",
  );
  assert.notDeepEqual(sensor.provenance, duplicate.provenance);
});

test("only active same-origin classic scripts qualify, with first duplicate attribute winning", () => {
  const page = new Page(
    "https://target.example/login/page",
    [
      '<!-- <script src="/comment"></script> -->',
      '<template><script src="/template"></script></template>',
      '<noscript><script src="/noscript"></script></noscript>',
      '<script type="module" src="/module"></script>',
      '<script nomodule src="/legacy"></script>',
      '<script type="application/json" src="/data"></script>',
      '<script src="https://other.example/cross"></script>',
      '<script src="http://target.example/insecure"></script>',
      '<script src="https://target.example:8443/port"></script>',
      '<script src="http://["></script>',
      '<script src="javascript:ignored"></script>',
      '<script src=""></script>',
      '<SCRIPT TYPE="text/javascript" SRC="collector" src="https://other.example/duplicate"></SCRIPT>',
    ].join(""),
  );
  assert.deepEqual(
    findProtections(page).map((item) => item.scriptURL),
    ["https://target.example/login/collector"],
  );
  for (const [base, expected] of [
    ["", "https://target.example/login/collector"],
    ['<base href="/assets/">', "https://target.example/assets/collector"],
    ['<base href="http://[">', "https://target.example/login/collector"],
    [
      '<base href="javascript:ignored">',
      "https://target.example/login/collector",
    ],
    ['<base href="https://other.example/">', undefined],
  ]) {
    const found = findProtections(
      new Page(page.url, `${base}<script src="collector"></script>`),
    );
    assert.equal(found[0]?.scriptURL, expected);
  }
});

test("JS assets and ambiguous SBSD queries are not silently reclassified", () => {
  for (const source of [
    "/app.js",
    "/app.JS?x=2",
    "/app.mjs",
    "/app.cjs",
    "/app%2Ejs",
  ]) {
    assert.deepEqual(
      findProtections(
        new Page(
          "https://target.example/",
          `<script src="${source}"></script>`,
        ),
      ),
      [],
    );
  }
  const page = new Page(
    "https://target.example/",
    [
      '<!-- bazadebezolkohpepadr="123" -->',
      '<template><script>bazadebezolkohpepadr="456";</script></template>',
      '<script type="application/json">bazadebezolkohpepadr="789";</script>',
      '<script src="/akam/13/abc"></script>',
      `<script src="/duplicate?v=${version}&amp;v=${version}"></script>`,
      `<script src="/tokens?v=${version}&amp;t=one&amp;t=two"></script>`,
    ].join(""),
  );
  assert.deepEqual(findProtections(page), []);
});

test("SBSD blocking is raw t presence, and predicates filter concrete candidates locally", () => {
  for (const token of ["t", "t=", "t=opaque%2Ftoken+part"]) {
    assert.equal(
      new Sbsd(
        new Page("https://target.example/", ""),
        `https://target.example/s?v=${version}&${token}`,
      ).blocking,
      true,
    );
  }
  const page = new Page(
    "https://target.example/",
    [
      `<script src="/one?v=${version}&amp;%74="></script>`,
      `<script src="/two?v=${version}&amp;t="></script>`,
      '<script src="/sensor"></script>',
    ].join(""),
  );
  assert.deepEqual(
    findProtections(page, {
      where: (item) => item.kind === "sbsd" && item.blocking,
    }).map((item) => item.scriptURL),
    [`https://target.example/two?v=${version}&t=`],
  );
  const normal = findProtections(page)[0];
  assert.ok(normal instanceof Sbsd && !normal.blocking);
});

test("relative or non-HTTP page URLs are rejected at the public boundary", () => {
  for (const url of [
    "/relative",
    "file:///tmp/page",
    "javascript:x",
    "https://[",
  ]) {
    assert.throws(() => new Page(url, ""), TypeError);
  }
});
