import assert from "node:assert/strict";
import test from "node:test";
import {
  AmbiguousProtectionError,
  findProtections,
  Page,
  Pixel,
  Sbsd,
  Sensor,
  ThreatMetrix,
} from "@nullgate/sdk";

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
  const found = findProtections(page, { panic: false });
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

test("discovery rejects multiple candidates by default, even across kinds", () => {
  const page = new Page(
    "https://target.example/",
    `<script src="/sensor"></script><script src="/sbsd?v=${version}"></script>`,
  );
  const candidates = findProtections(page, { panic: false });
  assert.throws(
    () => findProtections(page),
    (error) => {
      assert.ok(error instanceof AmbiguousProtectionError);
      assert.deepEqual(error.candidates, candidates);
      return true;
    },
  );
  assert.throws(
    () => findProtections(page, { panic: true }),
    AmbiguousProtectionError,
  );
});

test("where filters before ambiguity and opt-out returns only matching candidates", () => {
  const page = new Page(
    "https://target.example/",
    [
      '<script src="/first"></script>',
      `<script src="/sbsd?v=${version}"></script>`,
      '<script src="/second"></script>',
    ].join(""),
  );
  const onlySbsd = findProtections(page, {
    where: (item) => item.kind === "sbsd",
  });
  assert.ok(onlySbsd[0] instanceof Sbsd);
  assert.deepEqual(
    onlySbsd.map((item) => item.scriptURL),
    [`https://target.example/sbsd?v=${version}`],
  );
  assert.deepEqual(findProtections(page, { where: () => false }), []);
  assert.throws(
    () =>
      findProtections(page, {
        where: (item) => item.kind === "sensor",
      }),
    (error) => {
      assert.ok(error instanceof AmbiguousProtectionError);
      assert.deepEqual(
        error.candidates.map((item) => item.scriptURL),
        ["https://target.example/first", "https://target.example/second"],
      );
      return true;
    },
  );
  const sensors = findProtections(page, {
    where: (item) => item.kind === "sensor",
    panic: false,
  });
  assert.deepEqual(
    sensors.map((item) => item.provenance?.tagIndex),
    [0, 2],
  );
});

test("ThreatMetrix tags cross origins without weakening mixed-provider ambiguity", () => {
  const page = new Page(
    "https://target.example/login",
    [
      '<base href="https://collector.example/resources/">',
      '<script src="tags.js?org_id=org&amp;session_id=document"></script>',
      '<script src="/tags.js?org_id=first&amp;org_id=second&amp;session_id=document"></script>',
      '<script src="/tags.js?org_id=org&amp;session_id="></script>',
      '<script src="https://target.example/sensor"></script>',
    ].join(""),
  );
  assert.throws(() => findProtections(page), AmbiguousProtectionError);
  const found = findProtections(page, { panic: false });
  assert.equal(found.length, 2);
  assert.ok(found[0] instanceof ThreatMetrix);
  assert.equal(found[0].page, page);
  assert.equal(
    found[0].scriptURL,
    "https://collector.example/resources/tags.js?org_id=org&session_id=document",
  );
  assert.ok(found[1] instanceof Sensor);
  const selected = findProtections(page, {
    where: (candidate) => candidate.provider === "threatmetrix",
  });
  assert.deepEqual(selected, [found[0]]);
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
  const normal = findProtections(page, { panic: false })[0];
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
