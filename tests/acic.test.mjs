import assert from "node:assert/strict";
import test from "node:test";
import { inspect } from "node:util";
import { acic } from "@nullgate/sdk";

const pageUrl = "https://www.amazon.de/cvf/page";
const setup = `<script>acic.setupACIC({
  "data-ref-id": "cvf", "data-challenge-type": "POW", "data-callback": function(data) { return submit(data); },
  "data-header-footer": false, "data-context": '{"x":"a+/="}', "data-locale": "en-GB",
  "data-external-id": "external", "data-host-config": "prod.EUAmazon",
  "data-use-post-request-method": true, "data-enable-telemetry": true,
  "data-div": document.querySelector("#cvf-aamation-container")
});</script><div id="cvf-aamation-container"></div>`;
const form = `<form id="cvf-aamation-challenge-form" method="post" action="verify">
<input type="hidden" name="duplicate" value="one"><input type="hidden" name="empty">
<input type="hidden" name="duplicate" value="two"><input type="hidden" name="cvf_aamation_response_token" value="old"></form>`;
/** @param {string} action @param {unknown} context @param {string} token */
const header = (action, context, token) => ({
  "Amz-Aamation-Resp": JSON.stringify({
    actionType: action,
    clientSideContext: context,
    sessionToken: token,
  }),
});
/** @param {Uint8Array | null} body */
const text = (body) => new TextDecoder().decode(body ?? undefined);

test("start and successive answers preserve options and current opaque state", () => {
  const found = acic.discover(pageUrl, setup);
  assert.ok(found);
  assert.equal(found.serviceUrl, "https://www.amazon.de/aaut/verify/cvf");
  const start = found.start();
  assert.deepEqual(start.headers, {
    "Content-Type": "application/json",
    Origin: "https://www.amazon.de",
    Referer: pageUrl,
  });
  const initial = JSON.parse(text(start.body));
  assert.equal(initial.options, new URL(start.url).searchParams.get("options"));
  assert.deepEqual(JSON.parse(initial.options), {
    clientData: '{"x":"a+/="}',
    challengeType: "POW",
    locale: "en-GB",
    externalId: "external",
    enableHeaderFooter: false,
    enableBypassMechanism: false,
    enableModalView: false,
    eventTrigger: null,
    aaExternalToken: null,
    forceJsFlush: false,
    aamationToken: null,
    pageId: null,
  });
  assert.deepEqual(
    [initial.context, initial.response, initial.fwcimBlob],
    [null, "null", null],
  );
  /** @type {[string, string][]} */
  const stages = [
    ["first+/=", "token+/="],
    ["second", "new/token"],
  ];
  for (const [context, token] of stages) {
    const result = acic.parseResult(header("POW", context, token));
    assert.ok(result);
    const answer = found.answer(result, '{"proof":1}');
    assert.deepEqual(answer.headers, start.headers);
    const url = new URL(answer.url);
    assert.equal(url.pathname, `/aaut/verify/cvf/${encodeURIComponent(token)}`);
    assert.equal(url.searchParams.get("context"), context);
    assert.equal(url.searchParams.get("options"), initial.options);
    assert.equal(url.searchParams.get("response"), '{"proof":1}');
    assert.deepEqual(JSON.parse(text(answer.body)), {
      context,
      options: initial.options,
      response: '{"proof":1}',
      fwcimBlob: null,
    });
  }
});

test("continuation retains duplicate fields and substitutes the final token", () => {
  const found = acic.discover(pageUrl, setup + form);
  const result = acic.parseResult(header("PASS", "private", "last+/="));
  assert.ok(found && result);
  const continuation = found.continuation(result);
  assert.equal(continuation.url, "https://www.amazon.de/cvf/verify");
  assert.equal(
    text(continuation.body),
    "duplicate=one&empty=&duplicate=two&cvf_aamation_response_token=last%2B%2F%3D",
  );
  assert.doesNotMatch(inspect(result), /private|last/);
  assert.throws(
    () => found.continuation(new acic.Result("POW", null, "x")),
    /PASS/,
  );
  assert.throws(
    () =>
      acic
        .discover(
          pageUrl,
          setup +
            form.replace('action="verify"', 'action="https://other.example/"'),
        )
        ?.continuation(result),
    /same-origin/,
  );
});

test("missing and malformed setup and result are distinct", () => {
  assert.equal(acic.discover(pageUrl, "<script>unrelated()</script>"), null);
  assert.equal(acic.parseResult({}), null);
  assert.throws(
    () => acic.parseResult({ "amz-aamation-resp": "{" }),
    /Malformed/,
  );
  assert.throws(() => acic.discover(pageUrl, setup + setup), /Ambiguous/);
  assert.throws(
    () =>
      acic.discover(
        pageUrl,
        setup.replace('"data-locale": "en-GB"', '"data-locale": dynamicValue'),
      ),
    /literal/,
  );
  assert.throws(
    () =>
      acic.discover(
        pageUrl,
        setup.replace(
          '"data-locale": "en-GB"',
          '"data-locale": "en-GB", "data-locale": "de-DE"',
        ),
      ),
    /Duplicate/,
  );
  const found = acic.discover(pageUrl, setup);
  const result = acic.parseResult(header("PASS", null, "token"));
  assert.ok(found && result);
  assert.throws(() => found.continuation(result), /missing/);
  assert.deepEqual(JSON.parse(result.voucherResponse('v"+')), {
    challengeType: "PASS",
    data: '"v\\"+"',
  });
});

test("WAF discovery uses the matching provider, locale and required rounds", () => {
  const html = `<script>Object.assign({"problem":"decoy"}, unrelated)</script>
<script src="https://tenant.eu-west-1.captcha.awswaf.com/path/captcha.js"></script>
<script>const wafInputProperties = Object.assign({"problem":"grid","visualSolutionsRequired":2,"defaultLocale":"en-GB","id":"a+/="}, wafOnLoadProperty);</script>`;
  const waf = acic.discoverWaf(pageUrl, html);
  assert.ok(waf);
  const problem = new URL(waf.problemUrl);
  assert.equal(
    problem.origin + problem.pathname,
    "https://tenant.eu-west-1.captcha.awswaf.com/path/problem",
  );
  assert.deepEqual(Object.fromEntries(problem.searchParams), {
    kind: "visual",
    domain: "www.amazon.de",
    locale: "en-gb",
    problem: "grid",
    num_solutions_required: "2",
    id: "a+/=",
  });
  assert.equal(waf.roundsRequired, 2);
  assert.equal(
    waf.verificationUrl({ region: "eu-west-1" }),
    "https://tenant.eu-west-1.captcha.awswaf.com/path/verify?region=eu-west-1",
  );
  assert.deepEqual(waf.headers, {
    Origin: "https://www.amazon.de",
    Referer: "https://www.amazon.de/",
    "Content-Type": "text/plain;charset=UTF-8",
  });
  assert.equal(
    acic.discoverWaf(pageUrl, "<script>Object.assign({}, unrelated)</script>"),
    null,
  );
  assert.throws(
    () =>
      acic.discoverWaf(
        pageUrl,
        html.replace("tenant.eu-west-1.captcha.awswaf.com", "evil.example"),
      ),
    /provider/,
  );
});

test("bootstrap preserves JavaScript string escapes without evaluating expressions", () => {
  const html = setup.replace(
    `'{"x":"a+/="}'`,
    String.raw`'{"path":"https:\/\/example.test\/","symbol":"\ud83d\ude00"}'`,
  );
  const found = acic.discover(pageUrl, html);
  assert.ok(found);
  assert.equal(
    JSON.parse(JSON.parse(text(found.start().body)).options).clientData,
    '{"path":"https://example.test/","symbol":"\u{1f600}"}',
  );
  assert.throws(
    () => acic.discover(pageUrl, setup.replace('"en-GB"', "'en-GB' 'suffix'")),
    /literal/,
  );
});
