import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";
import { json } from "node:stream/consumers";
import test from "node:test";
import { inspect } from "node:util";
import {
  NullgateAPIError,
  NullgateClient,
  NullgateClosedError,
  NullgateProtocolError,
  NullgateTransportError,
  Page,
  Pixel,
  PixelParams,
  Sbsd,
  SbsdParams,
  Sensor,
  SensorParams,
} from "@nullgate/sdk";

const identity = "11111111-2222-4333-8444-555555555555";
const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const page = new Page(
  "https://target.example/login",
  "<html>private document</html>",
);
const sensor = new Sensor(page, "https://target.example/collector?x=%2f");
const params = new SensorParams(sensor, "private source");
const requestId = "0123456789abcdef0123456789abcdef";
const apiKey = "ng_private_test_credential";

/**
 * @typedef {{
 *   website: {url: string, html: string, document_id: string, started_at_ms: number},
 *   timezone?: string,
 *   script: {text: string, source: string},
 *   challenge?: string,
 *   cookies?: Record<string, string>,
 *   inputs: {attributes: Record<string, string>, value: {counts: number[]}}[],
 *   actions: unknown[]
 * }} GenerationRequest
 */

/**
 * @param {import('node:test').TestContext} t
 * @param {(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => void | Promise<void>} handler
 */
async function serve(t, handler) {
  /** @type {unknown[]} */
  const failures = [];
  const server = createServer(async (req, res) => {
    try {
      await handler(req, res);
    } catch (error) {
      failures.push(error);
      res.writeHead(500).end();
    }
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address === "object");
  t.after(async () => {
    const closed = once(server, "close");
    server.closeAllConnections();
    server.close();
    await closed;
    assert.deepEqual(failures, []);
  });
  return `http://127.0.0.1:${address.port}`;
}

/**
 * @param {import('node:http').ServerResponse} res
 * @param {unknown} body
 * @param {Record<string, string>} [headers]
 */
function reply(res, body, headers = {}) {
  res.writeHead(200, {
    "Content-Type": "application/json",
    "X-Request-ID": requestId,
    ...headers,
  });
  res.end(JSON.stringify(body));
}

test("all concrete operations normalize real service shapes into ready target requests", async (t) => {
  const baseURL = await serve(t, async (req, res) => {
    assert.equal(req.method, "POST");
    assert.equal(req.headers.authorization, `Bearer ${apiKey}`);
    assert.equal(req.headers["user-agent"], "Windows Chrome146");
    const body = /** @type {GenerationRequest} */ (await json(req));
    assert.equal(body.timezone, "Europe/Berlin");
    assert.equal(typeof body.script.text, "string");
    if (req.url?.endsWith("type=pixel")) {
      assert.equal(body.challenge, "0012");
      reply(res, {
        url: "https://target.example/pixel",
        body: "a=one%2Btwo+three",
        send_at: -1,
        headers: { "Accept-Language": "en-US", "content-TYPE": "wrong/type" },
      });
    } else if (req.url?.endsWith("type=sbsd")) {
      assert.deepEqual(body.cookies, { sbsd: "opaque" });
      reply(res, {
        url: "https://target.example/sbsd?t=",
        body: '{"body":"encoded"}',
        send_at: -1,
        headers: { "Accept-Language": "en-US" },
      });
    } else {
      assert.equal(req.url, `/v1/${identity}/generate?type=akamai`);
      assert.equal(body.script.source, sensor.scriptURL);
      const input = body.inputs[0];
      assert.ok(input);
      assert.deepEqual(input.attributes, {
        name: "credential",
        type: "password",
      });
      assert.deepEqual(input.value.counts, [4, 3, 1, 0]);
      assert.equal(JSON.stringify(body).includes("s🔑&"), false);
      assert.deepEqual(body.actions, []);
      reply(res, {
        sensor_data: 'encoded;"snow☃',
        send_at: -1,
        headers: { "Accept-Language": "en-US" },
      });
    }
  });
  const client = new NullgateClient({ apiKey, baseURL });
  t.after(() => client.close());
  const session = client.open({
    identity,
    userAgent: "Windows Chrome146",
    timezone: "Europe/Berlin",
  });
  const pixelResult = await session.solve(
    new PixelParams(
      new Pixel(page, "https://target.example/akam/13/abc", "0012"),
      "pixel source",
    ),
  );
  assert.equal(pixelResult.method, "POST");
  assert.equal(pixelResult.body, "a=one%2Btwo+three");
  assert.equal(pixelResult.url, "https://target.example/pixel");
  assert.equal(
    pixelResult.headers["content-type"],
    "application/x-www-form-urlencoded",
  );
  assert.equal(pixelResult.headers["accept-language"], "en-US");
  assert.equal(pixelResult.requestId, requestId);
  assert.equal(pixelResult.sendAt, -1);
  const sbsdResult = await session.solve(
    new SbsdParams(
      new Sbsd(page, `https://target.example/sbsd?v=${identity}&t=`),
      "sbsd source",
      { cookies: { sbsd: "opaque" } },
    ),
  );
  assert.equal(sbsdResult.body, '{"body":"encoded"}');
  assert.equal(sbsdResult.headers["content-type"], "application/json");
  const result = await session.solve(
    new SensorParams(sensor, "sensor source", {
      inputs: [{ name: "credential", type: "password", value: "s🔑&" }],
      actions: [],
    }),
  );
  assert.equal(result.url, sensor.scriptURL);
  assert.equal(result.body, JSON.stringify({ sensor_data: 'encoded;"snow☃' }));
  assert.equal(result.headers["content-type"], "text/plain;charset=UTF-8");
});

test("queued discoveries change document context without replacing session state", async (t) => {
  const before = Date.now();
  const acquired = new Page(
    "https://target.example/login",
    [
      '<script>bazadebezolkohpepadr="12"</script>',
      '<script src="/akam/13/abc"></script>',
      '<script src="/sensor"></script>',
      `<script src="/sbsd?v=${identity}"></script>`,
    ].join(""),
  );
  const reacquired = new Page(acquired.url, acquired.html);
  const after = Date.now();
  /** @type {Array<{body: GenerationRequest, state: string}>} */
  const seen = [];
  const baseURL = await serve(t, async (req, res) => {
    assert.equal(req.url?.startsWith(`/v1/${identity}/generate?`), true);
    assert.equal(req.headers["user-agent"], "document-session");
    const body = /** @type {GenerationRequest} */ (await json(req));
    assert.equal(body.timezone, "Europe/Berlin");
    const state = req.headers["x-state-id"];
    assert.ok(typeof state === "string");
    assert.match(state, uuidPattern);
    seen.push({ body, state });
    reply(
      res,
      req.url?.endsWith("type=akamai")
        ? { sensor_data: "encoded", headers: {}, send_at: 0 }
        : {
            url: "https://target.example/submit",
            body: "encoded",
            headers: {},
            send_at: 0,
          },
    );
  });
  const client = new NullgateClient({ apiKey, baseURL });
  t.after(() => client.close());
  const session = client.open({
    identity,
    userAgent: "document-session",
    timezone: "Europe/Berlin",
  });
  const pending = [];
  for (const document of [acquired, reacquired]) {
    for (const protection of client.findProtections(document, {
      panic: false,
    })) {
      if (protection.provider !== "akamai") continue;
      const params =
        protection.kind === "pixel"
          ? new PixelParams(protection, "source")
          : protection.kind === "sensor"
            ? new SensorParams(protection, "source")
            : new SbsdParams(protection, "source");
      pending.push(session.solve(params));
    }
  }
  await Promise.all(pending);
  assert.equal(seen.length, 6);
  for (const [index, request] of seen.entries()) {
    const document = index < 3 ? acquired : reacquired;
    assert.equal(request.body.website.document_id, document.documentId);
    assert.equal(request.body.website.started_at_ms, document.startedAtMs);
    assert.ok(Number.isInteger(document.startedAtMs));
    assert.ok(document.startedAtMs >= before && document.startedAtMs <= after);
    assert.match(document.documentId, uuidPattern);
    assert.equal(request.state, seen[index < 3 ? 0 : 3]?.state);
  }
  assert.notEqual(acquired.documentId, reacquired.documentId);
  assert.equal(seen[0]?.state, seen[3]?.state);
});

test("parallel sessions stay isolated, and error rotations survive absent later state headers", {
  timeout: 5000,
}, async (t) => {
  const arrived = Promise.withResolvers();
  const release = Promise.withResolvers();
  /** @type {Array<{ua: string | undefined, state: string | string[] | undefined}>} */
  const seen = [];
  const counts = new Map();
  const baseURL = await serve(t, async (req, res) => {
    await json(req);
    const ua = req.headers["user-agent"];
    const count = (counts.get(ua) ?? 0) + 1;
    counts.set(ua, count);
    seen.push({ ua, state: req.headers["x-state-id"] });
    if (ua === "A" && count === 1) {
      arrived.resolve(undefined);
      await release.promise;
    }
    if (ua === "A" && count === 2) {
      res.writeHead(409, {
        "X-State-ID": "A-rotated",
        "X-Request-ID": requestId,
      });
      res.end(
        JSON.stringify({
          detail: { message: "stale", input: "private-source-and-cookie" },
        }),
      );
      return;
    }
    reply(
      res,
      { sensor_data: "encoded", headers: {}, send_at: -1 },
      count === 1 ? { "X-State-ID": `${ua}-initial` } : {},
    );
  });
  const client = new NullgateClient({ apiKey, baseURL });
  t.after(() => client.close());
  const a = client.open({ identity, userAgent: "A" });
  const b = client.open({ identity, userAgent: "B" });
  const a1 = a.solve(params);
  const a2 = assert.rejects(a.solve(params), (error) => {
    assert.ok(error instanceof NullgateAPIError);
    assert.equal(error.statusCode, 409);
    assert.equal(error.requestId, requestId);
    assert.deepEqual(error.detail, {
      message: "stale",
      input: "private-source-and-cookie",
    });
    assert.equal(inspect(error).includes("private-source-and-cookie"), false);
    return true;
  });
  await arrived.promise;
  await b.solve(params);
  assert.equal(seen[0]?.ua, "A");
  assert.equal(seen[1]?.ua, "B");
  assert.match(String(seen[0]?.state), uuidPattern);
  assert.match(String(seen[1]?.state), uuidPattern);
  assert.notEqual(seen[0]?.state, seen[1]?.state);
  release.resolve(undefined);
  await Promise.all([a1, a2]);
  await a.solve(params);
  await a.solve(params);
  a.close();
  await b.solve(params);
  assert.deepEqual(seen.slice(2), [
    { ua: "A", state: "A-initial" },
    { ua: "A", state: "A-rotated" },
    { ua: "A", state: "A-rotated" },
    { ua: "B", state: "B-initial" },
  ]);
});

test("a truncated response body closes and preserves its state header for the next solve", {
  timeout: 5000,
}, async (t) => {
  const closed = Promise.withResolvers();
  /** @type {(string | string[] | undefined)[]} */
  const states = [];
  const baseURL = await serve(t, async (req, res) => {
    await json(req);
    states.push(req.headers["x-state-id"]);
    if (states.length === 1) {
      res.once("close", () => closed.resolve(undefined));
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Content-Length": "1024",
        Connection: "close",
        "X-State-ID": "truncated-state",
        "X-Request-ID": requestId,
      });
      res.end('{"sensor_data":"');
      return;
    }
    reply(res, { sensor_data: "continued", headers: {}, send_at: 0 });
  });
  const client = new NullgateClient({ apiKey, baseURL });
  t.after(() => client.close());
  const session = client.open({ identity, userAgent: "test" });
  await assert.rejects(session.solve(params), NullgateTransportError);
  await closed.promise;
  assert.equal(
    (await session.solve(params)).body,
    '{"sensor_data":"continued"}',
  );
  assert.match(String(states[0]), uuidPattern);
  assert.equal(states[1], "truncated-state");
});

for (const mode of ["timeout", "cancel"]) {
  test(`state rotation survives a ${mode} during response-body consumption`, {
    timeout: 5000,
  }, async (t) => {
    const reading = Promise.withResolvers();
    const closed = Promise.withResolvers();
    /** @type {(string | string[] | undefined)[]} */
    const states = [];
    const baseURL = await serve(t, async (req, res) => {
      await json(req);
      states.push(req.headers["x-state-id"]);
      if (states.length === 1) {
        res.once("close", () => closed.resolve(undefined));
        res.writeHead(200, {
          "Content-Type": "application/json",
          "X-State-ID": "body-state",
          "X-Request-ID": requestId,
        });
        res.write('{"sensor_data":"');
        return;
      }
      reply(res, { sensor_data: "continued", headers: {}, send_at: 0 });
    });
    const client = new NullgateClient({
      apiKey,
      baseURL,
      timeoutMs: mode === "timeout" ? 1000 : 30_000,
      fetch: async (input, init) => {
        const response = await fetch(input, init);
        const text = response.text.bind(response);
        response.text = () => {
          reading.resolve(undefined);
          return text();
        };
        return response;
      },
    });
    t.after(() => client.close());
    const session = client.open({ identity, userAgent: "test" });
    const controller = new AbortController();
    const reason = new Error("cancel response-body consumption");
    const rejection = assert.rejects(
      session.solve(params, { signal: controller.signal }),
      (error) => {
        if (mode === "cancel") assert.equal(error, reason);
        else {
          assert.ok(error instanceof DOMException);
          assert.equal(error.name, "TimeoutError");
        }
        return true;
      },
    );
    await reading.promise;
    if (mode === "cancel") controller.abort(reason);
    await rejection;
    await closed.promise;
    assert.equal(
      (await session.solve(params)).body,
      '{"sensor_data":"continued"}',
    );
    assert.match(String(states[0]), uuidPattern);
    assert.equal(states[1], "body-state");
  });
}

test("queued cancellation is prompt without opening a concurrent continuation request", {
  timeout: 5000,
}, async (t) => {
  const arrived = Promise.withResolvers();
  const release = Promise.withResolvers();
  let requests = 0;
  const baseURL = await serve(t, async (req, res) => {
    await json(req);
    requests += 1;
    if (requests > 1) assert.equal(req.headers["x-state-id"], "continued");
    if (requests === 1) {
      arrived.resolve(undefined);
      await release.promise;
    }
    reply(
      res,
      { sensor_data: "encoded", headers: {}, send_at: 0 },
      { "X-State-ID": "continued" },
    );
  });
  const client = new NullgateClient({ apiKey, baseURL });
  t.after(() => client.close());
  const session = client.open({ identity, userAgent: "test" });
  const first = session.solve(params);
  await arrived.promise;
  const controller = new AbortController();
  const reason = new Error("cancel queued generation");
  const otherPage = new Page(page.url, page.html);
  const cancelled = session.solve(
    new SensorParams(new Sensor(otherPage, sensor.scriptURL), "source"),
    { signal: controller.signal },
  );
  const rejection = assert.rejects(cancelled, (error) => error === reason);
  const third = session.solve(params);
  controller.abort(reason);
  await rejection;
  assert.equal(requests, 1);
  release.resolve(undefined);
  await Promise.all([first, third]);
  assert.equal(requests, 2);
});

test("closing a session cancels its live request without closing independent sessions", {
  timeout: 5000,
}, async (t) => {
  const arrived = Promise.withResolvers();
  const baseURL = await serve(t, async (req, res) => {
    await json(req);
    if (req.headers["user-agent"] === "pending") {
      arrived.resolve(undefined);
      return;
    }
    reply(res, { sensor_data: "encoded", headers: {}, send_at: 0 });
  });
  const client = new NullgateClient({ apiKey, baseURL });
  t.after(() => client.close());
  const a = client.open({ identity, userAgent: "pending" });
  const b = client.open({ identity, userAgent: "other" });
  const pending = assert.rejects(a.solve(params), NullgateClosedError);
  await arrived.promise;
  a.close();
  await pending;
  assert.equal((await b.solve(params)).body, '{"sensor_data":"encoded"}');
  client.close();
  await assert.rejects(b.solve(params), NullgateClosedError);
  assert.throws(
    () => client.open({ identity, userAgent: "other" }),
    NullgateClosedError,
  );
});

test("malformed successful bodies fail explicitly instead of manufacturing defaults", async (t) => {
  /** @type {unknown[]} */
  const malformed = [
    {},
    { sensor_data: 123, headers: {}, send_at: 0 },
    { sensor_data: "x", headers: {}, send_at: "0" },
    { sensor_data: "x", headers: { language: 1 }, send_at: 0 },
    { sensor_data: "x", headers: {}, send_at: 0 },
  ];
  let step = 0;
  const baseURL = await serve(t, async (req, res) => {
    await json(req);
    const body = malformed[step];
    step += 1;
    if (step === malformed.length) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(body));
    } else reply(res, body);
  });
  const client = new NullgateClient({ apiKey, baseURL });
  t.after(() => client.close());
  const session = client.open({ identity, userAgent: "test" });
  for (const ignored of malformed) {
    void ignored;
    await assert.rejects(session.solve(params), NullgateProtocolError);
  }
});

test("JavaScript consumers cannot accidentally pair the wrong protection and parameter variant", () => {
  const pixel = new Pixel(page, "https://target.example/akam/13/abc", "12");
  const sbsd = new Sbsd(page, `https://target.example/sbsd?v=${identity}`);
  for (const [Params, protection] of [
    [PixelParams, sensor],
    [SensorParams, pixel],
    [SbsdParams, sensor],
    [PixelParams, sbsd],
  ]) {
    assert.ok(typeof Params === "function");
    assert.throws(
      () => Reflect.construct(Params, [protection, "source"]),
      TypeError,
    );
  }
});

test("raw action values are rejected before private input text can leave the process", async () => {
  let contacted = false;
  const client = new NullgateClient({
    apiKey,
    fetch: async () => {
      contacted = true;
      throw new Error("Unexpected request");
    },
  });
  const session = client.open({ identity, userAgent: "test" });
  try {
    const unsafe = Reflect.construct(SensorParams, [
      sensor,
      "source",
      {
        actions: [{ type: "input", target: 0, value: "private-password" }],
      },
    ]);
    await assert.rejects(session.solve(unsafe), (error) => {
      assert.ok(error instanceof TypeError);
      assert.equal(inspect(error).includes("private-password"), false);
      return true;
    });
    assert.equal(contacted, false);
  } finally {
    client.close();
  }
});
