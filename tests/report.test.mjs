import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";
import { json } from "node:stream/consumers";
import test from "node:test";
import {
  NullgateClient,
  NullgateClosedError,
  Page,
  Sensor,
  SensorParams,
} from "@nullgate/sdk";

const identity = "11111111-2222-4333-8444-555555555555";
const requestId = "0123456789abcdef0123456789abcdef";
const params = new SensorParams(
  new Sensor(
    new Page("https://target.example/", "private HTML"),
    "https://target.example/sensor",
  ),
  "private JS",
);

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

test("solution reports send only request_id, never generation credentials, cookies, or state", async (t) => {
  let reports = 0;
  let redirected = false;
  const baseURL = await serve(t, async (req, res) => {
    if (req.url?.includes("/generate")) {
      await json(req);
      res.writeHead(200, {
        "X-Request-ID": requestId,
        "X-State-ID": "private-state",
        "Set-Cookie": "private-cookie=secret",
      });
      res.end(
        JSON.stringify({ sensor_data: "encoded", headers: {}, send_at: -1 }),
      );
      return;
    }
    if (req.url === "/redirected") redirected = true;
    assert.equal(req.url, "/report");
    assert.equal(req.headers.authorization, undefined);
    assert.equal(req.headers["x-state-id"], undefined);
    assert.equal(req.headers.cookie, undefined);
    const body = await json(req);
    assert.deepEqual(body, {
      request_id: reports === 0 ? requestId : "unknown-issued-id",
    });
    reports += 1;
    if (reports === 1) res.writeHead(200).end('{"ok":true}');
    else if (reports === 2) res.writeHead(503).end();
    else res.writeHead(302, { Location: "/redirected" }).end();
  });
  const client = new NullgateClient({
    apiKey: "ng_private-key",
    baseURL,
    analyticsURL: baseURL,
  });
  t.after(() => client.close());
  const session = client.open({ identity, userAgent: "private UA" });
  const solution = await session.solve(params);
  assert.equal(await solution.report(), true);
  assert.equal(await client.report("unknown-issued-id"), false);
  assert.equal(await client.report("unknown-issued-id"), false);
  assert.equal(redirected, false);
  assert.equal(reports, 3);
});

test("native network failure and a bounded report timeout return false without retry", {
  timeout: 5000,
}, async (t) => {
  let attempts = 0;
  const baseURL = await serve(t, (req) => {
    attempts += 1;
    if (attempts === 1) req.socket.destroy();
    // The second request deliberately receives no response until the SDK timeout.
  });
  const client = new NullgateClient({
    apiKey: "ng_test",
    analyticsURL: baseURL,
    reportTimeoutMs: 100,
  });
  t.after(() => client.close());
  assert.equal(await client.report(requestId), false);
  assert.equal(attempts, 1);
  assert.equal(await client.report(requestId), false);
  assert.equal(attempts, 2);
});

test("caller cancellation and closed-client errors are never swallowed as report success", {
  timeout: 5000,
}, async (t) => {
  const arrived = Promise.withResolvers();
  const baseURL = await serve(t, async (req) => {
    await json(req);
    arrived.resolve(undefined);
  });
  const client = new NullgateClient({
    apiKey: "ng_test",
    analyticsURL: baseURL,
  });
  t.after(() => client.close());
  const controller = new AbortController();
  const reason = new Error("cancel report");
  const reported = client.report(requestId, { signal: controller.signal });
  const rejected = assert.rejects(reported, (error) => error === reason);
  await arrived.promise;
  controller.abort(reason);
  await rejected;
  client.close();
  await assert.rejects(client.report(requestId), NullgateClosedError);
});

test("programming and malformed-configuration errors propagate", async () => {
  assert.throws(
    () => new NullgateClient({ apiKey: "ng_test", analyticsURL: "not-a-url" }),
    TypeError,
  );
  const problem = new TypeError("caller transport programming bug");
  const client = new NullgateClient({
    apiKey: "ng_test",
    fetch: async () => {
      throw problem;
    },
  });
  try {
    await assert.rejects(
      client.report(requestId),
      (error) => error === problem,
    );
    await assert.rejects(client.report(""), TypeError);
  } finally {
    client.close();
  }
});

test("wait uses absolute send_at and preserves cancellation, including already-ready solutions", {
  timeout: 5000,
}, async (t) => {
  let sendAt = -1;
  const baseURL = await serve(t, async (req, res) => {
    await json(req);
    res.writeHead(200, { "X-Request-ID": requestId });
    res.end(
      JSON.stringify({ sensor_data: "encoded", headers: {}, send_at: sendAt }),
    );
  });
  const client = new NullgateClient({ apiKey: "ng_test", baseURL });
  t.after(() => client.close());
  const session = client.open({ identity, userAgent: "test" });
  const past = await session.solve(params);
  await past.wait();
  const controller = new AbortController();
  controller.abort(new Error("already cancelled"));
  await assert.rejects(
    past.wait({ signal: controller.signal }),
    /already cancelled/,
  );
  sendAt = (Date.now() + 100) / 1000;
  const future = await session.solve(params);
  await future.wait();
  assert.ok(Date.now() >= future.sendAt * 1000);
  sendAt = (Date.now() + 60_000) / 1000;
  const waiting = await session.solve(params);
  const cancellation = new AbortController();
  const rejected = assert.rejects(
    waiting.wait({ signal: cancellation.signal }),
    { name: "AbortError" },
  );
  cancellation.abort();
  await rejected;
});
