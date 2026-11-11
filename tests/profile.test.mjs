import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";
import test from "node:test";
import { Nullgate } from "@nullgate/sdk";
import { WebSocketServer } from "ws";

const requestId = "11111111222243338444555555555556";
const profileId = "11111111-2222-4333-8444-555555555555";
const tags = "https://tags.example/tags.js?org_id=org&session_id=visit";
/**
 * @param {import('node:test').TestContext} t
 * @param {(socket: import('ws').WebSocket, message: Record<string, any>, request: import('node:http').IncomingMessage) => void} receive
 */
async function serve(t, receive) {
  /** @type {unknown[]} */ const failures = [];
  const server = createServer();
  const sockets = new WebSocketServer({ server });
  sockets.on("connection", (socket, request) =>
    socket.on("message", (data) => {
      try {
        receive(socket, JSON.parse(data.toString()), request);
      } catch (error) {
        failures.push(error);
        socket.terminate();
      }
    }),
  );
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address === "object");
  t.after(async () => {
    for (const socket of sockets.clients) socket.terminate();
    const closed = once(sockets, "close");
    sockets.close();
    await closed;
    const stopped = once(server, "close");
    server.close();
    await stopped;
    assert.deepEqual(failures, []);
  });
  return `http://127.0.0.1:${address.port}`;
}
/** @param {import('ws').WebSocket} socket */
function hello(socket) {
  socket.send(
    JSON.stringify({
      type: "hello",
      session: "continued",
      request_id: requestId,
    }),
  );
}
/** @param {Nullgate} ng */
function page(ng) {
  return ng
    .session({ userAgent: "browser", profile: profileId })
    .page("https://shop.example/login", `<script src="${tags}"></script>`);
}

test("profile sends the flat start, preserves binary HTTP, continues session and acknowledges departure", async (t) => {
  const bytes = Buffer.from([0, 255, 128, 13, 10]);
  let starts = 0;
  let departures = 0;
  const baseUrl = await serve(t, (socket, message, request) => {
    if (message.type === "start") {
      assert.equal(request.url, "/threatmetrix/profile");
      assert.equal(request.headers.authorization, "Bearer fake");
      assert.equal(request.headers["x-state-id"], undefined);
      assert.equal(message.profile, profileId);
      assert.equal(message.user_agent, "browser");
      assert.equal(message.session, starts++ === 0 ? null : "continued");
      assert.equal(message.url, "https://shop.example/login");
      assert.equal(message.tags_url, tags);
      assert.equal(message.website, undefined);
      assert.equal(typeof message.at_ms, "number");
      hello(socket);
      socket.send(
        JSON.stringify({
          type: "http",
          id: 1,
          request: {
            role: "tags",
            url: tags,
            method: "POST",
            headers: {},
            body: bytes.toString("base64"),
            credentials: "omit",
          },
        }),
      );
    } else if (message.type === "http.result") {
      assert.equal(message.response.status, 503);
      assert.equal(message.response.body, bytes.toString("base64"));
      assert.equal(typeof message.response.received_at_ms, "number");
      socket.send(JSON.stringify({ type: "ready", request_id: requestId }));
      socket.send(JSON.stringify({ type: "collected", request_id: requestId }));
    } else if (message.type === "pagehide") {
      assert.equal(message.persisted, true);
      departures++;
      socket.send(JSON.stringify({ type: "pagehide.done" }));
    } else if (message.type === "close") socket.close();
  });
  const document = page(new Nullgate("fake", { baseUrl }));
  /** @type {import('@nullgate/sdk').TargetFetch} */
  const send = async (request) => {
    assert.equal(request.credentials, "omit");
    assert.deepEqual(request.body, bytes);
    return { status: 503, headers: { nonce: "observed" }, body: bytes };
  };
  const live = await document.threatmetrix({ send });
  await live.waitForCollected();
  await live.pagehide({ persisted: true });
  await live[Symbol.asyncDispose]();
  const next = await document.threatmetrix({ send });
  await next.close();
  assert.equal(starts, 2);
  assert.equal(departures, 1);
});

for (const failure of [
  "invalid_key",
  "insufficient_balance",
  "session_busy",
  "invalid_page",
  "unavailable",
]) {
  test(`profile maps ${failure} from the public error envelope`, async (t) => {
    const baseUrl = await serve(t, (socket) =>
      socket.send(
        JSON.stringify({
          type: "error",
          code: failure,
          message: "Safe explanation",
          request_id: requestId,
        }),
      ),
    );
    await assert.rejects(
      page(new Nullgate("fake", { baseUrl })).threatmetrix({
        send: async () => assert.fail("must not send"),
      }),
      { code: failure, message: "Safe explanation", requestId },
    );
  });
}

for (const request of [
  {
    role: "tags",
    url: tags,
    method: "GET",
    headers: { Cookie: "secret" },
    body: null,
    credentials: "omit",
  },
  {
    role: "tags",
    url: "https://user:secret@tags.example/",
    method: "GET",
    headers: {},
    body: null,
    credentials: "include",
  },
  {
    role: "tags",
    url: tags,
    method: "POST",
    headers: {},
    body: "bad base64",
    credentials: "include",
  },
]) {
  test(`refuses unsafe target commands: ${request.url} ${request.body}`, async (t) => {
    const baseUrl = await serve(t, (socket) => {
      hello(socket);
      socket.send(JSON.stringify({ type: "http", id: 1, request }));
    });
    await assert.rejects(
      page(new Nullgate("fake", { baseUrl })).threatmetrix({
        send: async () => assert.fail("must not send"),
      }),
      { code: "protocol_error" },
    );
  });
}

test("target transport errors send only sanitized cause facts", async (t) => {
  const baseUrl = await serve(t, (socket, message) => {
    if (message.type === "start") {
      hello(socket);
      socket.send(
        JSON.stringify({
          type: "http",
          id: 1,
          request: {
            role: "tags",
            url: tags,
            method: "GET",
            headers: {},
            body: null,
            credentials: "include",
          },
        }),
      );
    } else if (message.type === "http.error") {
      assert.deepEqual(message, {
        type: "http.error",
        id: 1,
        detail: "Target request failed",
        error: { kind: "connection", type: "Error", code: "ECONNREFUSED" },
      });
      socket.send(
        JSON.stringify({
          type: "error",
          code: "upstream_error",
          message: "Target failed",
          request_id: requestId,
        }),
      );
    }
  });
  await assert.rejects(
    page(new Nullgate("fake", { baseUrl })).threatmetrix({
      send: async () => {
        throw Object.assign(new Error("private proxy password"), {
          code: "ECONNREFUSED",
        });
      },
    }),
    { code: "upstream_error" },
  );
});

test("ICE gather failure reports null and permits the live profile to proceed", async (t) => {
  const baseUrl = await serve(t, (socket, message) => {
    if (message.type === "start") {
      hello(socket);
      socket.send(
        JSON.stringify({
          type: "ice",
          id: 1,
          server: {
            host: "127.0.0.1",
            port: 1,
            transport: "tcp",
            username: "fake",
            credential: "fake",
          },
        }),
      );
    } else if (message.type === "ice.result") {
      assert.deepEqual(message, {
        type: "ice.result",
        id: 1,
        observation: null,
      });
      socket.send(JSON.stringify({ type: "ice.release", id: 1 }));
      socket.send(JSON.stringify({ type: "ready", request_id: requestId }));
    } else if (message.type === "close") socket.close();
  });
  const live = await page(
    new Nullgate("fake", { baseUrl, timeout: 1 }),
  ).threatmetrix({ send: async () => assert.fail("no HTTP command") });
  await live.close();
});

test("profile retries maintenance handshakes at most twice", async (t) => {
  const server = createServer();
  let attempts = 0;
  server.on("upgrade", (_request, socket) => {
    attempts++;
    const body = JSON.stringify({
      code: "maintenance",
      message: "Updating",
      request_id: requestId,
    });
    socket.end(
      `HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nRetry-After: 0\r\nConnection: close\r\n\r\n${body}`,
    );
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address === "object");
  t.after(async () => {
    const stopped = once(server, "close");
    server.close();
    await stopped;
  });
  await assert.rejects(
    page(
      new Nullgate("fake", { baseUrl: `http://127.0.0.1:${address.port}` }),
    ).threatmetrix({ send: async () => assert.fail("must not send") }),
    { code: "maintenance", status: 503 },
  );
  assert.equal(attempts, 3);
});

test("closing a live profile aborts pending target work", async (t) => {
  const entered = Promise.withResolvers();
  const cancelled = Promise.withResolvers();
  let departures = 0;
  const baseUrl = await serve(t, (socket, message) => {
    if (message.type === "start") {
      hello(socket);
      socket.send(JSON.stringify({ type: "ready", request_id: requestId }));
      socket.send(
        JSON.stringify({
          type: "http",
          id: 1,
          request: {
            role: "tags",
            url: tags,
            method: "GET",
            headers: {},
            body: null,
            credentials: "include",
          },
        }),
      );
    } else if (message.type === "pagehide") departures++;
    else if (message.type === "close") socket.close();
  });
  const live = await page(new Nullgate("fake", { baseUrl })).threatmetrix({
    send: async (request) => {
      entered.resolve(undefined);
      await new Promise((resolve) =>
        request.signal.addEventListener("abort", resolve, { once: true }),
      );
      cancelled.resolve(undefined);
      throw request.signal.reason;
    },
  });
  await entered.promise;
  await live.close();
  await cancelled.promise;
  assert.equal(departures, 0);
  assert.equal(live.error, undefined);
});

for (const scriptUrl of [undefined, "/explicit-tags.js"]) {
  test(`ThreatMetrix accepts module discovery and relative override ${scriptUrl}`, async (t) => {
    const baseUrl = await serve(t, (socket, message) => {
      if (message.type === "start") {
        assert.equal(
          message.tags_url,
          scriptUrl === undefined
            ? tags
            : "https://shop.example/explicit-tags.js",
        );
        hello(socket);
        socket.send(JSON.stringify({ type: "ready", request_id: requestId }));
      } else if (message.type === "close") socket.close();
    });
    const document = new Nullgate("fake", { baseUrl })
      .session({ userAgent: "browser" })
      .page(
        "https://shop.example/login",
        `<script type="module" src="${tags}"></script>`,
      );
    const live = await document.threatmetrix({
      send: async () => assert.fail("must not send"),
      ...(scriptUrl === undefined ? {} : { scriptUrl }),
    });
    await live.close();
  });
}

const collectors = [
  {
    url: "https://dfme.kleinanzeigen.de:443/wrapper.js?opaque=%2f+%2B&x=two&empty=",
    orgId: "181rzcrc",
    sessionId: "observed-visit",
  },
  {
    url: "http://collector.example:0/profile",
    orgId: "org",
    sessionId: "visit",
  },
  {
    url: "https://collector.example:/profile",
    orgId: "org",
    sessionId: "visit",
  },
  { url: "https://collector.example/\ufeff", orgId: " \r\n", sessionId: "\t " },
];
for (const collector of collectors) {
  test(`explicit collector preserves the server start shape: ${collector.url}`, async (t) => {
    const baseUrl = await serve(t, (socket, message) => {
      if (message.type === "start") {
        assert.equal(Object.hasOwn(message, "tags_url"), false);
        assert.deepEqual(message.collector, {
          url: collector.url,
          org_id: collector.orgId,
          session_id: collector.sessionId,
        });
        hello(socket);
        socket.send(JSON.stringify({ type: "ready", request_id: requestId }));
      } else if (message.type === "close") socket.close();
    });
    // Explicit collectors must bypass even ambiguous automatic tags discovery.
    const document = new Nullgate("fake", { baseUrl })
      .session({ userAgent: "browser" })
      .page(
        "https://shop.example/login",
        `<script src="${tags}"></script><script src="${tags}&other=1"></script>`,
      );
    const live = await document.threatmetrix({
      send: async () => assert.fail("must not send"),
      collector,
      scriptUrl: null,
    });
    await live.close();
  });
}

const invalidCollectors = [
  undefined,
  false,
  [],
  {},
  { url: "https://collector.example/profile", orgId: "org" },
  { url: "https://collector.example/profile", sessionId: "visit" },
  { orgId: "org", sessionId: "visit" },
  { url: "https://collector.example/profile", orgId: "", sessionId: "visit" },
  { url: "https://collector.example/profile", orgId: 1, sessionId: "visit" },
  { url: "https://collector.example/profile", orgId: "org", sessionId: "" },
  { url: "https://collector.example/profile", orgId: "org", sessionId: 1 },
  {
    url: "https://collector.example/profile",
    orgId: "org",
    sessionId: "visit",
    extra: "unsupported",
  },
  ...[
    "",
    "/relative",
    "//collector.example/profile",
    "ftp://collector.example/profile",
    "https://user:password@collector.example/profile",
    "https://@collector.example/profile",
    "https://collector.example/profile#",
    "https://collector.example/profile\\path",
    "https://collector.example/white space",
    "https://collector.example/\u0085",
    "https://collector.example/\u001c",
    "https://collector.example:-1/profile",
    "https://collector.example:65536/profile",
    "https://collector.example:invalid/profile",
  ].map((url) => ({ url, orgId: "org", sessionId: "visit" })),
];
for (const [index, collector] of invalidCollectors.entries()) {
  test(`invalid collector ${index} fails before starting a profile`, async (t) => {
    const baseUrl = await serve(t, () =>
      assert.fail("must not start a profile"),
    );
    const document = new Nullgate("fake", { baseUrl })
      .session({ userAgent: "browser" })
      .page("https://shop.example/login", "");
    await assert.rejects(
      document.threatmetrix({
        send: async () => assert.fail("must not send"),
        collector: /** @type {any} */ (collector),
      }),
      {
        code:
          collector === undefined ? "protection_not_found" : "invalid_request",
      },
    );
  });
}
for (const scriptUrl of ["", "/tags.js", tags]) {
  test(`collector and explicit scriptUrl ${JSON.stringify(scriptUrl)} are mutually exclusive`, async () => {
    const document = page(new Nullgate("fake"));
    await assert.rejects(
      document.threatmetrix({
        send: async () => assert.fail("must not send"),
        collector: {
          url: "https://collector.example/profile",
          orgId: "org",
          sessionId: "visit",
        },
        scriptUrl,
      }),
      { code: "invalid_request" },
    );
  });
}
test("null collector selects the tags entry instead", async (t) => {
  const baseUrl = await serve(t, (socket, message) => {
    if (message.type === "start") {
      assert.equal(Object.hasOwn(message, "collector"), false);
      assert.equal(message.tags_url, tags);
      hello(socket);
      socket.send(JSON.stringify({ type: "ready", request_id: requestId }));
    } else if (message.type === "close") socket.close();
  });
  const live = await page(new Nullgate("fake", { baseUrl })).threatmetrix({
    send: async () => assert.fail("must not send"),
    collector: null,
  });
  await live.close();
});
