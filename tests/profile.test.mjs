import assert from "node:assert/strict";
import dns from "node:dns/promises";
import { once } from "node:events";
import { createServer } from "node:http";
import { syncBuiltinESMExports } from "node:module";
import { Socket } from "node:net";
import test from "node:test";
import { setImmediate as nextTurn } from "node:timers/promises";
import { inspect } from "node:util";
import {
  NullgateAPIError,
  NullgateClient,
  NullgateProtocolError,
  Page,
  Target,
  ThreatMetrix,
  ThreatMetrixCollector,
  ThreatMetrixParams,
} from "@nullgate/sdk";
import { WebSocketServer } from "ws";

const identity = "11111111-2222-4333-8444-555555555555";
const requestId = "11111111222243338444555555555556";
const nextState = "11111111-2222-4333-8444-555555555557";
const page = new Page("https://target.example/login", "<html>document</html>");
const params = new ThreatMetrixParams(
  new ThreatMetrix(
    page,
    "https://tags.example/tags.js?org_id=org&session_id=document",
  ),
);
const collectorURL =
  "https://collector.example/fp/opaque?org_id=not-the-org&session_id=not-the-session&x=%2f+%2B&x=two&empty=";

/**
 * @param {import('node:test').TestContext} t
 * @param {(socket: import('ws').WebSocket, message: Record<string, unknown>, request: import('node:http').IncomingMessage) => void} receive
 * @param {(request: import('node:http').IncomingMessage, response: import('node:http').ServerResponse) => void} [http]
 */
async function serve(t, receive, http) {
  /** @type {unknown[]} */
  const failures = [];
  const server = createServer(
    http ?? ((_request, response) => response.writeHead(404).end()),
  );
  const sockets = new WebSocketServer({ server });
  sockets.on("connection", (socket, request) => {
    socket.on("message", (data) => {
      try {
        receive(socket, JSON.parse(data.toString()), request);
      } catch (error) {
        failures.push(error);
        socket.terminate();
      }
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address === "object");
  t.after(async () => {
    for (const socket of sockets.clients) socket.terminate();
    const socketsClosed = once(sockets, "close");
    sockets.close();
    await socketsClosed;
    const closed = once(server, "close");
    server.closeAllConnections();
    server.close();
    await closed;
    assert.deepEqual(failures, []);
  });
  return `http://127.0.0.1:${address.port}`;
}

/** @param {import('ws').WebSocket} socket */
function hello(socket) {
  socket.send(
    JSON.stringify({
      type: "hello",
      state_id: nextState,
      request_id: requestId,
    }),
  );
}

/**
 * @param {import('node:test').TestContext} t
 * @param {ThreatMetrix | ThreatMetrixCollector} protection
 */
async function profileLifecycle(t, protection) {
  const bytes = Buffer.from([0, 255, 128, 13, 10]);
  let completedAt = 0;
  let departures = 0;
  let continuations = 0;
  /** @type {string} */
  let baseURL;
  baseURL = await serve(
    t,
    (socket, message, request) => {
      if (message.type === "start") {
        assert.equal(request.url, `/v1/${identity}/profile`);
        assert.equal(request.headers.authorization, "Bearer ng_private-key");
        assert.equal(request.headers["user-agent"], "profile UA");
        if (continuations === 0)
          assert.match(
            String(request.headers["x-state-id"]),
            /^[0-9a-f-]{36}$/i,
          );
        else assert.equal(request.headers["x-state-id"], nextState);
        continuations += 1;
        assert.deepEqual(message.website, {
          url: page.url,
          html: page.html,
          document_id: page.documentId,
          started_at_ms: page.startedAtMs,
        });
        assert.equal(message.timezone, "Europe/Berlin");
        if (protection instanceof ThreatMetrixCollector) {
          assert.equal(Object.hasOwn(message, "tags_url"), false);
          assert.deepEqual(message.collector, {
            url: collectorURL,
            org_id: "explicit-org",
            session_id: "explicit-session",
          });
        } else {
          assert.equal(Object.hasOwn(message, "collector"), false);
          assert.equal(message.tags_url, protection.scriptURL);
        }
        assert.equal(JSON.stringify(message).includes("ng_private-key"), false);
        if (continuations === 1) {
          const inputs =
            /** @type {import('@nullgate/sdk').PreparedInput[]} */ (
              message.inputs
            );
          assert.deepEqual(inputs[0]?.attributes, {
            name: "credential",
            type: "password",
          });
          assert.deepEqual(inputs[0]?.value.counts, [4, 3, 1, 0]);
          assert.equal(JSON.stringify(message).includes("s🔑&"), false);
          assert.equal(
            JSON.stringify(message).includes("changed-after-start"),
            false,
          );
          assert.deepEqual(message.actions, [{ type: "click", x: 2, y: 3 }]);
        } else {
          assert.deepEqual(message.inputs, []);
          assert.deepEqual(message.actions, []);
        }
        hello(socket);
        socket.send(
          JSON.stringify({
            type: "http",
            id: 1,
            request: {
              role:
                protection instanceof ThreatMetrixCollector
                  ? "collector"
                  : "tags",
              url: `${baseURL}/binary`,
              method: "POST",
              headers: { "User-Agent": "profile UA" },
              body: bytes.toString("base64"),
              credentials: "omit",
            },
          }),
        );
      } else if (message.type === "http.result") {
        assert.equal(message.id, 1);
        const response = /** @type {Record<string, unknown>} */ (
          message.response
        );
        assert.equal(response.status, 503);
        assert.equal(response.body, bytes.toString("base64"));
        assert.equal(typeof response.received_at_ms, "number");
        assert.ok(Number(response.received_at_ms) >= completedAt);
        assert.ok(Number(response.received_at_ms) <= Date.now());
        socket.send(JSON.stringify({ type: "ready", request_id: requestId }));
      } else if (message.type === "pagehide") {
        departures += 1;
        assert.equal(message.at_ms, 123456.75);
        assert.equal(message.persisted, true);
        socket.send(
          JSON.stringify({ type: "collected", request_id: requestId }),
        );
        socket.send(JSON.stringify({ type: "pagehide.done" }));
      } else if (message.type === "close") socket.close();
      else throw new Error("Unexpected client message");
    },
    (request, response) => {
      assert.equal(request.url, "/binary");
      assert.equal(request.headers.cookie, undefined);
      /** @type {Buffer[]} */
      const chunks = [];
      request.on("data", (chunk) => chunks.push(chunk));
      request.on("end", () => {
        assert.deepEqual(Buffer.concat(chunks), bytes);
        response.writeHead(503, { "tmx-nonce": "actual-nonce" }).end(bytes);
        completedAt = Date.now();
      });
    },
  );
  const client = new NullgateClient({
    apiKey: "ng_private-key",
    profileBaseURL: baseURL,
  });
  t.after(() => client[Symbol.asyncDispose]());
  const session = client.open({
    identity,
    userAgent: "profile UA",
    timezone: "Europe/Berlin",
  });
  const target = new Target(
    async (request) => {
      assert.equal(request.credentials, "omit");
      assert.equal(
        request.role,
        protection instanceof ThreatMetrixCollector ? "collector" : "tags",
      );
      const response = await fetch(request.url, {
        method: request.method,
        headers: request.headers,
        body: request.body === null ? null : new Uint8Array(request.body),
        credentials: request.credentials,
        redirect: "manual",
        signal: request.signal,
      });
      return {
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body: new Uint8Array(await response.arrayBuffer()),
      };
    },
    { proxy: null },
  );
  const field = { name: "credential", type: "password", value: "s🔑&" };
  const click = { type: "click", x: 2, y: 3 };
  const pending = session.profile(
    new ThreatMetrixParams(protection, {
      inputs: [field],
      actions: [click],
    }),
    target,
  );
  field.value = "changed-after-start";
  click.x = 999;
  const profile = await pending;
  assert.equal(profile.requestId, requestId);
  assert.equal(profile.isCollected, false);
  await profile.pagehide({ atMs: 123456.75, persisted: true });
  await profile.waitForCollected();
  assert.equal(profile.isCollected, true);
  assert.equal(profile.isClosed, false);
  await profile.close();
  const next = await session.profile(
    new ThreatMetrixParams(protection, { inputs: [], actions: [] }),
    target,
  );
  await next.close();
  assert.equal(continuations, 2);
  assert.equal(departures, 1);
}

test("tags profiles preserve HTTP failures, observations, state, and departure", (t) =>
  profileLifecycle(t, params.protection));
test("direct collector profiles preserve their explicit session and parent document", (t) =>
  profileLifecycle(
    t,
    new ThreatMetrixCollector(
      page,
      collectorURL,
      "explicit-org",
      "explicit-session",
    ),
  ));

test("direct collectors reject malformed URLs, IDs, and ambiguous protection objects", () => {
  for (const url of [
    "",
    "/relative",
    "ftp://collector.example/fp",
    "https:///missing-authority",
    "https://collector.example:65536/fp",
    "https://user:password@collector.example/fp",
    "https://@collector.example/fp",
    "https://collector.example/fp#fragment",
    "https://collector.example/fp#",
    "https://collector.example/fp\n",
    "https://collector.example/a b",
    "https://collector.example\\fp",
    null,
    42,
  ]) {
    assert.throws(
      // @ts-expect-error Runtime validation also rejects non-string URLs.
      () => new ThreatMetrixCollector(page, url, "org", "session"),
      TypeError,
    );
  }
  for (const id of ["", " \t", "line\rbreak", "line\nbreak", null, 42]) {
    assert.throws(
      // @ts-expect-error Runtime validation also rejects non-string organization IDs.
      () => new ThreatMetrixCollector(page, collectorURL, id, "session"),
      TypeError,
    );
    assert.throws(
      // @ts-expect-error Runtime validation also rejects non-string session IDs.
      () => new ThreatMetrixCollector(page, collectorURL, "org", id),
      TypeError,
    );
  }
  assert.throws(
    () =>
      new ThreatMetrixParams({
        // @ts-expect-error An unvalidated, ambiguous wire object is not a protection.
        tags_url: params.protection.scriptURL,
        collector: {
          url: collectorURL,
          org_id: "org",
          session_id: "session",
        },
      }),
    TypeError,
  );
});

test("a duplicate cross-kind ID fails the active profile and cancels its pending target HTTP", async (t) => {
  /** @type {PromiseWithResolvers<import('ws').WebSocket>} */
  const connected = Promise.withResolvers();
  const fetching = Promise.withResolvers();
  const cancelled = Promise.withResolvers();
  const baseURL = await serve(t, (socket, message) => {
    if (message.type === "start") {
      hello(socket);
      socket.send(JSON.stringify({ type: "ready", request_id: requestId }));
      connected.resolve(socket);
    }
  });
  const client = new NullgateClient({
    apiKey: "ng_key",
    profileBaseURL: baseURL,
  });
  t.after(() => client[Symbol.asyncDispose]());
  const session = client.open({ identity, userAgent: "profile UA" });
  const target = new Target(
    async (request) => {
      fetching.resolve(undefined);
      request.signal.addEventListener(
        "abort",
        () => cancelled.resolve(undefined),
        { once: true },
      );
      await once(request.signal, "abort");
      throw request.signal.reason;
    },
    { proxy: null },
  );
  const profile = await session.profile(params, target);
  const socket = await connected.promise;
  socket.send(
    JSON.stringify({
      type: "http",
      id: 7,
      request: {
        role: "tags",
        url: "http://target.example/tags.js",
        method: "GET",
        headers: {},
        body: null,
        credentials: "include",
      },
    }),
  );
  await fetching.promise;
  socket.send(JSON.stringify({ type: "ice", id: 7, server: {} }));
  await assert.rejects(profile.waitForCollected(), (error) => {
    assert.ok(error instanceof NullgateProtocolError);
    assert.equal(error.requestId, requestId);
    return true;
  });
  await cancelled.promise;
  await profile.close();
  assert.equal(profile.isClosed, true);
});

test("AbortSignal closes an active profile without synthesizing pagehide", async (t) => {
  let departures = 0;
  const disconnected = Promise.withResolvers();
  const baseURL = await serve(t, (socket, message) => {
    if (message.type === "start") {
      socket.once("close", () => disconnected.resolve(undefined));
      hello(socket);
      socket.send(JSON.stringify({ type: "ready", request_id: requestId }));
    } else if (message.type === "pagehide") departures += 1;
  });
  const client = new NullgateClient({
    apiKey: "ng_key",
    profileBaseURL: baseURL,
  });
  t.after(() => client[Symbol.asyncDispose]());
  const session = client.open({ identity, userAgent: "profile UA" });
  const target = new Target(
    async () => {
      throw new Error("No target requests expected");
    },
    { proxy: null },
  );
  const abort = new AbortController();
  const profile = await session.profile(params, target, {
    signal: abort.signal,
  });
  const reason = new Error("caller cancelled");
  abort.abort(reason);
  await assert.rejects(profile.waitForCollected(), (error) => error === reason);
  await profile.close();
  await disconnected.promise;
  assert.equal(departures, 0);
});

for (const outcome of ["resolved", "rejected"]) {
  test(`profile close cancels a stalled OS lookup before its late ${outcome} outcome`, {
    timeout: 5000,
  }, async (t) => {
    const querying = Promise.withResolvers();
    /** @type {PromiseWithResolvers<import('node:dns').LookupAddress>} */
    const query = Promise.withResolvers();
    const lookup = t.mock.method(
      dns,
      "lookup",
      /** @param {string} host */
      (host) => {
        assert.equal(host, "stalled-turn.example");
        querying.resolve(undefined);
        return query.promise;
      },
    );
    syncBuiltinESMExports();
    const settleQuery = () => {
      if (outcome === "resolved")
        query.resolve({ address: "127.0.0.1", family: 4 });
      else query.reject(new Error("late OS lookup failure"));
    };
    t.after(async () => {
      settleQuery();
      await query.promise.catch(() => undefined);
      lookup.mock.restore();
      syncBuiltinESMExports();
    });
    /** @type {unknown[]} */
    const messages = [];
    const baseURL = await serve(t, (socket, message) => {
      if (message.type === "start") {
        hello(socket);
        socket.send(JSON.stringify({ type: "ready", request_id: requestId }));
        socket.send(
          JSON.stringify({
            type: "ice",
            id: 1,
            server: {
              host: "stalled-turn.example",
              port: 3478,
              transport: "tcp",
              username: "turn-user",
              credential: "turn-secret",
            },
          }),
        );
      } else {
        messages.push(message.type);
        if (message.type === "close") socket.close();
      }
    });
    const client = new NullgateClient({
      apiKey: "ng_key",
      profileBaseURL: baseURL,
    });
    t.after(() => client[Symbol.asyncDispose]());
    const session = client.open({ identity, userAgent: "profile UA" });
    const target = new Target(
      async () => {
        throw new Error("No target HTTP requests expected");
      },
      { proxy: null },
    );
    const profile = await session.profile(params, target);
    await querying.promise;
    const connect = t.mock.method(Socket.prototype, "connect", () => {
      throw new Error("No target dial expected after cancellation");
    });
    await profile.close();
    assert.equal(profile.isClosed, true);
    assert.equal(profile.error, undefined);
    settleQuery();
    await query.promise.catch(() => undefined);
    // Drain the late resolver's reactions, not a wall-clock cancellation deadline.
    await nextTurn();
    assert.equal(connect.mock.callCount(), 0);
    assert.deepEqual(messages, ["close"]);
    connect.mock.restore();
  });
}

test("service failures preserve typed status and request ID without exposing detail", async (t) => {
  const baseURL = await serve(t, (socket, message) => {
    if (message.type === "start") {
      hello(socket);
      socket.send(
        JSON.stringify({
          type: "error",
          status: 422,
          detail: "private validation",
          request_id: requestId,
        }),
      );
    }
  });
  const client = new NullgateClient({
    apiKey: "ng_key",
    profileBaseURL: baseURL,
  });
  t.after(() => client[Symbol.asyncDispose]());
  const session = client.open({ identity, userAgent: "profile UA" });
  const target = new Target(
    async () => {
      throw new Error("No target requests expected");
    },
    { proxy: null },
  );
  await assert.rejects(session.profile(params, target), (error) => {
    assert.ok(error instanceof NullgateAPIError);
    assert.equal(error.statusCode, 422);
    assert.equal(error.requestId, requestId);
    assert.equal(inspect(error).includes("private validation"), false);
    return true;
  });
});

test("Target requires an explicit valid local route and keeps proxy credentials private", () => {
  /** @type {import('@nullgate/sdk').TargetFetch} */
  const fetch = async () => {
    throw new Error("Not called");
  };
  const target = new Target(fetch, {
    proxy: "socks5://private-user:private-password@proxy.example:1080",
  });
  assert.equal(inspect(target).includes("private-password"), false);
  assert.throws(
    () =>
      new Target(fetch, {
        proxy: "socks5h://private-user:private-password@proxy.example",
      }),
    (error) => {
      assert.ok(error instanceof TypeError);
      assert.equal(inspect(error).includes("private-password"), false);
      return true;
    },
  );
});

for (const negotiated of [false, true]) {
  test(`target transport metadata requires negotiated hello: ${negotiated}`, async (t) => {
    const localError = Object.assign(
      new Error("https://user:private@host/?cookie=private"),
      {
        code: "ECONNREFUSED",
      },
    );
    const metadata = {
      code: "CLIENT_TRANSPORT_ERROR",
      origin: "client",
      message: "Target transport failed",
      retryable: null,
      stage: "target_http",
      command_id: 1,
      target: { role: "tags", method: "GET", host: "tags.example" },
      cause: { kind: "connection", type: "Error", code: "ECONNREFUSED" },
    };
    const endpoint = await serve(t, (socket, message, request) => {
      if (message.type === "start") {
        assert.equal(request.headers["x-nullgate-error-format"], "1");
        socket.send(
          JSON.stringify({
            type: "hello",
            state_id: nextState,
            request_id: requestId,
            ...(negotiated ? { error_format: 1 } : {}),
          }),
        );
        socket.send(
          JSON.stringify({
            type: "http",
            id: 1,
            request: {
              role: "tags",
              url: "https://tags.example/private?cookie=private",
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
          ...(negotiated ? { error: metadata.cause } : {}),
        });
        assert.equal(JSON.stringify(message).includes("private"), false);
        socket.send(
          JSON.stringify({
            type: "error",
            status: 502,
            detail: "private service detail",
            request_id: requestId,
            ...(negotiated ? { error: metadata } : {}),
          }),
        );
      }
    });
    const client = new NullgateClient({
      apiKey: "key",
      profileBaseURL: endpoint,
    });
    t.after(() => client.close());
    const session = client.open({ identity, userAgent: "UA" });
    await assert.rejects(
      session.profile(
        params,
        new Target(
          async () => {
            throw localError;
          },
          { proxy: null },
        ),
      ),
      (error) => {
        assert.ok(error instanceof NullgateAPIError);
        assert.equal(error.targetError, negotiated ? localError : undefined);
        const { command_id, ...expectedInfo } = metadata;
        assert.deepEqual(
          error.errorInfo,
          negotiated ? { ...expectedInfo, commandId: command_id } : undefined,
        );
        assert.equal(inspect(error).includes("private"), false);
        return true;
      },
    );
  });
}

test("malformed WS metadata keeps the legacy service failure", async (t) => {
  const endpoint = await serve(t, (socket, message) => {
    if (message.type === "start") {
      socket.send(
        JSON.stringify({
          type: "error",
          status: 502,
          detail: "legacy failure",
          request_id: requestId,
          error: {
            code: "FUTURE_ERROR",
            origin: "service",
            message: "safe",
            retryable: null,
            cause: { kind: [] },
          },
        }),
      );
    }
  });
  const client = new NullgateClient({
    apiKey: "key",
    profileBaseURL: endpoint,
  });
  t.after(() => client.close());
  const session = client.open({ identity, userAgent: "UA" });
  await assert.rejects(
    session.profile(
      params,
      new Target(
        async () => ({ status: 200, headers: {}, body: new Uint8Array() }),
        { proxy: null },
      ),
    ),
    (error) => {
      assert.ok(error instanceof NullgateAPIError);
      assert.equal(error.detail, "legacy failure");
      assert.equal(error.statusCode, 502);
      assert.equal(error.errorInfo, undefined);
      return true;
    },
  );
});

test("closing a negotiated profile cancels target work without reporting transport failure", async (t) => {
  const entered = Promise.withResolvers();
  const cancelled = Promise.withResolvers();
  const endpoint = await serve(t, (socket, message) => {
    if (message.type === "start") {
      socket.send(
        JSON.stringify({
          type: "hello",
          state_id: nextState,
          request_id: requestId,
          error_format: 1,
        }),
      );
      socket.send(JSON.stringify({ type: "ready", request_id: requestId }));
      socket.send(
        JSON.stringify({
          type: "http",
          id: 1,
          request: {
            role: "tags",
            url: "https://tags.example/tags.js",
            method: "GET",
            headers: {},
            body: null,
            credentials: "include",
          },
        }),
      );
    } else {
      assert.equal(message.type, "close");
    }
  });
  const client = new NullgateClient({
    apiKey: "key",
    profileBaseURL: endpoint,
  });
  t.after(() => client.close());
  const session = client.open({ identity, userAgent: "UA" });
  const target = new Target(
    async (request) => {
      entered.resolve(undefined);
      await once(request.signal, "abort");
      cancelled.resolve(undefined);
      throw request.signal.reason;
    },
    { proxy: null },
  );
  const profile = await session.profile(params, target);
  await entered.promise;
  await profile.close();
  await cancelled.promise;
  assert.equal(profile.error, undefined);
});

/** @type {[string, string, unknown, number | undefined][]} */
const correlationCases = [
  ["CLIENT_TRANSPORT_ERROR", "client", 1, 1],
  ["CLIENT_TRANSPORT_ERROR", "client", 2, 2],
  ["CLIENT_TRANSPORT_ERROR", "client", 3, undefined],
  ["UPSTREAM_ERROR", "upstream", 1, undefined],
  ["CLIENT_TRANSPORT_ERROR", "service", 1, undefined],
  ["CLIENT_TRANSPORT_ERROR", "client", null, undefined],
  ["CLIENT_TRANSPORT_ERROR", "client", true, undefined],
  ["CLIENT_TRANSPORT_ERROR", "client", 0, undefined],
  ["CLIENT_TRANSPORT_ERROR", "client", "1", undefined],
];
for (const [code, origin, commandId, expected] of correlationCases) {
  test(`concurrent target cause correlation: ${code}/${origin}/${commandId}`, async (t) => {
    const errors = new Map([
      [1, new Error("private first")],
      [2, new Error("private second")],
    ]);
    const allEntered = Promise.withResolvers();
    let entered = 0;
    const callbacks = new Map();
    const endpoint = await serve(t, (socket, message) => {
      if (message.type === "start") {
        socket.send(
          JSON.stringify({
            type: "hello",
            state_id: nextState,
            request_id: requestId,
            error_format: 1,
          }),
        );
        for (const id of [1, 2, 3]) {
          socket.send(
            JSON.stringify({
              type: "http",
              id,
              request: {
                role: "tags",
                url: `https://tags.example/${id}`,
                method: "GET",
                headers: {},
                body: null,
                credentials: "include",
              },
            }),
          );
        }
      } else if (
        message.type === "http.error" ||
        message.type === "http.result"
      ) {
        callbacks.set(message.id, message);
        if (callbacks.size !== 3) return;
        assert.equal(callbacks.get(1).type, "http.error");
        assert.equal(callbacks.get(2).type, "http.error");
        assert.equal(callbacks.get(3).response.status, 502);
        socket.send(
          JSON.stringify({
            type: "error",
            status: 502,
            detail: "legacy service failure",
            request_id: requestId,
            error: {
              code,
              origin,
              message: "safe",
              retryable: null,
              command_id: commandId,
            },
          }),
        );
      }
    });
    const client = new NullgateClient({
      apiKey: "key",
      profileBaseURL: endpoint,
    });
    t.after(() => client.close());
    const session = client.open({ identity, userAgent: "UA" });
    await assert.rejects(
      session.profile(
        params,
        new Target(
          async (request) => {
            if (++entered === 3) allEntered.resolve(undefined);
            await allEntered.promise;
            const id = Number(new URL(request.url).pathname.slice(1));
            if (errors.has(id)) throw errors.get(id);
            return { status: 502, headers: {}, body: new Uint8Array() };
          },
          { proxy: null },
        ),
      ),
      (error) => {
        assert.ok(error instanceof NullgateAPIError);
        assert.equal(
          error.targetError,
          expected === undefined ? undefined : errors.get(expected),
        );
        assert.equal(error.statusCode, 502);
        assert.equal(error.detail, "legacy service failure");
        if (
          typeof commandId !== "number" ||
          !Number.isSafeInteger(commandId) ||
          commandId <= 0
        )
          assert.equal(error.errorInfo, undefined);
        return true;
      },
    );
  });
}

for (const mode of ["stalled", "truncated", "oversized", "cancelled"]) {
  test(`rejected handshake retains HTTP diagnostics with ${mode} body`, {
    timeout: 5000,
  }, async (t) => {
    const received = Promise.withResolvers();
    const server = createServer();
    server.on("upgrade", (_request, socket) => {
      socket.on("error", () => undefined);
      socket.on("end", () => socket.destroy());
      socket.write(
        `HTTP/1.1 503 Service Unavailable\r\nX-Request-ID: ${requestId}\r\nContent-Length: 2000000\r\nConnection: close\r\n\r\n`,
      );
      socket.write('{"detail":"incomplete');
      received.resolve(undefined);
      if (mode === "truncated") socket.end();
      if (mode === "oversized") socket.write(Buffer.alloc(1_048_577));
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address();
    assert.ok(address && typeof address === "object");
    t.after(async () => {
      const closed = once(server, "close");
      server.close();
      await closed;
    });
    const client = new NullgateClient({
      apiKey: "key",
      profileBaseURL: `http://127.0.0.1:${address.port}`,
      timeoutMs: 300,
    });
    t.after(() => client.close());
    const controller = new AbortController();
    const reason = new Error("caller cancelled handshake");
    const session = client.open({ identity, userAgent: "UA" });
    const pending = session.profile(
      params,
      new Target(async () => assert.fail("target fetch must not run"), {
        proxy: null,
      }),
      { signal: controller.signal },
    );
    const rejected = assert.rejects(pending, (error) => {
      if (mode === "cancelled") assert.equal(error, reason);
      else {
        assert.ok(error instanceof NullgateAPIError);
        assert.equal(error.statusCode, 503);
        assert.equal(error.requestId, requestId);
        assert.equal(error.errorInfo, undefined);
      }
      return true;
    });
    await received.promise;
    if (mode === "cancelled") controller.abort(reason);
    await rejected;
  });
}
