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
  ThreatMetrixParams,
} from "@nullgate/sdk";
import { WebSocketServer } from "ws";

const identity = "11111111-2222-4333-8444-555555555555";
const requestId = "11111111-2222-4333-8444-555555555556";
const nextState = "11111111-2222-4333-8444-555555555557";
const page = new Page("https://target.example/login", "<html>document</html>");
const params = new ThreatMetrixParams(
  new ThreatMetrix(
    page,
    "https://tags.example/tags.js?org_id=org&session_id=document",
  ),
);

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

test("profiling preserves binary HTTP failures and receives collection while awaiting departure", async (t) => {
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
              role: "tags",
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
    new ThreatMetrixParams(params.protection, {
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
    new ThreatMetrixParams(params.protection, { inputs: [], actions: [] }),
    target,
  );
  await next.close();
  assert.equal(continuations, 2);
  assert.equal(departures, 1);
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
