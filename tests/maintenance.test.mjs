import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";
import test from "node:test";
import {
  FwcimParams,
  NullgateAPIError,
  NullgateClient,
  Page,
  Sensor,
  SensorParams,
  Target,
  ThreatMetrix,
  ThreatMetrixParams,
} from "@nullgate/sdk";

const identity = "11111111-2222-4333-8444-555555555555";
const page = new Page("https://target.example/", "<form></form>");
const params = new FwcimParams(page, {
  performanceTiming: { navigationStart: page.startedAtMs },
});
const detail = "Service updating; retry after a short delay";

/** @param {string | undefined} retryAfter @param {string} [message] @param {number} [status] @param {string | undefined} [marker] */
function maintenance(retryAfter, message = detail, status = 503, marker = "1") {
  return new Response(JSON.stringify({ detail: message }), {
    status,
    headers: {
      "X-State-ID": "must-not-adopt",
      ...(marker ? { "X-Nullgate-Maintenance": marker } : {}),
      ...(retryAfter === undefined ? {} : { "Retry-After": retryAfter }),
    },
  });
}

test("definitive pre-work maintenance retries twice without adopting rejected state", async () => {
  let count = 0;
  /** @type {(string | null)[]} */
  const states = [];
  const client = new NullgateClient({
    apiKey: "ng_test",
    fetch: async (_url, init) => {
      count += 1;
      states.push(new Headers(init?.headers).get("X-State-ID"));
      return count < 3
        ? maintenance("0")
        : new Response(
            JSON.stringify({
              metadata1: "private",
              send_at: 0,
              headers: {},
            }),
            { headers: { "X-Request-ID": "request" } },
          );
    },
  });
  const session = client.open({ identity, userAgent: "UA" });
  assert.equal((await session.fwcim(params)).metadata1, "private");
  assert.equal(count, 3);
  assert.equal(new Set(states).size, 1);
  assert.notEqual(states[0], "must-not-adopt");
  client.close();
});

test("maintenance retries are bounded and never cover generic/ambiguous failures", async () => {
  for (const [header, message, status, marker, expected] of [
    ["0", detail, 503, "1", 3],
    [undefined, detail, 503, "1", 1],
    ["6", detail, 503, "1", 1],
    ["NaN", detail, 503, "1", 1],
    ["-1", detail, 503, "1", 1],
    ["0", "different rejection", 503, "1", 3],
    ["0", detail, 502, "1", 1],
    ["0", detail, 503, "", 1],
    ["0", detail, 503, "0", 1],
    ["0", detail, 503, "1, 1", 1],
  ]) {
    let count = 0;
    const client = new NullgateClient({
      apiKey: "ng_test",
      fetch: async () => {
        count += 1;
        return maintenance(
          /** @type {string | undefined} */ (header),
          /** @type {string} */ (message),
          /** @type {number} */ (status),
          /** @type {string} */ (marker),
        );
      },
    });
    await assert.rejects(
      client.open({ identity, userAgent: "UA" }).fwcim(params),
      NullgateAPIError,
    );
    assert.equal(count, expected);
    client.close();
  }
});

test("closing a client interrupts maintenance delay without another request", async () => {
  let count = 0;
  /** @type {() => void} */
  let received = () => {};
  const first = new Promise((resolve) => {
    received = () => resolve(undefined);
  });
  const client = new NullgateClient({
    apiKey: "ng_test",
    fetch: async () => {
      count += 1;
      received();
      return maintenance("5");
    },
  });
  const pending = client.open({ identity, userAgent: "UA" }).fwcim(params);
  await first;
  client.close();
  await assert.rejects(pending, /closed/);
  assert.equal(count, 1);
});

test("profiling retries only marked pre-upgrade maintenance denials", async (t) => {
  let count = 0;
  let rejectedDetail = detail;
  let marker = "1";
  /** @type {Set<string | undefined>} */
  const states = new Set();
  const server = createServer();
  server.on("upgrade", (request, socket) => {
    count += 1;
    states.add(request.headers["x-state-id"]?.toString());
    const body = JSON.stringify({ detail: rejectedDetail });
    socket.end(
      `HTTP/1.1 503 Service Unavailable\r\nRetry-After: 0\r\nX-Nullgate-Maintenance: ${marker}\r\nX-State-ID: must-not-adopt\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`,
    );
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(async () => {
    server.close();
    await once(server, "close");
  });
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const client = new NullgateClient({
    apiKey: "ng_test",
    profileBaseURL: `http://127.0.0.1:${address.port}`,
  });
  t.after(() => client.close());
  const session = client.open({ identity, userAgent: "UA" });
  const profile = new ThreatMetrixParams(
    new ThreatMetrix(
      page,
      "https://target.example/tags.js?org_id=org&session_id=document",
    ),
  );
  const target = new Target(
    async () => {
      throw new Error("must not issue target HTTP");
    },
    { proxy: null },
  );
  await assert.rejects(session.profile(profile, target), NullgateAPIError);
  assert.equal(count, 3);
  assert.equal(states.size, 1);
  assert.equal(states.has("must-not-adopt"), false);
  rejectedDetail = "Generic temporary failure";
  count = 0;
  await assert.rejects(session.profile(profile, target), NullgateAPIError);
  assert.equal(count, 3);
  marker = "0";
  count = 0;
  await assert.rejects(session.profile(profile, target), NullgateAPIError);
  assert.equal(count, 1);
});

test("maintenance retries classify headers without reading response bodies", async () => {
  let count = 0;
  const client = new NullgateClient({
    apiKey: "ng_test",
    fetch: async () => {
      count += 1;
      if (count === 3)
        return new Response(
          JSON.stringify({
            metadata1: "private",
            send_at: 0,
            headers: {},
          }),
          { headers: { "X-Request-ID": "maintenance-recovered" } },
        );
      const response = maintenance("0", "conflicting generic body");
      response.text = async () => {
        throw new Error("maintenance body must not be read");
      };
      return response;
    },
  });
  try {
    assert.equal(
      (await client.open({ identity, userAgent: "UA" }).fwcim(params))
        .metadata1,
      "private",
    );
    assert.equal(count, 3);
  } finally {
    client.close();
  }
});

test("profile denial headers rotate state before incomplete, oversized, or stalled bodies", async (t) => {
  for (const mode of ["incomplete", "oversized", "stalled"]) {
    await t.test(mode, async (t) => {
      const server = createServer();
      /** @type {Set<import("node:stream").Duplex>} */
      const sockets = new Set();
      server.on("upgrade", (_request, socket) => {
        sockets.add(socket);
        socket.once("close", () => sockets.delete(socket));
        socket.on("error", () => {});
        socket.write(
          "HTTP/1.1 403 Forbidden\r\nX-State-ID: denial-next\r\nContent-Type: application/json\r\nContent-Length: 2000000\r\nConnection: close\r\n\r\n",
        );
        if (mode === "incomplete") socket.end('{"detail":');
        else if (mode === "oversized") socket.end("x".repeat(1_048_577));
      });
      server.listen(0, "127.0.0.1");
      await once(server, "listening");
      t.after(async () => {
        for (const socket of sockets) socket.destroy();
        server.close();
        await once(server, "close");
      });
      const address = server.address();
      assert.ok(address && typeof address === "object");
      const client = new NullgateClient({
        apiKey: "ng_test",
        timeoutMs: 200,
        profileBaseURL: `http://127.0.0.1:${address.port}`,
        fetch: async (_url, init) => {
          assert.equal(
            new Headers(init?.headers).get("X-State-ID"),
            "denial-next",
          );
          return new Response(
            JSON.stringify({
              sensor_data: "sensor",
              send_at: 0,
              headers: {},
            }),
            { headers: { "X-Request-ID": "request" } },
          );
        },
      });
      t.after(() => client.close());
      const session = client.open({ identity, userAgent: "UA" });
      const profile = new ThreatMetrixParams(
        new ThreatMetrix(
          page,
          "https://target.example/tags.js?org_id=org&session_id=document",
        ),
      );
      const target = new Target(
        async () => {
          throw new Error("must not issue target HTTP");
        },
        { proxy: null },
      );
      await assert.rejects(session.profile(profile, target));
      await session.solve(
        new SensorParams(
          new Sensor(page, "https://target.example/sensor"),
          "source",
        ),
      );
    });
  }
});
