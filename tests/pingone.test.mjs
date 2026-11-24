import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";
import test from "node:test";
import { gunzipSync } from "node:zlib";
import { Nullgate, NullgateError } from "@nullgate/sdk";

const script = "source".repeat(300);
const generated = {
  data: "encoded",
  sdk_version: "1",
  device_id: "device",
  session: "done",
  request_id: "result",
};
const request = {
  role: "pingone.token",
  method: "GET",
  url: "https://identity.example/token.css",
  headers: {},
  body: null,
  credentials: "include",
};

/** @param {(path: string, body: any) => Response} reply
 * @param {number} [timeout]
 */
function page(reply, timeout) {
  return new Nullgate("private-key", {
    ...(timeout === undefined ? {} : { timeout }),
    fetch: async (input, init) => {
      const bytes = init?.body;
      const json =
        new Headers(init?.headers).get("content-encoding") === "gzip"
          ? gunzipSync(/** @type {Uint8Array} */ (bytes)).toString()
          : String(bytes);
      return reply(new URL(String(input)).pathname, JSON.parse(json));
    },
  })
    .session({ userAgent: "browser" })
    .page("https://identity.example/login", "<html></html>");
}

test("protect sends caller-fetched CSS and recovers retained source once", async () => {
  /** @type {any[]} */ const calls = [];
  let fetches = 0;
  const result = await page((path, body) => {
    calls.push({ path, body });
    if (path.endsWith("prepare"))
      return Response.json({ session: "prepared", request });
    if (calls.length === 2)
      return Response.json(
        { code: "script_required", message: "missing", request_id: "error" },
        { status: 428 },
      );
    return Response.json(generated);
  }).protect({
    script,
    sdkConfig: { universalDeviceIdentification: false },
    jwtDeviceAttributes: "device.jwt",
    jwtAgentPayload: "agent.jwt",
    send: async (target) => {
      fetches++;
      assert.equal(target.url, request.url);
      assert.equal(new Headers(target.headers).has("authorization"), false);
      return {
        status: 200,
        headers: {},
        body: new TextEncoder().encode("token CSS"),
      };
    },
  });
  assert.equal(fetches, 1);
  assert.equal(calls[0].body.script, script);
  assert.equal(calls[0].body.website.url, "https://identity.example/login");
  assert.equal(calls[1].body.script, undefined);
  assert.equal(calls[2].body.script, script);
  assert.equal(calls[2].body.token_response, "token CSS");
  assert.equal(calls[2].body.jwt_device_attributes, "device.jwt");
  assert.equal(calls[2].body.jwt_agent_payload, "agent.jwt");
  assert.deepEqual(result, {
    data: "encoded",
    sdkVersion: "1",
    deviceId: "device",
    requestId: "result",
  });
});

test("client token skips prepare and target fetch", async () => {
  const result = await page((path, body) => {
    assert.equal(path, "/pingone/protect");
    assert.equal(body.client_token, "caller-token");
    assert.equal(body.script, script);
    return Response.json(generated);
  }).protect({
    script,
    clientToken: "caller-token",
    send: async () => {
      throw new Error("unexpected target fetch");
    },
  });
  assert.equal(result.data, "encoded");
});

test("non-2xx CSS response stops before protect", async () => {
  let calls = 0;

  await assert.rejects(
    page((path) => {
      calls++;
      assert.equal(path, "/pingone/prepare");
      return Response.json({ session: "prepared", request });
    }).protect({
      script,
      send: async () => ({ status: 403, headers: {}, body: new Uint8Array() }),
    }),
    (error) => error instanceof NullgateError && error.code === "target_error",
  );
  assert.equal(calls, 1);
});

test("target timeout aborts the callback and releases the session queue", async () => {
  const document = page(
    (path) =>
      Response.json(
        path.endsWith("prepare") ? { session: "prepared", request } : generated,
      ),
    0.01,
  );
  let aborted = false;
  const first = document.protect({
    script,
    send: ({ signal }) => {
      signal.addEventListener("abort", () => {
        aborted = signal.aborted;
      });
      return new Promise(() => {});
    },
  });
  const second = document.protect({ script, clientToken: "caller-token" });
  await assert.rejects(
    first,
    (error) => error instanceof NullgateError && error.code === "timeout",
  );
  assert.equal(aborted, true);
  assert.equal((await second).data, "encoded");
});

test("prepared credentials cannot expose the API key to the callback", async () => {
  for (const unsafe of [
    { ...request, url: "https://identity.example/private-key" },
    { ...request, headers: { "x-private-key": "value" } },
    { ...request, headers: { authorization: "Bearer private-key" } },
  ]) {
    let called = false;
    await assert.rejects(
      page(() =>
        Response.json({ session: "prepared", request: unsafe }),
      ).protect({
        script,
        send: async () => {
          called = true;
          return { status: 200, headers: {}, body: new Uint8Array() };
        },
      }),
      (error) =>
        error instanceof NullgateError && error.code === "protocol_error",
    );
    assert.equal(called, false);
  }
});

test("target receives caller credentials that do not contain the API key", async () => {
  const headers = { cookie: "session=abc", authorization: "Bearer target" };
  await page((path) =>
    Response.json(
      path.endsWith("prepare")
        ? { session: "prepared", request: { ...request, headers } }
        : generated,
    ),
  ).protect({
    script,
    send: async (target) => {
      assert.deepEqual(target.headers, headers);
      return { status: 200, headers: {}, body: new Uint8Array() };
    },
  });
});
test("compressed protect requests reach a real HTTP server intact", async () => {
  const server = createServer(async (req, res) => {
    /** @type {Buffer[]} */ const chunks = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    const body = JSON.parse(gunzipSync(Buffer.concat(chunks)).toString());
    assert.equal(req.headers["content-encoding"], "gzip");
    assert.equal(body.script, script);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(generated));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("Missing server address");
    const result = await new Nullgate("key", {
      baseUrl: `http://127.0.0.1:${address.port}`,
    })
      .session({ userAgent: "browser" })
      .page("https://identity.example", "")
      .protect({ script, clientToken: "token" });
    assert.equal(result.data, "encoded");
  } finally {
    server.close();
    await once(server, "close");
  }
});
