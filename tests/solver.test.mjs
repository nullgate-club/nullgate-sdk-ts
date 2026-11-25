import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";
import test from "node:test";
import { Solver, SolverError } from "@nullgate/sdk";

const products = [
  ["akamai", { accepted: true }, { accepted: true }],
  ["threatmetrix", { collected: true }, { collected: true }],
  [
    "pingone",
    {
      data: "encoded",
      device_id: "device",
      sdk_version: "1",
      request_id: "request",
    },
    {
      data: "encoded",
      deviceId: "device",
      sdkVersion: "1",
      requestId: "request",
    },
  ],
  [
    "amazon_acic",
    { status: "PASS", url: "https://shop.example/done", status_code: 200 },
    { status: "PASS", url: "https://shop.example/done", statusCode: 200 },
  ],
];

for (const [type, wireResult, expected] of products) {
  test(`${type}: preserve target identity and product data through the local server`, async (t) => {
    const server = createServer(async (request, response) => {
      let body = "";
      for await (const chunk of request) body += chunk;
      const input = JSON.parse(body);
      const valid =
        request.method === "POST" &&
        request.url === "/solve" &&
        input.proxy === "http://proxy.example:8080" &&
        input.session === "shop" &&
        input.user_agent === "browser" &&
        input.headers?.Accept === "text/html" &&
        JSON.stringify(input.transport?.headers_order) ===
          '["accept","user-agent"]' &&
        input.transport?.tls_options?.native_name === "unchanged" &&
        input.transport?.http2_options?.initial_window_size === 123 &&
        input.cookies?.[0]?.http_only === true &&
        input.cookies?.[0]?.same_site === "Lax" &&
        input.pingone?.sdk_config?.native_key === 2 &&
        input.pingone?.behavioral?.native_key === 3;
      if (!valid) {
        response.writeHead(400, { "content-type": "application/json" });
        response.end(
          JSON.stringify({
            code: "invalid_request",
            message: "Identity lost",
            stage: "validate",
            request_id: "bad",
          }),
        );
        return;
      }
      response.setHeader("content-type", "application/json");
      response.end(
        JSON.stringify({
          cookies: [
            {
              name: "sid",
              value: "value",
              domain: "shop.example",
              path: "/",
              secure: true,
              http_only: true,
              host_only: false,
              same_site: "Lax",
              expires: null,
            },
          ],
          result: wireResult,
        }),
      );
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    t.after(() => server.close());
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const solver = new Solver({ baseUrl: `http://127.0.0.1:${address.port}` });
    const response = await solver.solve({
      // @ts-expect-error Table values are checked by the server.
      type,
      url: "https://shop.example",
      userAgent: "browser",
      proxy: "http://proxy.example:8080",
      session: "shop",
      headers: { Accept: "text/html" },
      transport: {
        headersOrder: ["accept", "user-agent"],
        tlsOptions: { native_name: "unchanged" },
        http2Options: { initial_window_size: 123 },
      },
      cookies: [{ name: "sid", value: "old", httpOnly: true, sameSite: "Lax" }],
      pingone: { sdkConfig: { native_key: 2 }, behavioral: { native_key: 3 } },
    });
    assert.deepEqual(response.result, expected);
    assert.deepEqual(response.cookies, [
      {
        name: "sid",
        value: "value",
        domain: "shop.example",
        path: "/",
        secure: true,
        httpOnly: true,
        hostOnly: false,
        sameSite: "Lax",
        expires: null,
      },
    ]);
  });
}

test("structured errors retain the solver stage and upstream cause", async (t) => {
  const server = createServer((_request, response) => {
    response.writeHead(502, { "content-type": "application/json" });
    response.end(
      JSON.stringify({
        code: "target_failed",
        message: "Target failed",
        stage: "verify",
        request_id: "req",
        cause: "upstream",
      }),
    );
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => server.close());
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  await assert.rejects(
    new Solver({ baseUrl: `http://127.0.0.1:${address.port}` }).solve({
      type: "akamai",
      url: "https://shop.example",
    }),
    (error) => {
      assert.ok(error instanceof SolverError);
      assert.equal(error.code, "target_failed");
      assert.equal(error.stage, "verify");
      assert.equal(error.requestId, "req");
      assert.equal(error.status, 502);
      assert.equal(error.cause, "upstream");
      return true;
    },
  );
});

test("cancellation interrupts a pending solve instead of waiting for the deadline", async (t) => {
  const controller = new AbortController();
  const server = createServer(() => controller.abort());
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => server.close());
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  await assert.rejects(
    new Solver({ baseUrl: `http://127.0.0.1:${address.port}` }).solve({
      type: "akamai",
      url: "https://shop.example",
      signal: controller.signal,
    }),
    (error) => error instanceof SolverError && error.code === "cancelled",
  );
});

for (const body of ["not json", JSON.stringify({ cookies: [], result: {} })]) {
  test("invalid solver response cannot be mistaken for a successful solve", async (t) => {
    const server = createServer((_request, response) => {
      response.setHeader("content-type", "application/json");
      response.end(body);
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    t.after(() => server.close());
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    await assert.rejects(
      new Solver({ baseUrl: `http://127.0.0.1:${address.port}` }).solve({
        type: "akamai",
        url: "https://shop.example",
      }),
      (error) =>
        error instanceof SolverError && error.code === "invalid_response",
    );
  });
}

test("a stalled server produces a deadline error", async (t) => {
  const server = createServer(() => {});
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => server.close());
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  await assert.rejects(
    new Solver({
      baseUrl: `http://127.0.0.1:${address.port}`,
      timeoutMs: 50,
    }).solve({ type: "akamai", url: "https://shop.example" }),
    (error) => error instanceof SolverError && error.code === "timeout",
  );
});
