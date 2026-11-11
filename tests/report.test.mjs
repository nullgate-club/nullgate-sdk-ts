import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";
import test from "node:test";
import { Nullgate } from "@nullgate/sdk";

const requestId = "0123456789abcdef0123456789abcdef";
const html =
  '<script src="/sensor"></script><script>bazadebezolkohpepadr="123"</script><script src="/akam/13/abc"></script><script src="/sbsd?v=00000000-0000-0000-0000-00000000004a"></script>';
for (const operation of ["sensor", "pixel", "sbsd", "fwcim"]) {
  test(`${operation} reports only its request ID without credentials or private observations`, async () => {
    let reports = 0;
    const client = new Nullgate("private-key", {
      baseUrl: "https://gateway.example/prefix",
      fetch: async (input, init) => {
        if (String(input).endsWith("/analytics/report")) {
          reports++;
          assert.equal(
            String(input),
            "https://gateway.example/prefix/analytics/report",
          );
          assert.equal(init?.method, "POST");
          assert.deepEqual(JSON.parse(String(init?.body)), {
            request_id: requestId,
          });
          assert.deepEqual(
            [...new Headers(init?.headers)],
            [["content-type", "application/json"]],
          );
          assert.equal(init?.credentials, "omit");
          assert.equal(init?.redirect, "manual");
          return new Response("privacy-neutral acknowledgement", {
            status: 200,
          });
        }
        return Response.json(
          operation === "fwcim"
            ? {
                metadata1: "private-metadata",
                headers: {},
                send_at: 0,
                session: "private-state",
                request_id: requestId,
              }
            : {
                request: {
                  url: "https://shop.example/post",
                  body: "private-payload",
                  headers: {},
                  send_at: 0,
                },
                session: "private-state",
                request_id: requestId,
              },
        );
      },
    });
    const page = client
      .session({ userAgent: "private-UA" })
      .page("https://shop.example", html);
    const result =
      operation === "sensor"
        ? await page.sensor({
            script: "private-script",
            cookies: { _abck: "private-cookie" },
          })
        : operation === "pixel"
          ? await page.pixel({ script: "private-script" })
          : operation === "sbsd"
            ? await page.sbsd({ script: "private-script", cookies: {} })
            : await page.fwcim({ timing: { navigationStart: 1 } });
    assert.equal(await result.report(), true);
    assert.equal(reports, 1);
  });
}
for (const status of [200, 302, 400, 503]) {
  test(`client report returns delivery status ${status} without retries`, async () => {
    let attempts = 0;
    const client = new Nullgate("fake", {
      fetch: async (_input, init) => {
        attempts++;
        assert.deepEqual(JSON.parse(String(init?.body)), {
          request_id: "unknown-issued-id",
        });
        return new Response("", {
          status,
          headers: {
            "Retry-After": "0",
            Location: "https://must-not-follow.example",
          },
        });
      },
    });
    assert.equal(await client.report("unknown-issued-id"), status === 200);
    assert.equal(attempts, 1);
  });
}
test("reports preserve caller cancellation and programming errors", async () => {
  const problem = new TypeError("caller programming failure");
  const client = new Nullgate("fake", {
    fetch: async () => {
      throw problem;
    },
  });
  await assert.rejects(client.report(requestId), (error) => error === problem);
  const controller = new AbortController();
  const reason = new Error("cancel report");
  controller.abort(reason);
  await assert.rejects(
    client.report(requestId, { signal: controller.signal }),
    (error) => error === reason,
  );
  await assert.rejects(client.report(""), { code: "invalid_request" });
});
test("native report connection failure and timeout return false without retries", {
  timeout: 2000,
}, async (t) => {
  let attempts = 0;
  const server = createServer((request) => {
    attempts++;
    if (attempts === 1) request.socket.destroy();
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
  });
  const client = new Nullgate("fake", {
    baseUrl: `http://127.0.0.1:${address.port}`,
    timeout: 0.1,
  });
  assert.equal(await client.report(requestId), false);
  assert.equal(attempts, 1);
  assert.equal(await client.report(requestId), false);
  assert.equal(attempts, 2);
});
