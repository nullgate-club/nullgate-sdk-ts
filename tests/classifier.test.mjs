import assert from "node:assert/strict";
import test from "node:test";
import { gunzipSync } from "node:zlib";
import { Nullgate } from "@nullgate/sdk";

const labels = ["cat", "dog"];
const first = new Uint8Array([0xff, 0xd8, 0xff, 0x00, 0xfb]);
const second = new Uint8Array(2048).map((_, index) => index % 251);

test("classify posts base64 images and labels and returns one result per image", async () => {
  /** @type {{ url: string, init: RequestInit | undefined }[]} */
  const requests = [];
  const ng = new Nullgate("fake", {
    baseUrl: "http://localhost:8080",
    fetch: async (url, init) => {
      requests.push({ url: String(url), init });
      const { images } = JSON.parse(
        typeof init?.body === "string"
          ? init.body
          : gunzipSync(/** @type {Uint8Array} */ (init?.body)).toString(),
      );
      return Response.json({
        model: "balanced",
        results: images.map(() => ({ label: "dog", scores: [0.25, 0.75] })),
      });
    },
  });

  assert.deepEqual(await ng.classify({ images: first, labels }), {
    model: "balanced",
    results: [{ label: "dog", scores: [0.25, 0.75] }],
  });
  // A view into a larger buffer must send only its own bytes.
  const view = new Uint8Array(second.buffer, 16, 1500);
  const many = await ng.classify({
    images: [first, view],
    labels,
    model: "precise",
  });
  assert.equal(many.results.length, 2);

  const [single, batch] = requests;
  assert.equal(single?.url, "http://localhost:8080/classifier/classify");
  assert.equal(single?.init?.method, "POST");
  const headers = /** @type {Record<string, string>} */ (single?.init?.headers);
  assert.equal(headers.Authorization, "Bearer fake");
  assert.equal(headers["Content-Type"], "application/json");
  assert.deepEqual(JSON.parse(String(single?.init?.body)), {
    images: [Buffer.from(first).toString("base64")],
    labels,
  });
  assert.equal(
    /** @type {Record<string, string>} */ (batch?.init?.headers)[
      "Content-Encoding"
    ],
    "gzip",
  );
  const sent = JSON.parse(
    gunzipSync(/** @type {Uint8Array} */ (batch?.init?.body)).toString(),
  );
  assert.equal(sent.model, "precise");
  assert.deepEqual(sent.labels, labels);
  assert.deepEqual(
    sent.images.map((/** @type {string} */ image) => [
      ...Buffer.from(image, "base64"),
    ]),
    [[...first], [...view]],
  );
});

for (const [name, options] of /** @type {const} */ ([
  ["no images", { images: [], labels }],
  ["an empty image", { images: [first, new Uint8Array()], labels }],
  ["more than 32 images", { images: Array(33).fill(first), labels }],
  ["a single label", { images: first, labels: ["cat"] }],
  ["base64 strings", { images: ["/9j/"], labels }],
])) {
  test(`classify rejects ${name} without sending`, async () => {
    const ng = new Nullgate("fake", {
      fetch: async () => assert.fail("must not send"),
    });
    await assert.rejects(ng.classify(/** @type {any} */ (options)), {
      name: "NullgateError",
      code: "invalid_request",
      status: null,
    });
  });
}

for (const [code, status] of /** @type {const} */ ([
  ["invalid_request", 400],
  ["insufficient_balance", 402],
])) {
  test(`classify maps ${code} to the public error`, async () => {
    const ng = new Nullgate("fake", {
      fetch: async () =>
        Response.json(
          { code, message: "Safe explanation", request_id: "correlation" },
          { status },
        ),
    });
    await assert.rejects(ng.classify({ images: first, labels }), {
      name: "NullgateError",
      code,
      message: "Safe explanation",
      requestId: "correlation",
      status,
    });
  });
}

for (const [name, data] of /** @type {const} */ ([
  ["a missing result", { model: "balanced", results: [] }],
  [
    "scores that do not match the labels",
    { model: "balanced", results: [{ label: "cat", scores: [1] }] },
  ],
])) {
  test(`classify rejects ${name} as a protocol error`, async () => {
    const ng = new Nullgate("fake", { fetch: async () => Response.json(data) });
    await assert.rejects(ng.classify({ images: first, labels }), {
      code: "protocol_error",
    });
  });
}
