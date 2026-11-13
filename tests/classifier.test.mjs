import assert from "node:assert/strict";
import test from "node:test";
import { Nullgate } from "@nullgate/sdk";

const labels = ["cat", "dog"];
const first = new Uint8Array([0xff, 0xd8, 0xff, 0x00, 0xfb]);
const second = new Uint8Array(2048).map((_, index) => index % 251);

/** @param {RequestInit | undefined} init */
const sentForm = (init) =>
  new Response(/** @type {FormData} */ (init?.body)).formData();
/** @param {FormData} form */
const sentImages = (form) =>
  Promise.all(
    form
      .getAll("image")
      .map(async (part) => [
        ...new Uint8Array(await /** @type {File} */ (part).arrayBuffer()),
      ]),
  );

test("classify posts raw images and labels as multipart and returns one result per image", async () => {
  /** @type {{ url: string, init: RequestInit | undefined }[]} */
  const requests = [];
  const ng = new Nullgate("fake", {
    baseUrl: "http://localhost:8080",
    fetch: async (url, init) => {
      requests.push({ url: String(url), init });
      const form = /** @type {FormData} */ (init?.body);
      return Response.json({
        model: "balanced",
        results: form
          .getAll("image")
          .map(() => ({ label: "dog", scores: [0.25, 0.75] })),
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
  // Only Authorization: fetch adds the multipart boundary, and nothing is gzipped.
  assert.deepEqual(single?.init?.headers, { Authorization: "Bearer fake" });
  assert.deepEqual(batch?.init?.headers, { Authorization: "Bearer fake" });

  const one = await sentForm(single?.init);
  assert.deepEqual([...new Set(one.keys())], ["image", "label"]);
  assert.deepEqual(one.getAll("label"), labels);
  assert.deepEqual(await sentImages(one), [[...first]]);

  const two = await sentForm(batch?.init);
  assert.deepEqual([...new Set(two.keys())], ["image", "label", "model"]);
  assert.deepEqual(two.getAll("label"), labels);
  assert.deepEqual(two.getAll("model"), ["precise"]);
  assert.deepEqual(await sentImages(two), [[...first], [...view]]);
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

test("match posts raw images and queries in order without gzip", async () => {
  /** @type {{ url: string, init: RequestInit | undefined }[]} */
  const requests = [];
  const ng = new Nullgate("fake", {
    baseUrl: "http://localhost:8080",
    fetch: async (url, init) => {
      requests.push({ url: String(url), init });
      return Response.json({
        results: [{ scores: [0.9, 0.8] }, { scores: [0, 1] }],
      });
    },
  });
  const view = new Uint8Array(second.buffer, 16, 1500);
  assert.deepEqual(await ng.match({ images: [first, view], queries: labels }), {
    results: [{ scores: [0.9, 0.8] }, { scores: [0, 1] }],
  });
  const [request] = requests;
  assert.equal(request?.url, "http://localhost:8080/classifier/match");
  assert.equal(request?.init?.method, "POST");
  assert.deepEqual(request?.init?.headers, { Authorization: "Bearer fake" });
  const form = await sentForm(request?.init);
  assert.deepEqual([...new Set(form.keys())], ["image", "query"]);
  assert.deepEqual(form.getAll("query"), labels);
  assert.deepEqual(await sentImages(form), [[...first], [...view]]);
});

for (const [name, options] of /** @type {const} */ ([
  ["no images", { images: [], queries: labels }],
  ["an empty image", { images: [first, new Uint8Array()], queries: labels }],
  ["more than 32 images", { images: Array(33).fill(first), queries: labels }],
  ["a non-byte image", { images: ["image"], queries: labels }],
  ["no queries", { images: first, queries: [] }],
])) {
  test(`match rejects ${name} without sending`, async () => {
    const ng = new Nullgate("fake", {
      fetch: async () => assert.fail("must not send"),
    });
    await assert.rejects(ng.match(/** @type {any} */ (options)), {
      name: "NullgateError",
      code: "invalid_request",
      status: null,
    });
  });
}

for (const [name, body] of /** @type {const} */ ([
  ["a missing result", '{"results":[]}'],
  ["a missing score", '{"results":[{"scores":[0.5]}]}'],
  ["a non-number score", '{"results":[{"scores":[0.5,"1"]}]}'],
  ["a negative score", '{"results":[{"scores":[0.5,-0.1]}]}'],
  ["a score above one", '{"results":[{"scores":[0.5,1.1]}]}'],
  ["a non-finite score", '{"results":[{"scores":[0.5,1e400]}]}'],
])) {
  test(`match rejects ${name} as a protocol error`, async () => {
    const ng = new Nullgate("fake", { fetch: async () => new Response(body) });
    await assert.rejects(ng.match({ images: first, queries: labels }), {
      code: "protocol_error",
    });
  });
}

test("match maps server errors to the public error", async () => {
  const ng = new Nullgate("fake", {
    fetch: async () =>
      Response.json(
        {
          code: "insufficient_balance",
          message: "Safe explanation",
          request_id: "correlation",
        },
        { status: 402 },
      ),
  });
  await assert.rejects(ng.match({ images: first, queries: labels }), {
    name: "NullgateError",
    code: "insufficient_balance",
    message: "Safe explanation",
    requestId: "correlation",
    status: 402,
  });
});
