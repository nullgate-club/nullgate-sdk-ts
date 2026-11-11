import assert from "node:assert/strict";
import test from "node:test";
import { inspect } from "node:util";
import {
  FwcimParams,
  FwcimSolution,
  NullgateAPIError,
  NullgateClient,
  NullgateProtocolError,
  Page,
  prepareFwcimInputs,
  Sensor,
  SensorParams,
} from "@nullgate/sdk";

const identity = "11111111-2222-4333-8444-555555555555";
const page = new Page(
  "https://www.amazon.example/ap/signin",
  '<form id="login"><input id="email" name="email"><input name="password" type="PASSWORD"><textarea name="note"></textarea></form>',
  { startedAtMs: 1000 },
);
const timing = { navigationStart: 1000, domComplete: 1100 };
const params = new FwcimParams(page, { performanceTiming: timing });

/** @param {unknown} body @param {number} [status] @param {string} [state] */
function response(body, status = 200, state = "amazon-next") {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "X-Request-ID": "request-1", "X-State-ID": state },
  });
}

const success = {
  metadata1: "sensitive+/=field",
  send_at: 0,
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
};

test("FWCIM uses isolated endpoint/state and keeps page/timing and absence semantics", async () => {
  /** @type {{url: string, state: string | null, body: Record<string, any>}[]} */
  const calls = [];
  const client = new NullgateClient({
    apiKey: "ng_test",
    amazonBaseURL: "https://amazon.example",
    baseURL: "https://akamai.example",
    fetch: async (url, init) => {
      const headers = new Headers(init?.headers);
      assert.equal(headers.get("Authorization"), "Bearer ng_test");
      assert.equal(headers.get("User-Agent"), "test UA");
      assert.equal(headers.get("X-Nullgate-Error-Format"), "1");
      assert.equal(init?.credentials, "omit");
      assert.equal(init?.redirect, "manual");
      calls.push({
        url: String(url),
        state: headers.get("X-State-ID"),
        body: JSON.parse(String(init?.body)),
      });
      return String(url).includes("type=fwcim")
        ? response(success)
        : response(
            { sensor_data: "sensor", send_at: 0, headers: {} },
            200,
            "akamai-next",
          );
    },
  });
  const session = client.open({
    identity,
    userAgent: "test UA",
    timezone: "UTC",
  });
  const first = await session.fwcim(params);
  assert.ok(first instanceof FwcimSolution);
  assert.equal(first.metadata1, success.metadata1);
  assert.equal(first.sendAt, 0);
  assert.equal(first.requestId, "request-1");
  assert.equal(inspect(first).includes(success.metadata1), false);
  assert.equal(JSON.stringify(first).includes(success.metadata1), false);
  await first.wait();
  const form = new URLSearchParams({ metadata1: first.metadata1 });
  assert.equal(form.get("metadata1"), success.metadata1);
  assert.equal(form.toString(), "metadata1=sensitive%2B%2F%3Dfield");
  await session.solve(
    new SensorParams(
      new Sensor(page, "https://www.amazon.example/sensor"),
      "source",
    ),
  );
  await session.fwcim(
    new FwcimParams(page, {
      performanceTiming: timing,
      inputs: [],
      actions: [],
      submitted: false,
      referrer: "https://www.amazon.example/",
      historyLength: 2,
    }),
  );
  assert.equal(
    calls[0]?.url,
    `https://amazon.example/v1/${identity}/generate?type=fwcim`,
  );
  assert.notEqual(calls[0]?.state, calls[1]?.state);
  assert.equal(calls[2]?.state, "amazon-next");
  assert.deepEqual(calls[0]?.body.website, {
    url: page.url,
    html: page.html,
    document_id: page.documentId,
    started_at_ms: 1000,
  });
  assert.deepEqual(calls[0]?.body.performance_timing, timing);
  assert.equal(calls[0]?.body.timezone, "UTC");
  assert.equal(calls[0]?.body.submitted, true);
  assert.equal("inputs" in (calls[0]?.body ?? {}), false);
  assert.equal("actions" in (calls[0]?.body ?? {}), false);
  assert.equal("script" in (calls[0]?.body ?? {}), false);
  assert.deepEqual(calls[2]?.body.inputs, []);
  assert.deepEqual(calls[2]?.body.actions, []);
  assert.equal(calls[2]?.body.submitted, false);
  assert.equal(calls[2]?.body.website.history_length, 2);
  client.close();
});

test("input summaries use wrapper CESU-8 CRC32 and explicit canvas/geometry observations", () => {
  const [ascii, unicode] = prepareFwcimInputs(page, [
    { id: "email", value: "123456789" },
    {
      name: "note",
      selector: "#login textarea[name=note]",
      value: "é😀",
      text: "é😀",
      geometry: { width: 10, height: 20 },
    },
  ]);
  assert.equal(ascii?.checksum, 0xcbf43926);
  // CRC32 of c3 a9 ed a0 bd ed b8 80 (CESU-8, not four-byte UTF-8).
  assert.equal(unicode?.checksum, 0x1643ecee);
  assert.equal(unicode?.value.length, 3);
  assert.equal("checksum" in (unicode?.value ?? {}), false);
  assert.deepEqual(unicode?.attributes, { name: "note" });
  assert.deepEqual(unicode?.geometry, { width: 10, height: 20 });
  assert.equal(unicode?.text, "é😀");
  assert.equal(JSON.stringify(ascii).includes("123456789"), false);
});

test("actual password targets and password HTML are rejected without echoing raw data", () => {
  for (const input of [
    { name: "password", value: "private-password" },
    {
      selector: "input[type=PASSWORD]",
      value: "private-password",
      text: "private-password",
    },
    {
      id: "email",
      selector: "input[name=password]",
      value: "private-password",
    },
  ]) {
    assert.throws(
      () => prepareFwcimInputs(page, [input]),
      (error) => {
        assert.equal(String(error).includes("private-password"), false);
        return error instanceof TypeError;
      },
    );
  }
  assert.throws(
    () =>
      new FwcimParams(
        new Page(page.url, '<input TYPE="password" value="private-password">'),
        {
          performanceTiming: timing,
        },
      ),
    /password values/,
  );
  const ambiguous = new Page(
    page.url,
    '<input name="same"><textarea name="same"></textarea>',
  );
  assert.throws(
    () => prepareFwcimInputs(ambiguous, [{ name: "same", value: "safe" }]),
    /exactly one/,
  );
  assert.throws(
    () => prepareFwcimInputs(page, [{ selector: "[", value: "safe" }]),
    /selector/,
  );
  assert.throws(
    () =>
      prepareFwcimInputs(page, [
        { id: "email", value: "safe", text: "different" },
      ]),
    /match/,
  );
  assert.throws(
    () =>
      prepareFwcimInputs(page, [
        { id: "email", geometry: { width: -1, height: 1 } },
      ]),
    /dimensions/,
  );
  assert.throws(
    () =>
      new FwcimParams(page, { performanceTiming: { navigationStart: 2000 } }),
    /navigationStart/,
  );
});

test("FWCIM retains API/protocol errors, rotates error state, and cancels queued calls", async () => {
  let count = 0;
  /** @type {(value?: unknown) => void} */
  let release = () => {};
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  /** @type {(value?: unknown) => void} */
  let entered = () => {};
  const started = new Promise((resolve) => {
    entered = resolve;
  });
  const client = new NullgateClient({
    apiKey: "ng_test",
    fetch: async (_url, init) => {
      count += 1;
      if (count === 1) {
        entered();
        await gate;
        return response({ detail: "bad observations" }, 422, "error-state");
      }
      assert.equal(new Headers(init?.headers).get("X-State-ID"), "error-state");
      return response({ ...success, metadata1: 42 });
    },
  });
  const session = client.open({ identity, userAgent: "UA" });
  const first = session.fwcim(params);
  await started;
  const controller = new AbortController();
  const cancelled = session.fwcim(params, { signal: controller.signal });
  controller.abort(new Error("cancelled"));
  await assert.rejects(cancelled, /cancelled/);
  release();
  await assert.rejects(first, NullgateAPIError);
  await assert.rejects(session.fwcim(params), NullgateProtocolError);
  assert.equal(count, 2);
  const stop = AbortSignal.abort(new Error("stop wait"));
  const solution = new FwcimSolution({
    ...success,
    sendAt: Date.now() / 1000 + 10,
    requestId: "r",
  });
  await assert.rejects(solution.wait({ signal: stop }), /stop wait/);
  session.close();
  await assert.rejects(session.fwcim(params), /closed/);
  client.close();
});

test("FWCIM normalizes password types before any raw observation processing", () => {
  for (const type of [" password ", "\tPaSsWoRd\n"]) {
    const clean = new Page(page.url, `<input id="secret" type="${type}">`, {
      startedAtMs: 1000,
    });
    assert.throws(
      () => prepareFwcimInputs(clean, [{ id: "secret", value: "private" }]),
      /Password observations/,
    );
    const filled = new Page(
      page.url,
      `<input type="${type}" value="private">`,
      { startedAtMs: 1000 },
    );
    assert.throws(
      () => new FwcimParams(filled, { performanceTiming: timing }),
      /password values/,
    );
  }
});

test("FWCIM rejects every populated duplicate password value before transport", () => {
  for (const html of [
    '<input type=password value="" value="private-password">',
    '<input type=password value="private-password" value="">',
    '<input type=password value="" value="&#112;rivate-password" value="">',
  ]) {
    const filled = new Page(page.url, html, { startedAtMs: 1000 });
    assert.throws(
      () => new FwcimParams(filled, { performanceTiming: timing }),
      /password values/,
    );
  }
});

test("FWCIM excludes template content but still checks its raw password values", () => {
  const document = new Page(
    page.url,
    '<form id="f"><template><input id="inert"></template><input id="active"></form><template><form id="hidden"></form></template>',
    { startedAtMs: 1000 },
  );
  for (const input of [{ id: "inert" }, { selector: "#inert" }]) {
    assert.throws(
      () =>
        new FwcimParams(document, {
          performanceTiming: timing,
          formSelector: "#f",
          inputs: [input],
        }),
      /exactly one matching control/,
    );
  }
  new FwcimParams(document, {
    performanceTiming: timing,
    formSelector: "#f",
    inputs: [{ id: "active" }],
  });
  assert.throws(
    () =>
      new FwcimParams(document, {
        performanceTiming: timing,
        formSelector: "#hidden",
      }),
    /formSelector/,
  );
  for (const html of [
    '<template><input type=password value="" value=private></template>',
    "<template><textarea autocomplete=current-password>private</textarea></template>",
  ]) {
    const unsafe = new Page(page.url, html, { startedAtMs: 1000 });
    assert.throws(
      () => new FwcimParams(unsafe, { performanceTiming: timing }),
      /password values/,
    );
  }
});

test("FWCIM explicit form selects one form and owns observed controls", () => {
  const forms = new Page(
    page.url,
    '<form id="one"><input id="inside"></form><form id="two"><input id="outside"></form><input id="associated" form="one">',
    { startedAtMs: 1000 },
  );
  for (const formSelector of ["[", "form", "#inside", "#missing"]) {
    assert.throws(
      () => new FwcimParams(forms, { performanceTiming: timing, formSelector }),
      /formSelector/,
    );
  }
  assert.throws(
    () =>
      new FwcimParams(forms, {
        performanceTiming: timing,
        formSelector: "#one",
        inputs: [{ id: "outside", value: "safe" }],
      }),
    /selected form/,
  );
  new FwcimParams(forms, {
    performanceTiming: timing,
    formSelector: "#one",
    inputs: [{ id: "inside" }],
  });
  assert.throws(
    () =>
      new FwcimParams(forms, {
        performanceTiming: timing,
        formSelector: "#one",
        inputs: [{ id: "associated" }],
      }),
    /selected form/,
  );
  assert.throws(
    () =>
      new FwcimParams(page, {
        performanceTiming: { ...timing, fetchStart: 999 },
      }),
    /performanceTiming/,
  );
  new FwcimParams(page, {
    performanceTiming: { ...timing, fetchStart: 0 },
  });
});

test("FWCIM cookies require a name-to-value mapping", () => {
  for (const cookies of [null, [], ["value"], "value", 1, { name: 1 }]) {
    assert.throws(
      // @ts-expect-error Deliberately exercise invalid JavaScript cookie values.
      () => new FwcimParams(page, { performanceTiming: timing, cookies }),
      /cookies must be a string mapping/,
    );
  }
  new FwcimParams(page, {
    performanceTiming: timing,
    cookies: { name: "value" },
  });
});

test("FWCIM action boundary rejects raw and nested payloads without changing other providers", () => {
  for (const field of [
    { value: "private" },
    { key: "private" },
    { text: "private" },
    { target: {} },
    { target_path: {} },
    { pointer_type: null },
    { trusted: 1 },
    { x: true },
    { time: Infinity },
    { touches: [{ x: 1, value: "private" }] },
    { touches: [{ x: 1, y: null }] },
    { touches: [{ y: 1 }] },
    { touches: [{ x: 1, y: 2, identifier: 0.5 }] },
    { touches: [null] },
    { acceleration: { x: "private" } },
    { acceleration_with_gravity: { value: "private" } },
    { rotation_rate: { x: 1 } },
    { acceleration: { x: 1, y: 2, z: 3 } },
    { acceleration: [1, 2] },
    { acceleration_with_gravity: [1, 2, 3, 4] },
    { rotation_rate: [1, true, 3] },
    { rotation_rate: [1, Infinity, 3] },
    { input_summary: { value: "private" } },
    { input_summary: [1, [0, 1, 2, "private"]] },
    { input_summary: [-1, null] },
  ]) {
    assert.throws(
      () =>
        new FwcimParams(page, {
          performanceTiming: timing,
          // @ts-expect-error Deliberately exercise invalid wire observations.
          actions: [{ type: "input", ...field }],
        }),
      /FWCIM action/,
    );
  }
  new FwcimParams(page, {
    performanceTiming: timing,
    actions: [
      {
        type: "input",
        target: 1,
        target_path: "#email",
        trusted: true,
        time: 1,
        x: null,
        touches: [{ x: 1, y: -2, identifier: 2 }],
        acceleration: [null, 1, 2],
        acceleration_with_gravity: [1, null, 3],
        rotation_rate: [1, 2, null],
        input_summary: [3, [1, 1, 1, 0]],
      },
    ],
  });
});

test("FWCIM snapshots validated event facts without serialization hooks or second reads", async () => {
  let hookCalls = 0;
  let reads = 0;
  const prototype = {
    toJSON() {
      hookCalls += 1;
      return { value: "private" };
    },
  };
  const touch = Object.assign(Object.create(prototype), {
    x: -1,
    y: 2,
    identifier: 0,
  });
  const action = Object.assign(Object.create(prototype), {
    type: "touchmove",
    touches: [touch],
  });
  Object.defineProperty(action, "time", {
    enumerable: true,
    get() {
      reads += 1;
      return reads === 1 ? 3 : "private";
    },
  });
  const observations = new FwcimParams(page, {
    performanceTiming: Object.assign(Object.create(prototype), timing),
    cookies: Object.assign(Object.create(prototype), { safe: "cookie" }),
    actions: [action],
  });
  touch.x = 99;
  const client = new NullgateClient({
    apiKey: "ng_test",
    fetch: async (_url, init) => {
      const body = JSON.parse(String(init?.body));
      assert.deepEqual(body.actions, [
        {
          type: "touchmove",
          touches: [{ x: -1, y: 2, identifier: 0 }],
          time: 3,
        },
      ]);
      assert.deepEqual(body.performance_timing, timing);
      assert.deepEqual(body.cookies, { safe: "cookie" });
      return response(success);
    },
  });
  try {
    await client.open({ identity, userAgent: "UA" }).fwcim(observations);
    assert.equal(hookCalls, 0);
    assert.equal(reads, 1);
  } finally {
    client.close();
  }
});

test("FWCIM collects descendant controls by identity regardless of form attributes", () => {
  const document = new Page(
    page.url,
    '<div id="same"></div><form id="same" class="first"><input id="inside" form="elsewhere"><input id="empty" form=""></form><form id="same" class="second"><input id="second"></form><input id="external" form="same">',
    { startedAtMs: 1000 },
  );
  new FwcimParams(document, {
    performanceTiming: timing,
    formSelector: ".first",
    inputs: [{ id: "inside" }, { id: "empty" }],
  });
  for (const id of ["inside", "external"]) {
    assert.throws(
      () =>
        new FwcimParams(document, {
          performanceTiming: timing,
          formSelector: ".second",
          inputs: [{ id }],
        }),
      /selected form/,
    );
  }
});

test("FWCIM protects canonical password controls and validates observation fields", () => {
  for (const attributes of [
    'autocomplete="section-login CURRENT-password"',
    'autocomplete="new-password"',
    'id=" AP_PASSWORD "',
    'name=" Password "',
  ]) {
    const clean = new Page(page.url, `<input ${attributes}>`, {
      startedAtMs: 1000,
    });
    assert.throws(
      () =>
        prepareFwcimInputs(clean, [{ selector: "input", value: "private" }]),
      /Password observations/,
    );
    const filled = new Page(page.url, `<input ${attributes} value="private">`, {
      startedAtMs: 1000,
    });
    assert.throws(
      () => new FwcimParams(filled, { performanceTiming: timing }),
      /password values/,
    );
  }
  for (const field of [
    { checksum: 0 },
    { checksum: "private" },
    { text: 1 },
    { extra: "private" },
  ]) {
    assert.throws(
      () =>
        prepareFwcimInputs(page, [
          // @ts-expect-error Invalid runtime observation.
          { id: "email", ...field },
        ]),
      TypeError,
    );
  }
  const zero = new Page(page.url, "<form></form>", { startedAtMs: 0 });
  assert.throws(
    () => new FwcimParams(zero, { performanceTiming: { navigationStart: 0 } }),
    /navigationStart/,
  );
});

test("stalled Amazon calls do not block Akamai and session close cancels both queues", async () => {
  const entered = Promise.withResolvers();
  const client = new NullgateClient({
    apiKey: "ng_test",
    fetch: async (url, init) => {
      if (String(url).includes("type=fwcim")) {
        entered.resolve(undefined);
        await new Promise((_, reject) => {
          init?.signal?.addEventListener(
            "abort",
            () => reject(init?.signal?.reason),
            { once: true },
          );
        });
      }
      return response({ sensor_data: "sensor", send_at: 0, headers: {} });
    },
  });
  const session = client.open({ identity, userAgent: "UA" });
  const first = session.fwcim(params);
  const firstRejected = assert.rejects(first, /closed/);
  await entered.promise;
  const queued = session.fwcim(params);
  const queuedRejected = assert.rejects(queued, /closed/);
  await session.solve(
    new SensorParams(
      new Sensor(page, "https://target.example/sensor"),
      "source",
    ),
  );
  session.close();
  await Promise.all([firstRejected, queuedRejected]);
  await session[Symbol.asyncDispose]();
  client.close();
});
