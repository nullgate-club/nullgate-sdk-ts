import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { abckCounters, isEnough, prepareInputs } from "@nullgate/sdk";

test("input summaries retain attributes and order without raw UTF-16 values", () => {
  /** @type {import('@nullgate/sdk').InputField[]} */
  const fields = [
    { name: "credential", type: "password", value: "s🔑&" },
    { name: "surrogate", value: "\ud800" },
    { name: "missing" },
  ];
  const prepared = prepareInputs(fields);
  assert.deepEqual(
    prepared.map((field) => field.attributes.name),
    ["credential", "surrogate", "missing"],
  );
  assert.deepEqual(
    prepared.map((field) => field.value.length),
    [4, 1, 0],
  );
  assert.deepEqual(
    prepared.map((field) => field.value.hash),
    [
      createHash("sha256")
        .update(Buffer.from("73003dd811dd2600", "hex"))
        .digest("hex"),
      createHash("sha256").update(Buffer.from("00d8", "hex")).digest("hex"),
      createHash("sha256").update("").digest("hex"),
    ],
  );
  assert.ok(prepared.every((field) => !("value" in field.attributes)));
  assert.equal(fields[0]?.value, "s🔑&");
  assert.equal(JSON.stringify(prepared).includes("s🔑&"), false);
});

test("input categories use JS whitespace, Unicode lowercase, and UTF-16 lengths", () => {
  /** @type {Array<[string, number[]]>} */
  const cases = [
    ["AZaz09_ !", [9, 1, 4, 2]],
    ["ÉİKß😀\ud800", [7, 7, 2, 0]],
    [
      "_ \t\n\u00a0\u1680\u2000\u200a\u2028\u2029\u202f\u205f\u3000\ufeff",
      [14, 0, 0, 0],
    ],
    ["\u0085\u001c\u001d\u001e\u001f", [5, 5, 0, 0]],
  ];
  for (const [value, expected] of cases) {
    assert.deepEqual(prepareInputs([{ value }])[0]?.value.counts, expected);
  }
});

test("hash facts retain signed UTF-16 and native trim boundaries", () => {
  const cases = [
    ["", 0, 0, 0],
    ["A_9 😀İ\u00a0", -902761640, 386520648, 7],
    ["\u0085\ufeff", 69402, 133, 1],
    ["\ufeff\u00a0😀 \u0085\tX\u3000\ufeff", -2113306057, 927999095, 6],
    [" \0 ", 30784, 0, 1],
    ["\u180ex\u200b", 5929761, 5929761, 3],
    ["\ud800", 55296, 55296, 1],
  ];
  for (const [text, hash31, trimmedHash31, trimmedLength] of cases) {
    const value = prepareInputs([{ value: String(text) }])[0]?.value;
    assert.deepEqual(
      [value?.hash31, value?.trimmed_hash31, value?.trimmed_length],
      [hash31, trimmedHash31, trimmedLength],
    );
  }
});

test("cookie counters follow URI decoding and decimal Number prefix semantics", () => {
  assert.deepEqual(abckCounters("x%7E%20%2B2tail%7Ez%7E3rest"), [2, 3]);
  assert.deepEqual(
    abckCounters("x~9007199254740993~z~0"),
    [9007199254740992, 0],
  );
  assert.deepEqual(abckCounters("x~0x10~z~-2tail"), [0, -2]);
  assert.deepEqual(abckCounters("x~\u00852~z~4"), [-1, 4]);
  for (const malformed of [undefined, "", "a~2", "a%~2~c~4", "a~2~c~%FF"]) {
    assert.deepEqual(abckCounters(malformed), [-1, -1]);
    assert.equal(isEnough(malformed, 99), false);
  }
  assert.equal(isEnough("x~2~z~0", 1), false);
  assert.equal(isEnough("x~2~z~0", 2), true);
  assert.equal(isEnough("x~0~z~0"), true);
  assert.equal(isEnough("x~-2~z~0"), true);
});
