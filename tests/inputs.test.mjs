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
  assert.deepEqual(prepared, [
    {
      attributes: { name: "credential", type: "password" },
      value: {
        length: 4,
        hash: createHash("sha256")
          .update(Buffer.from("73003dd811dd2600", "hex"))
          .digest("hex"),
        counts: [4, 3, 1, 0],
      },
    },
    {
      attributes: { name: "surrogate" },
      value: {
        length: 1,
        hash: createHash("sha256")
          .update(Buffer.from("00d8", "hex"))
          .digest("hex"),
        counts: [1, 1, 0, 0],
      },
    },
    {
      attributes: { name: "missing" },
      value: {
        length: 0,
        hash: createHash("sha256").update("").digest("hex"),
        counts: [0, 0, 0, 0],
      },
    },
  ]);
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
