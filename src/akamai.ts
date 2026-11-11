import { createHash } from "node:crypto";
import {
  httpURL,
  type JsonValue,
  Page,
  type ScriptReference,
} from "./models.js";

export interface ProvenanceOptions {
  readonly provenance?: ScriptReference;
}

export class Pixel {
  readonly provider = "akamai";
  readonly kind = "pixel";
  readonly page: Page;
  readonly scriptURL: string;
  readonly challenge: string;
  readonly provenance: ScriptReference | undefined;
  readonly challengeOffset: number | undefined;

  constructor(
    page: Page,
    scriptURL: string,
    challenge: string,
    options: ProvenanceOptions & { readonly challengeOffset?: number } = {},
  ) {
    if (!(page instanceof Page)) throw new TypeError("Pixel requires a Page");
    httpURL(scriptURL, "Pixel.scriptURL");
    if (typeof challenge !== "string" || !/^[0-9]+$/.test(challenge)) {
      throw new TypeError("Pixel.challenge must be a decimal string");
    }
    this.page = page;
    this.scriptURL = scriptURL;
    this.challenge = challenge;
    this.provenance = options.provenance;
    this.challengeOffset = options.challengeOffset;
    Object.freeze(this);
  }
}

/** An extensionless classic-script candidate; only generation validates its source. */
export class Sensor {
  readonly provider = "akamai";
  readonly kind = "sensor";
  readonly page: Page;
  readonly scriptURL: string;
  readonly provenance: ScriptReference | undefined;

  constructor(page: Page, scriptURL: string, options: ProvenanceOptions = {}) {
    if (!(page instanceof Page)) throw new TypeError("Sensor requires a Page");
    httpURL(scriptURL, "Sensor.scriptURL");
    this.page = page;
    this.scriptURL = scriptURL;
    this.provenance = options.provenance;
    Object.freeze(this);
  }
}

export class Sbsd {
  readonly provider = "akamai";
  readonly kind = "sbsd";
  readonly page: Page;
  readonly scriptURL: string;
  readonly provenance: ScriptReference | undefined;

  constructor(page: Page, scriptURL: string, options: ProvenanceOptions = {}) {
    if (!(page instanceof Page)) throw new TypeError("Sbsd requires a Page");
    httpURL(scriptURL, "Sbsd.scriptURL");
    this.page = page;
    this.scriptURL = scriptURL;
    this.provenance = options.provenance;
    Object.freeze(this);
  }

  /** Presence of the raw t parameter, including t=, denotes a blocking candidate. */
  get blocking(): boolean {
    return new URL(this.scriptURL).search
      .slice(1)
      .split("&")
      .some((part) => part.split("=", 1)[0] === "t");
  }
}

export type Protection = Pixel | Sensor | Sbsd;
export type InputField = Readonly<Record<string, string>>;

export type InputValue = {
  readonly length: number;
  readonly hash: string;
  readonly counts?: readonly [number, number, number, number];
  readonly hash31?: number;
  readonly trimmed_hash31?: number;
  readonly trimmed_length?: number;
};

/** Service event facts; input/change values are prepared summaries, never raw text. */
export type Action = Readonly<Record<string, JsonValue>> & {
  readonly type?: string;
  readonly value?: InputValue;
};

/** @internal */
export function prepareActions(actions: readonly Action[]): Action[] {
  return actions.map((action) => {
    if (typeof action.value === "string") {
      throw new TypeError(
        "Raw action input values are not allowed; use a prepared InputValue",
      );
    }
    return { ...action };
  });
}

export interface PreparedInput {
  readonly attributes: Readonly<Record<string, string>>;
  readonly value: InputValue;
  readonly selector?: string;
}

/** @internal Validate and detach an already-redacted observation without adding facts. */
export function validatePreparedInput(input: unknown): PreparedInput {
  if (input === null || typeof input !== "object" || Array.isArray(input))
    throw new TypeError("Invalid prepared input");
  const fields = input as Record<string, unknown>;
  if (
    Object.keys(fields).some(
      (key) => !["attributes", "value", "selector"].includes(key),
    ) ||
    fields.attributes === null ||
    typeof fields.attributes !== "object" ||
    Array.isArray(fields.attributes) ||
    Object.entries(fields.attributes).some(
      ([key, value]) =>
        ["value", "selector"].includes(key) || typeof value !== "string",
    ) ||
    ("selector" in fields &&
      (typeof fields.selector !== "string" || fields.selector.length === 0))
  )
    throw new TypeError("Invalid prepared input attributes or selector");
  const value = fields.value as Record<string, unknown> | null;
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).some(
      (key) =>
        ![
          "length",
          "hash",
          "counts",
          "hash31",
          "trimmed_hash31",
          "trimmed_length",
        ].includes(key),
    ) ||
    !Number.isInteger(value.length) ||
    Number(value.length) < 0 ||
    typeof value.hash !== "string" ||
    !/^[0-9a-f]{64}$/.test(value.hash)
  )
    throw new TypeError("Invalid prepared input value");
  for (const key of ["hash31", "trimmed_hash31"])
    if (
      key in value &&
      (!Number.isInteger(value[key]) ||
        Number(value[key]) < -(2 ** 31) ||
        Number(value[key]) >= 2 ** 31)
    )
      throw new TypeError("Input hashes must be signed 32-bit integers");
  if (
    "trimmed_length" in value &&
    (!Number.isInteger(value.trimmed_length) ||
      Number(value.trimmed_length) < 0 ||
      Number(value.trimmed_length) > Number(value.length) ||
      (value.trimmed_length === 0 &&
        "trimmed_hash31" in value &&
        value.trimmed_hash31 !== 0))
  )
    throw new TypeError("Invalid prepared trimmed input length");
  if ("counts" in value) {
    const counts = value.counts;
    if (
      !Array.isArray(counts) ||
      counts.length !== 4 ||
      counts.some((count) => !Number.isInteger(count) || count < 0) ||
      counts[0] !== value.length ||
      counts[1] + counts[3] > Number(value.length) ||
      counts[2] + counts[3] > Number(value.length)
    )
      throw new TypeError("Invalid prepared input counts");
  }
  return {
    attributes: Object.fromEntries(Object.entries(fields.attributes)),
    value: {
      ...value,
      length: Number(value.length),
      hash: value.hash,
      ...("counts" in value
        ? {
            counts: [...(value.counts as number[])] as [
              number,
              number,
              number,
              number,
            ],
          }
        : {}),
    } as InputValue,
    ...("selector" in fields ? { selector: fields.selector as string } : {}),
  };
}

/** Hash raw values locally, preserving source UTF-16 lengths and category counts. */
export function prepareInputs(inputs: readonly InputField[]): PreparedInput[] {
  return inputs.map((field): PreparedInput => {
    const value = field.value ?? "";
    if (
      typeof value !== "string" ||
      Object.values(field).some((v) => typeof v !== "string")
    ) {
      throw new TypeError(
        "Input fields must contain string attributes and values",
      );
    }
    const attributes = Object.fromEntries(
      Object.entries(field).filter(
        ([key]) => key !== "value" && key !== "selector",
      ),
    );
    const special = value.replace(/[A-Za-z0-9_\s]/g, "");
    const lower = value.toLowerCase().match(/[a-z]/g)?.length ?? 0;
    const digits = value.match(/[0-9]/g)?.length ?? 0;
    const trimmed = value.trim();
    return {
      attributes,
      ...(field.selector === undefined ? {} : { selector: field.selector }),
      value: {
        length: value.length,
        hash: createHash("sha256").update(value, "utf16le").digest("hex"),
        counts: [value.length, special.length, lower, digits],
        hash31: hash31(value),
        trimmed_hash31: hash31(trimmed),
        trimmed_length: trimmed.length,
      },
    };
  });
}

function hash31(value: string): number {
  let result = 0;
  for (let index = 0; index < value.length; index += 1) {
    result = (Math.imul(result, 31) + value.charCodeAt(index)) | 0;
  }
  return result;
}

/** Return [response limit, generation]; unavailable counters are -1. */
export function abckCounters(
  value: string | null | undefined,
): readonly [number, number] {
  if (value == null) return [-1, -1];
  let parts: string[];
  try {
    parts = decodeURIComponent(value).split("~");
  } catch {
    return [-1, -1];
  }
  if (parts.length < 4) return [-1, -1];
  const counter = (part: string | undefined): number => {
    const match = part?.match(/^\s*([+-]?[0-9]+)/);
    return match?.[1] === undefined ? -1 : Number(match[1]);
  };
  return [counter(parts[1]), counter(parts[3])];
}

/** Ordinary-send eligibility only, never proof that the target accepted a payload. */
export function isEnough(
  value: string | null | undefined,
  responseCount = 0,
): boolean {
  const [limit] = abckCounters(value);
  return limit !== -1 && responseCount >= limit;
}
