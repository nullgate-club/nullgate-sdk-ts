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
export type Cookies = Readonly<Record<string, string>>;
export type InputField = Readonly<Record<string, string>>;

export type InputValue = {
  readonly length: number;
  readonly hash: string;
  readonly counts: readonly [number, number, number, number];
};

/** Service event facts; input/change values are prepared summaries, never raw text. */
export type Action = Readonly<Record<string, JsonValue>> & {
  readonly type: string;
  readonly value?: InputValue;
};

export interface PreparedInput {
  readonly attributes: Readonly<Record<string, string>>;
  readonly value: InputValue;
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
      Object.entries(field).filter(([key]) => key !== "value"),
    );
    const special = value.replace(/[A-Za-z0-9_\s]/g, "");
    const lower = value.toLowerCase().match(/[a-z]/g)?.length ?? 0;
    const digits = value.match(/[0-9]/g)?.length ?? 0;
    return {
      attributes,
      value: {
        length: value.length,
        hash: createHash("sha256").update(value, "utf16le").digest("hex"),
        counts: [value.length, special.length, lower, digits],
      },
    };
  });
}

export class PixelParams {
  readonly kind = "pixel";
  readonly protection: Pixel;
  readonly script: string;

  constructor(protection: Pixel, script: string) {
    if (!(protection instanceof Pixel))
      throw new TypeError("PixelParams requires a Pixel protection");
    if (typeof script !== "string")
      throw new TypeError("script must be source text");
    this.protection = protection;
    this.script = script;
    Object.freeze(this);
  }
}

export interface SensorOptions {
  readonly cookies?: Cookies | null;
  readonly inputs?: readonly InputField[] | null;
  readonly actions?: readonly Action[] | null;
}

export class SensorParams {
  readonly kind = "sensor";
  readonly protection: Sensor;
  readonly script: string;
  readonly cookies: Cookies | null;
  readonly inputs: readonly InputField[] | null;
  readonly actions: readonly Action[] | null;

  constructor(protection: Sensor, script: string, options: SensorOptions = {}) {
    if (!(protection instanceof Sensor))
      throw new TypeError("SensorParams requires a Sensor protection");
    if (typeof script !== "string")
      throw new TypeError("script must be source text");
    this.protection = protection;
    this.script = script;
    this.cookies = options.cookies ?? null;
    this.inputs = options.inputs ?? null;
    this.actions = options.actions ?? null;
    Object.freeze(this);
  }
}

export class SbsdParams {
  readonly kind = "sbsd";
  readonly protection: Sbsd;
  readonly script: string;
  readonly cookies: Cookies | null;

  constructor(
    protection: Sbsd,
    script: string,
    options: Pick<SensorOptions, "cookies"> = {},
  ) {
    if (!(protection instanceof Sbsd))
      throw new TypeError("SbsdParams requires an Sbsd protection");
    if (typeof script !== "string")
      throw new TypeError("script must be source text");
    this.protection = protection;
    this.script = script;
    this.cookies = options.cookies ?? null;
    Object.freeze(this);
  }
}

export type Params = PixelParams | SensorParams | SbsdParams;

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
