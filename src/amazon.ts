import { selectAll } from "css-select";
import {
  type AnyNode,
  type Document,
  DomHandler,
  type Element,
} from "domhandler";
import { Parser } from "htmlparser2";
import {
  type InputValue,
  type PreparedInput,
  prepareInputs,
  validatePreparedInput,
} from "./akamai.js";
import { Page } from "./models.js";

export interface AcicPowOptions {
  readonly challengeType: string;
  readonly html: string;
  /** Unix milliseconds, within 10 minutes before or 1 minute after server time. */
  readonly startedAtMs?: number | null;
}
export interface AcicWafOptions {
  readonly problem: Readonly<Record<string, unknown>>;
}
export interface AcicWafResult {
  readonly clientSolution: number[];
}
export interface AcicWafVerificationOptions {
  readonly problem: {
    readonly state: unknown;
    readonly key: unknown;
    readonly hmac_tag: unknown;
  };
  readonly solution: readonly number[];
  readonly elapsedMs: number;
  readonly locale: string;
}

/** Build the body that the caller sends to AWS. */
export function acicWafVerificationBody(options: AcicWafVerificationOptions) {
  return {
    state: options.problem.state,
    key: options.problem.key,
    hmac_tag: options.problem.hmac_tag,
    client_solution: options.solution,
    metrics: { solve_time_millis: Math.trunc(options.elapsedMs) },
    locale: options.locale,
  };
}

/** FWCIM accepts event facts and local summaries, never an input value. */
export interface FwcimAction {
  readonly type?: string;
  readonly value?: never;
  readonly target?: number | null;
  readonly target_path?: string;
  readonly pointer_type?: string;
  readonly trusted?: boolean | null;
  readonly shift?: boolean | null;
  readonly ctrl?: boolean | null;
  readonly alt?: boolean | null;
  readonly meta?: boolean | null;
  readonly absolute?: boolean | null;
  readonly time?: number | null;
  readonly x?: number | null;
  readonly y?: number | null;
  readonly button?: number | null;
  readonly which?: number | null;
  readonly pointer_id?: number | null;
  readonly key_code?: number | null;
  readonly char_code?: number | null;
  readonly alpha?: number | null;
  readonly beta?: number | null;
  readonly gamma?: number | null;
  readonly interval?: number | null;
  readonly touches?: readonly {
    readonly x: number;
    readonly y: number;
    readonly identifier?: number;
  }[];
  readonly acceleration?:
    | readonly [number | null, number | null, number | null]
    | null;
  readonly acceleration_with_gravity?:
    | readonly [number | null, number | null, number | null]
    | null;
  readonly rotation_rate?:
    | readonly [number | null, number | null, number | null]
    | null;
  readonly input_summary?: readonly [
    number,
    readonly [number, number, number, number] | null,
  ];
}

// Snapshot once without invoking serialization hooks or retaining caller objects.
function detached<T>(value: T, ancestors = new Set<object>()): T {
  if (value === null || typeof value === "string" || typeof value === "boolean")
    return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value !== "object" || ancestors.has(value))
    throw new TypeError("Invalid FWCIM action or input observation shape");
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return Array.from(value, (field) => detached(field, ancestors)) as T;
    }
    return Object.fromEntries(
      Object.entries(value).map(([key, field]) => [
        key,
        field === undefined ? undefined : detached(field, ancestors),
      ]),
    ) as T;
  } finally {
    ancestors.delete(value);
  }
}
export interface FwcimGeometry {
  readonly left?: number;
  readonly top?: number;
  readonly width: number;
  readonly height: number;
}

/** Raw nonpassword observations, summarized locally before transport. */
export interface FwcimInput {
  readonly id?: string;
  readonly name?: string;
  readonly selector?: string;
  readonly value?: string;
  readonly geometry?: FwcimGeometry | null;
  /** Explicit opt-in to sending this same nonpassword value for canvas rendering. */
  readonly text?: string;
}

export interface PreparedFwcimInput {
  readonly attributes: Readonly<Record<string, string>>;
  readonly value: InputValue;
  readonly checksum?: number | null;
  readonly selector?: string;
  readonly geometry?: FwcimGeometry | null;
  readonly text?: string | null;
}

// CRC32 over CESU-8: encode each JavaScript UTF-16 code unit independently.
function checksum(value: string): number {
  let crc = 0xffffffff;
  const byte = (value: number): void => {
    crc ^= value;
    for (let bit = 0; bit < 8; bit += 1)
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  };
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit < 0x80) byte(unit);
    else if (unit < 0x800) {
      byte(0xc0 | (unit >> 6));
      byte(0x80 | (unit & 63));
    } else {
      byte(0xe0 | (unit >> 12));
      byte(0x80 | ((unit >> 6) & 63));
      byte(0x80 | (unit & 63));
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function sensitiveControl(node: Element): boolean {
  const normalize = (value: string | undefined) => value?.trim().toLowerCase();
  return (
    normalize(node.attribs.type) === "password" ||
    (normalize(node.attribs.autocomplete)
      ?.split(/\s+/)
      .some(
        (token) => token === "current-password" || token === "new-password",
      ) ??
      false) ||
    [node.attribs.id, node.attribs.name].some((value) =>
      ["password", "ap_password"].includes(normalize(value) ?? ""),
    )
  );
}

export function documentFor(page: Page) {
  if (!(page instanceof Page)) throw new TypeError("FWCIM requires a Page");
  const handler = new (class extends DomHandler {
    #nonemptyValue = "";
    onattribute(name: string, value: string) {
      // Every duplicate value remains in the original HTML sent to the service.
      if (name === "value" && value) this.#nonemptyValue = value;
    }
    override onopentag(name: string, attributes: Record<string, string>) {
      if (this.#nonemptyValue) attributes.value = this.#nonemptyValue;
      this.#nonemptyValue = "";
      super.onopentag(name, attributes);
    }
  })();
  new Parser(handler).end(page.html);
  const document = handler.root;
  if (
    // Raw HTML privacy includes template content, unlike native input selection.
    selectAll<AnyNode, Element>("input,textarea", document.children, {
      xmlMode: true,
    }).some(
      (node) =>
        sensitiveControl(node) &&
        Boolean(
          node.attribs.value ||
            (node.name === "textarea" &&
              node.children.some(
                (child) => child.type === "text" && child.data.length > 0,
              )),
        ),
    )
  )
    throw new TypeError("Page HTML must not contain password values");
  for (const template of selectAll<AnyNode, Element>(
    "template",
    document.children,
  ))
    template.children = [];
  return document;
}

export function inputFields<T extends FwcimInput | PreparedFwcimInput>(
  page: Page,
  inputs: Readonly<Record<string, string>> | readonly T[] | null | undefined,
): (T | FwcimInput)[] {
  if (Array.isArray(inputs)) return [...inputs];
  const document = documentFor(page);
  const elements = selectAll<AnyNode, Element>("*", document.children);
  return Object.entries(inputs ?? {}).map(([key, value]) =>
    elements.some((node) => node.attribs.id === key)
      ? { id: key, value }
      : { name: key, value },
  );
}

/** Match the actual HTML control before handling any raw observation. */
export function prepareFwcimInputs(
  page: Page,
  inputs: readonly (FwcimInput | PreparedFwcimInput)[],
): PreparedFwcimInput[] {
  const document = documentFor(page);
  return prepareDocumentInputs(document, detached(inputs));
}

function prepareDocumentInputs(
  document: Document,
  inputs: readonly (FwcimInput | PreparedFwcimInput)[],
  form?: Element,
): PreparedFwcimInput[] {
  const controls = selectAll<AnyNode, Element>(
    "input,textarea",
    document.children,
  );
  return inputs.map((observation) => {
    let prepared: PreparedInput | undefined;
    let input: FwcimInput;
    if ("attributes" in observation) {
      const {
        checksum: observedChecksum,
        text,
        geometry,
        ...summary
      } = observation;
      prepared = validatePreparedInput(summary);
      if (
        Object.keys(prepared.attributes).some(
          (key) => !["id", "name"].includes(key),
        ) ||
        ("checksum" in observation &&
          observedChecksum !== null &&
          (!Number.isInteger(observedChecksum) ||
            Number(observedChecksum) < 0 ||
            Number(observedChecksum) >= 2 ** 32)) ||
        ("text" in observation && text !== null && typeof text !== "string") ||
        ("geometry" in observation &&
          geometry !== null &&
          (typeof geometry !== "object" || Array.isArray(geometry)))
      )
        throw new TypeError("Invalid prepared FWCIM input");
      input = {
        ...prepared.attributes,
        ...(prepared.selector === undefined
          ? {}
          : { selector: prepared.selector }),
        ...(geometry === undefined ? {} : { geometry }),
      };
    } else input = observation;
    if (
      Object.keys(input).some(
        (key) =>
          !["id", "name", "selector", "value", "geometry", "text"].includes(
            key,
          ),
      ) ||
      [input.id, input.name, input.selector, input.value, input.text].some(
        (value) => value !== undefined && typeof value !== "string",
      )
    )
      throw new TypeError("Invalid FWCIM input observation");
    if (
      input.selector === undefined &&
      input.id === undefined &&
      input.name === undefined
    )
      throw new TypeError("FWCIM inputs require id, name, or selector");
    if (input.selector !== undefined && !input.selector.trim())
      throw new TypeError("Invalid FWCIM input selector");
    let matches = controls;
    try {
      matches = input.selector
        ? selectAll<AnyNode, Element>(input.selector, document.children)
        : controls.filter(
            (node) =>
              (input.id === undefined || node.attribs.id === input.id) &&
              (input.name === undefined || node.attribs.name === input.name),
          );
    } catch {
      throw new TypeError("Invalid FWCIM input selector");
    }
    const node = matches[0];
    if (
      matches.length !== 1 ||
      node === undefined ||
      !["input", "textarea"].includes(node.name) ||
      (input.id !== undefined && node.attribs.id !== input.id) ||
      (input.name !== undefined && node.attribs.name !== input.name)
    )
      throw new TypeError(
        "FWCIM input must identify exactly one matching control",
      );
    if (form !== undefined) {
      // The collector queries descendants, not HTML form-associated controls.
      let ancestor: AnyNode | null = node.parent;
      while (ancestor && ancestor !== form) ancestor = ancestor.parent;
      const belongs = ancestor === form;
      if (!belongs)
        throw new TypeError("FWCIM input must belong to the selected form");
    }
    if (
      sensitiveControl(node) &&
      (!prepared || "checksum" in observation || "text" in observation)
    )
      throw new TypeError("Password observations are not allowed");
    const value = input.value ?? "";
    if (!prepared && input.text !== undefined && input.text !== value)
      throw new TypeError("FWCIM canvas text must match the observed value");
    if (input.geometry != null) {
      const geometry = input.geometry;
      if (
        Object.keys(geometry).some(
          (key) => !["left", "top", "width", "height"].includes(key),
        ) ||
        Object.values(geometry).some(
          (value) => typeof value !== "number" || !Number.isFinite(value),
        ) ||
        !Number.isFinite(geometry.width) ||
        !Number.isFinite(geometry.height) ||
        geometry.width < 0 ||
        geometry.height < 0
      )
        throw new TypeError(
          "FWCIM geometry requires finite nonnegative dimensions",
        );
    }
    if (prepared) {
      const original = observation as PreparedFwcimInput;
      return {
        ...prepared,
        ...("checksum" in original ? { checksum: original.checksum } : {}),
        ...("geometry" in original ? { geometry: original.geometry } : {}),
        ...("text" in original ? { text: original.text } : {}),
      } as PreparedFwcimInput;
    }
    const [hashed] = prepareInputs([
      {
        ...(input.id === undefined ? {} : { id: input.id }),
        ...(input.name === undefined ? {} : { name: input.name }),
        ...(input.selector === undefined ? {} : { selector: input.selector }),
        value,
      },
    ]);
    if (hashed === undefined) throw new TypeError("Missing input summary");
    return {
      ...hashed,
      checksum: checksum(value),
      ...(input.geometry === undefined
        ? {}
        : { geometry: input.geometry === null ? null : { ...input.geometry } }),
      ...(input.text === undefined ? {} : { text: input.text }),
    };
  });
}

const actionStrings = ["type", "target_path", "pointer_type"];
const actionBooleans = ["trusted", "shift", "ctrl", "alt", "meta", "absolute"];
const actionNumbers = [
  "time",
  "x",
  "y",
  "button",
  "which",
  "pointer_id",
  "key_code",
  "char_code",
  "alpha",
  "beta",
  "gamma",
  "interval",
];

function finiteOrNull(value: unknown): boolean {
  return (
    value === null || (typeof value === "number" && Number.isFinite(value))
  );
}

function numericObject(value: unknown, keys: readonly string[]): boolean {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.entries(value).every(
      ([key, field]) => keys.includes(key) && finiteOrNull(field),
    )
  );
}

function prepareFwcimActions(
  actions: readonly FwcimAction[],
): readonly FwcimAction[] {
  if (!Array.isArray(actions))
    throw new TypeError("FWCIM actions must be an array");
  for (const action of actions) {
    if (
      action === null ||
      typeof action !== "object" ||
      Array.isArray(action) ||
      (action.type !== undefined && typeof action.type !== "string")
    )
      throw new TypeError("Invalid FWCIM action");
    for (const [key, value] of Object.entries(action)) {
      let valid = false;
      if (actionStrings.includes(key)) valid = typeof value === "string";
      else if (actionBooleans.includes(key))
        valid = value === null || typeof value === "boolean";
      else if (actionNumbers.includes(key)) valid = finiteOrNull(value);
      else if (key === "target")
        valid =
          value === null ||
          (typeof value === "number" && Number.isInteger(value));
      else if (key === "touches")
        valid =
          Array.isArray(value) &&
          value.every(
            (touch) =>
              numericObject(touch, ["x", "y", "identifier"]) &&
              typeof touch.x === "number" &&
              Number.isFinite(touch.x) &&
              typeof touch.y === "number" &&
              Number.isFinite(touch.y) &&
              (!("identifier" in touch) || Number.isInteger(touch.identifier)),
          );
      else if (
        key === "acceleration" ||
        key === "acceleration_with_gravity" ||
        key === "rotation_rate"
      )
        valid =
          value === null ||
          (Array.isArray(value) &&
            value.length === 3 &&
            value.every(finiteOrNull));
      else if (key === "input_summary")
        valid =
          Array.isArray(value) &&
          value.length === 2 &&
          typeof value[0] === "number" &&
          Number.isInteger(value[0]) &&
          value[0] >= 0 &&
          (value[1] === null ||
            (Array.isArray(value[1]) &&
              value[1].length === 4 &&
              value[1].every(
                (count) =>
                  typeof count === "number" &&
                  Number.isInteger(count) &&
                  count >= 0,
              )));
      if (!valid) throw new TypeError("Invalid FWCIM action field");
    }
  }
  return actions;
}

export function prepareFwcim(
  page: Page,
  formSelector: string | null,
  timing: Readonly<Record<string, number>>,
  inputs: readonly (FwcimInput | PreparedFwcimInput)[] | null | undefined,
  actions: readonly FwcimAction[] | null | undefined,
  options: {
    submitted?: boolean;
    referrer?: string;
    historyLength?: number | null;
  } = {},
): Record<string, unknown> {
  const document = documentFor(page);
  if (
    !timing ||
    !Number.isInteger(timing.navigationStart) ||
    (timing.navigationStart ?? 0) <= 0 ||
    Object.values(timing).some(
      (value) =>
        !Number.isInteger(value) ||
        value < 0 ||
        (value !== 0 && value < (timing.navigationStart ?? 0)),
    )
  )
    throw new TypeError(
      "timing must contain observed navigationStart milliseconds",
    );
  let form: Element | undefined;
  if (formSelector !== null) {
    let matches: Element[];
    try {
      if (!formSelector.trim()) throw new TypeError("Invalid form selector");
      matches = selectAll<AnyNode, Element>(formSelector, document.children);
    } catch {
      throw new TypeError("Invalid form selector");
    }
    form = matches[0];
    if (matches.length !== 1 || form?.name !== "form")
      throw new TypeError("form must select exactly one form");
  }
  if (
    ("submitted" in options && typeof options.submitted !== "boolean") ||
    ("referrer" in options && typeof options.referrer !== "string") ||
    (options.historyLength != null &&
      (!Number.isInteger(options.historyLength) || options.historyLength < 1))
  )
    throw new TypeError("Invalid FWCIM submitted, referrer, or historyLength");
  return {
    ...(formSelector === null ? {} : { form_selector: formSelector }),
    referrer: options.referrer ?? "",
    submitted: options.submitted ?? true,
    ...(options.historyLength == null
      ? {}
      : { history_length: options.historyLength }),
    performance_timing: { ...timing },
    ...(inputs == null
      ? {}
      : { inputs: prepareDocumentInputs(document, detached(inputs), form) }),
    ...(actions == null
      ? {}
      : { actions: prepareFwcimActions(detached(actions)) }),
  };
}
