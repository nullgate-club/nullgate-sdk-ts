import { setTimeout as sleep } from "node:timers/promises";
import { inspect } from "node:util";
import { selectAll } from "css-select";
import {
  type AnyNode,
  type Document,
  DomHandler,
  type Element,
} from "domhandler";
import { Parser } from "htmlparser2";
import { type Cookies, type InputValue, prepareInputs } from "./akamai.js";
import { NullgateAPIError, NullgateProtocolError } from "./errors.js";
import { Page } from "./models.js";
import type { OperationOptions } from "./solution.js";

/** FWCIM accepts event facts and local summaries, never an input value. */
export interface FwcimAction {
  readonly type: string;
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
  readonly geometry?: FwcimGeometry;
  /** Explicit opt-in to sending this same nonpassword value for canvas rendering. */
  readonly text?: string;
}

export interface PreparedFwcimInput {
  readonly attributes: Readonly<Record<string, string>>;
  readonly value: InputValue;
  readonly checksum: number;
  readonly selector?: string;
  readonly geometry?: FwcimGeometry;
  readonly text?: string;
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

function documentFor(page: Page) {
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
  return document;
}

/** Match the actual HTML control before handling any raw observation. */
export function prepareFwcimInputs(
  page: Page,
  inputs: readonly FwcimInput[],
): PreparedFwcimInput[] {
  const document = documentFor(page);
  return prepareDocumentInputs(document, detached(inputs));
}

function prepareDocumentInputs(
  document: Document,
  inputs: readonly FwcimInput[],
  form?: Element,
): PreparedFwcimInput[] {
  const controls = selectAll<AnyNode, Element>(
    "input,textarea",
    document.children,
  );
  return inputs.map((input) => {
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
    if (!input.selector && !input.id && !input.name)
      throw new TypeError("FWCIM inputs require id, name, or selector");
    if (input.selector !== undefined && !input.selector.trim())
      throw new TypeError("Invalid FWCIM input selector");
    let matches = controls;
    try {
      matches = input.selector
        ? selectAll<AnyNode, Element>(input.selector, document.children)
        : controls.filter(
            (node) =>
              (!input.id || node.attribs.id === input.id) &&
              (!input.name || node.attribs.name === input.name),
          );
    } catch {
      throw new TypeError("Invalid FWCIM input selector");
    }
    const node = matches[0];
    if (
      matches.length !== 1 ||
      node === undefined ||
      !["input", "textarea"].includes(node.name) ||
      (input.id && node.attribs.id !== input.id) ||
      (input.name && node.attribs.name !== input.name)
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
    if (sensitiveControl(node))
      throw new TypeError("Password observations are not allowed");
    const value = input.value ?? "";
    if (input.text !== undefined && input.text !== value)
      throw new TypeError("FWCIM canvas text must match the observed value");
    if (input.geometry !== undefined) {
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
    const [prepared] = prepareInputs([
      {
        ...(input.id === undefined ? {} : { id: input.id }),
        ...(input.name === undefined ? {} : { name: input.name }),
        ...(input.selector === undefined ? {} : { selector: input.selector }),
        value,
      },
    ]);
    if (prepared === undefined) throw new TypeError("Missing input summary");
    return {
      ...prepared,
      checksum: checksum(value),
      ...(input.geometry === undefined
        ? {}
        : { geometry: { ...input.geometry } }),
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
      typeof action.type !== "string"
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

export interface FwcimOptions {
  /** Actual caller observations, not synthesized browser measurements. */
  readonly performanceTiming: Readonly<Record<string, number>>;
  readonly cookies?: Cookies;
  readonly formSelector?: string;
  readonly inputs?: readonly FwcimInput[];
  readonly actions?: readonly FwcimAction[];
  readonly submitted?: boolean;
  readonly referrer?: string;
  readonly historyLength?: number;
}

export class FwcimParams {
  readonly page: Page;
  readonly #body: string;

  constructor(page: Page, options: FwcimOptions) {
    const document = documentFor(page);
    options = detached(options);
    if (
      !options?.performanceTiming ||
      typeof options.performanceTiming !== "object" ||
      Array.isArray(options.performanceTiming) ||
      page.startedAtMs <= 0 ||
      Object.values(options.performanceTiming).some(
        (value) =>
          !Number.isSafeInteger(value) ||
          value < 0 ||
          (value !== 0 && value < page.startedAtMs),
      ) ||
      options.performanceTiming.navigationStart !== page.startedAtMs
    )
      throw new TypeError(
        "Observed performanceTiming.navigationStart must match Page.startedAtMs",
      );
    if (
      options.formSelector !== undefined &&
      (typeof options.formSelector !== "string" || !options.formSelector.trim())
    )
      throw new TypeError("formSelector must be nonempty");
    let form: Element | undefined;
    if (options.formSelector !== undefined) {
      let matches: Element[];
      try {
        matches = selectAll<AnyNode, Element>(
          options.formSelector,
          document.children,
        );
      } catch {
        throw new TypeError("Invalid formSelector CSS selector");
      }
      form = matches[0];
      if (matches.length !== 1 || form?.name !== "form")
        throw new TypeError("formSelector must select exactly one form");
    }
    if (
      options.historyLength !== undefined &&
      (!Number.isSafeInteger(options.historyLength) ||
        options.historyLength < 1)
    )
      throw new TypeError("historyLength must be a positive integer");
    if (options.referrer !== undefined && typeof options.referrer !== "string")
      throw new TypeError("referrer must be a string");
    if (
      options.submitted !== undefined &&
      typeof options.submitted !== "boolean"
    )
      throw new TypeError("submitted must be a boolean");
    if (
      options.cookies !== undefined &&
      (options.cookies === null ||
        typeof options.cookies !== "object" ||
        Array.isArray(options.cookies) ||
        Object.values(options.cookies).some(
          (value) => typeof value !== "string",
        ))
    )
      throw new TypeError("cookies must be a string mapping");
    this.page = page;
    this.#body = JSON.stringify({
      website: {
        url: page.url,
        html: page.html,
        document_id: page.documentId,
        started_at_ms: page.startedAtMs,
        ...(options.referrer === undefined
          ? {}
          : { referrer: options.referrer }),
        ...(options.historyLength === undefined
          ? {}
          : { history_length: options.historyLength }),
      },
      ...(options.cookies === undefined ? {} : { cookies: options.cookies }),
      ...(options.formSelector === undefined
        ? {}
        : { form_selector: options.formSelector }),
      ...(options.inputs === undefined
        ? {}
        : { inputs: prepareDocumentInputs(document, options.inputs, form) }),
      ...(options.actions === undefined
        ? {}
        : { actions: prepareFwcimActions(options.actions) }),
      submitted: options.submitted ?? true,
      performance_timing: options.performanceTiming,
    });
    Object.freeze(this);
  }

  /** @internal */
  _request(timezone: string | undefined): PreparedFwcimRequest {
    return {
      operation: "fwcim",
      body:
        timezone === undefined
          ? this.#body
          : JSON.stringify({ ...JSON.parse(this.#body), timezone }),
    };
  }
}

/** @internal */
export interface PreparedFwcimRequest {
  readonly operation: "fwcim";
  readonly body: string;
}

export interface FwcimSolutionData {
  readonly metadata1: string;
  readonly sendAt: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly requestId: string;
}

/** Sensitive form field, not a ready login request. Never log metadata1. */
export class FwcimSolution {
  readonly #metadata1: string;
  readonly sendAt: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly requestId: string;

  constructor(data: FwcimSolutionData) {
    this.#metadata1 = data.metadata1;
    this.sendAt = data.sendAt;
    this.headers = Object.freeze({ ...data.headers });
    this.requestId = data.requestId;
    Object.freeze(this);
  }

  get metadata1(): string {
    return this.#metadata1;
  }

  [inspect.custom](): string {
    return `FwcimSolution { metadata1: [REDACTED], sendAt: ${this.sendAt} }`;
  }

  async wait(options: OperationOptions = {}): Promise<void> {
    options.signal?.throwIfAborted();
    let remaining = this.sendAt * 1000 - Date.now();
    while (remaining > 0) {
      await sleep(
        Math.min(remaining, 2_147_483_647),
        undefined,
        options.signal === undefined ? {} : { signal: options.signal },
      );
      remaining = this.sendAt * 1000 - Date.now();
    }
  }
}

/** @internal */
export function normalizeFwcimResponse(
  response: Response,
  body: unknown,
): FwcimSolutionData {
  const requestId = response.headers.get("X-Request-ID");
  if (!response.ok)
    throw new NullgateAPIError(
      response.status,
      requestId,
      body !== null && typeof body === "object" && "detail" in body
        ? body.detail
        : body,
      body !== null && typeof body === "object" && "error" in body
        ? body.error
        : undefined,
    );
  const invalid = (message: string): never => {
    throw new NullgateProtocolError(message, response.status, requestId);
  };
  if (!requestId) return invalid("missing X-Request-ID");
  if (body === null || typeof body !== "object" || Array.isArray(body))
    return invalid("expected a JSON object");
  const data = body as {
    metadata1?: unknown;
    send_at?: unknown;
    headers?: unknown;
  };
  if (typeof data.metadata1 !== "string" || !data.metadata1)
    return invalid("metadata1 must be a nonempty string");
  if (typeof data.send_at !== "number" || !Number.isFinite(data.send_at))
    return invalid("send_at must be a finite Unix timestamp");
  if (
    data.headers === null ||
    typeof data.headers !== "object" ||
    Array.isArray(data.headers)
  )
    return invalid("headers must be a string mapping");
  const headers = new Headers();
  for (const [name, value] of Object.entries(data.headers)) {
    if (typeof value !== "string")
      return invalid("headers must be a string mapping");
    try {
      headers.set(name, value);
    } catch {
      return invalid("headers contain an invalid HTTP field");
    }
  }
  return {
    metadata1: data.metadata1,
    sendAt: data.send_at,
    headers: Object.fromEntries(headers),
    requestId,
  };
}
