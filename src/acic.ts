import { Parser } from "htmlparser2";
import type { TargetRequest } from "./threatmetrix.js";

const hosts: Record<string, string> = {
  NA: "com",
  US: "com",
  EU: "de",
  DE: "de",
  FE: "co.jp",
  JP: "co.jp",
  CA: "ca",
  MX: "com.mx",
  AT: "at",
  SG: "sg",
  AU: "com.au",
  PL: "pl",
  TR: "com.tr",
  IT: "it",
  AE: "ae",
  GB: "co.uk",
  UK: "co.uk",
  SA: "sa",
  IN: "in",
  FR: "fr",
  ES: "es",
  NL: "nl",
  SE: "se",
  BR: "com.br",
  EG: "eg",
};

function secureURL(value: string, base?: string): URL {
  let url: URL;
  try {
    url = new URL(value, base);
  } catch {
    throw new TypeError("Invalid ACIC URL");
  }
  if (url.protocol !== "https:" || url.username || url.password || url.hash)
    throw new TypeError(
      "ACIC URL must use HTTPS without credentials or a fragment",
    );
  return url;
}

interface PageData {
  scripts: string[];
  sources: string[];
  forms: { action: string; method: string; fields: [string, string][] }[];
}

function pageData(html: string): PageData {
  const data: PageData = { scripts: [], sources: [], forms: [] };
  let script: string | null = null;
  let form: PageData["forms"][number] | null = null;
  const parser = new Parser(
    {
      onopentag(name, attrs) {
        if (name === "script") {
          if (attrs.src !== undefined) data.sources.push(attrs.src);
          else script = "";
        }
        if (name === "form" && attrs.id === "cvf-aamation-challenge-form") {
          form = {
            action: attrs.action ?? "",
            method: attrs.method ?? "get",
            fields: [],
          };
          data.forms.push(form);
        }
        if (
          form &&
          name === "input" &&
          (attrs.type ?? "text").toLowerCase() === "hidden" &&
          attrs.name !== undefined &&
          attrs.disabled === undefined
        )
          form.fields.push([attrs.name, attrs.value ?? ""]);
      },
      ontext(text) {
        if (script !== null) script += text;
      },
      onclosetag(name) {
        if (name === "script" && script !== null) {
          data.scripts.push(script);
          script = null;
        }
        if (name === "form") form = null;
      },
    },
    { decodeEntities: true },
  );
  parser.end(html);
  return data;
}

// Split only at the top level, preserving quoted strings and nested callback bodies.
function splitTop(source: string, separator: string): string[] {
  const parts: string[] = [];
  let start = 0;
  const stack: string[] = [];
  let quote = "";
  for (let i = 0; i < source.length; i++) {
    const c = source[i] ?? "";
    if (quote) {
      if (c === "\\") i++;
      else if (c === quote) quote = "";
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      quote = c;
      continue;
    }
    if ("({[".includes(c)) stack.push(c);
    else if (")}]".includes(c)) {
      const open = stack.pop();
      if (!open || "({[".indexOf(open) !== ")}]".indexOf(c))
        throw new TypeError("Malformed ACIC bootstrap");
    } else if (c === separator && stack.length === 0) {
      parts.push(source.slice(start, i));
      start = i + 1;
    }
  }
  if (quote || stack.length) throw new TypeError("Malformed ACIC bootstrap");
  parts.push(source.slice(start));
  return parts;
}

function literal(source: string): unknown {
  let value = source.trim();
  if (value.startsWith("'")) {
    if (!/^'(?:[^'\\\r\n]|\\(?:['"\\/bfnrt]|u[0-9a-fA-F]{4}))*'$/.test(value))
      throw new TypeError("Unsupported ACIC string literal");
    const inner = value.slice(1, -1).replace(/\\.|"/g, (token) => {
      if (token === "\\'") return "'";
      if (token === '"') return '\\"';
      return token;
    });
    value = `"${inner}"`;
  }
  try {
    return JSON.parse(value) as unknown;
  } catch {
    throw new TypeError("Unsupported ACIC literal");
  }
}

const optionNames: Record<string, string> = {
  "data-context": "clientData",
  "data-challenge-type": "challengeType",
  "data-locale": "locale",
  "data-external-id": "externalId",
  "data-header-footer": "enableHeaderFooter",
  "data-enable-bypass-mechanism": "enableBypassMechanism",
  "data-enable-modal-view": "enableModalView",
  "data-event-trigger": "eventTrigger",
  "data-aa-external-token": "aaExternalToken",
  "data-force-js-flush": "forceJsFlush",
  "data-aamation-token": "aamationToken",
  "data-page-id": "pageId",
};

function bootstrap(script: string, index: number): Record<string, unknown> {
  const rest = script.slice(index);
  const open = rest.indexOf("{");
  if (open < 0 || !/^\s*\{/.test(rest))
    throw new TypeError("Unsupported ACIC setup argument");
  let end = -1;
  let depth = 0;
  let quote = "";
  for (let i = open; i < rest.length; i++) {
    const c = rest[i] ?? "";
    if (quote) {
      if (c === "\\") i++;
      else if (c === quote) quote = "";
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      quote = c;
      continue;
    }
    if (c === "{") depth++;
    if (c === "}" && --depth === 0) {
      end = i;
      break;
    }
  }
  if (end < 0 || !/^\s*\)/.test(rest.slice(end + 1)))
    throw new TypeError("Malformed ACIC setup");
  const values: Record<string, unknown> = {};
  for (const entry of splitTop(rest.slice(open + 1, end), ",")) {
    if (!entry.trim()) continue;
    const match = entry.match(
      /^\s*(?:"([^"]+)"|'([^']+)'|([\w-]+))\s*:\s*([\s\S]*)$/,
    );
    if (!match) throw new TypeError("Unsupported ACIC property");
    const key = match[1] ?? match[2] ?? match[3] ?? "";
    if (Object.hasOwn(values, key))
      throw new TypeError("Duplicate ACIC property");
    if (key === "data-callback") {
      values[key] = true;
      continue;
    }
    if (key === "data-div") {
      const expression = (match[4] ?? "").trim();
      if (!expression || /^(?:null|false|undefined)$/.test(expression))
        throw new TypeError("Invalid ACIC div mount");
      values[key] = true;
      continue;
    }
    if (key.startsWith("data-") || Object.hasOwn(optionNames, key))
      values[key] = literal(match[4] ?? "");
  }
  return values;
}

function requiredString(value: unknown, name: string): string {
  if (typeof value !== "string" || !value)
    throw new TypeError(`Invalid ACIC ${name}`);
  return value;
}

function request(
  role: string,
  url: string,
  headers: Readonly<Record<string, string>>,
  body: string,
): TargetRequest {
  return {
    role,
    url,
    method: "POST",
    headers,
    body: new TextEncoder().encode(body),
    credentials: "include",
    signal: new AbortController().signal,
  };
}

export class Result {
  readonly #actionType: string;
  readonly #sessionToken: string;
  readonly #clientSideContext: unknown;
  constructor(
    actionType: string,
    clientSideContext: unknown,
    sessionToken: string,
  ) {
    this.#actionType = actionType;
    this.#clientSideContext = clientSideContext;
    this.#sessionToken = sessionToken;
  }
  get actionType(): string {
    return this.#actionType;
  }
  get clientSideContext(): unknown {
    return this.#clientSideContext;
  }
  get sessionToken(): string {
    return this.#sessionToken;
  }
  voucherResponse(voucher: string): string {
    if (typeof voucher !== "string") throw new TypeError("Invalid voucher");
    return JSON.stringify({
      challengeType: this.actionType,
      data: JSON.stringify(voucher),
    });
  }
}

export function parseResult(
  headers: Headers | Readonly<Record<string, string>>,
): Result | null {
  const entries =
    headers instanceof Headers
      ? [...headers.entries()]
      : Object.entries(headers);
  const matches = entries.filter(
    ([key]) => key.toLowerCase() === "amz-aamation-resp",
  );
  if (!matches.length) return null;
  if (matches.length !== 1) throw new TypeError("Ambiguous ACIC result header");
  let value: unknown;
  try {
    value = JSON.parse(matches[0]?.[1] ?? "");
  } catch {
    throw new TypeError("Malformed ACIC result header");
  }
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new TypeError("Malformed ACIC result header");
  const result = value as Record<string, unknown>;
  if (!Object.hasOwn(result, "clientSideContext"))
    throw new TypeError("Malformed ACIC result header");
  return new Result(
    requiredString(result.actionType, "action type"),
    result.clientSideContext,
    requiredString(result.sessionToken, "session token"),
  );
}

export class Setup {
  readonly serviceUrl: string;
  readonly locale: string;
  readonly origin: string;
  readonly #options: string;
  readonly #form: PageData["forms"][number] | null;
  readonly #pageUrl: string;
  constructor(
    serviceUrl: string,
    locale: string,
    origin: string,
    options: string,
    form: PageData["forms"][number] | null,
    pageUrl: string,
  ) {
    this.serviceUrl = serviceUrl;
    this.locale = locale;
    this.origin = origin;
    this.#options = options;
    this.#form = form;
    this.#pageUrl = pageUrl;
  }
  start(): TargetRequest {
    return this.#prepare(null, null, "null");
  }
  answer(result: Result, response: string): TargetRequest {
    if (!(result instanceof Result) || typeof response !== "string")
      throw new TypeError("Invalid ACIC answer");
    return this.#prepare(
      result.sessionToken,
      result.clientSideContext,
      response,
    );
  }
  #prepare(
    token: string | null,
    context: unknown,
    response: string,
  ): TargetRequest {
    const url = new URL(
      this.serviceUrl + (token === null ? "" : `/${encodeURIComponent(token)}`),
    );
    if (token !== null) {
      const queryContext =
        typeof context === "string" ? context : JSON.stringify(context);
      if (queryContext === undefined)
        throw new TypeError("Invalid ACIC context");
      url.searchParams.set("context", queryContext);
    }
    url.searchParams.set("options", this.#options);
    if (token !== null) url.searchParams.set("response", response);
    return request(
      "acic",
      url.toString(),
      {
        "Content-Type": "application/json",
        Origin: this.origin,
        Referer: this.#pageUrl,
      },
      JSON.stringify({
        context,
        options: this.#options,
        response,
        fwcimBlob: null,
      }),
    );
  }
  continuation(result: Result): TargetRequest {
    if (!(result instanceof Result) || result.actionType !== "PASS")
      throw new TypeError("ACIC continuation requires PASS");
    if (!this.#form) throw new TypeError("ACIC continuation form is missing");
    if (this.#form.method.toLowerCase() !== "post")
      throw new TypeError("ACIC continuation form must use POST");
    const url = secureURL(this.#form.action || this.#pageUrl, this.#pageUrl);
    if (url.origin !== this.origin)
      throw new TypeError("ACIC continuation form must be same-origin");
    const fields = new URLSearchParams();
    let found = false;
    for (const [name, value] of this.#form.fields) {
      if (name === "cvf_aamation_response_token") {
        fields.append(name, result.sessionToken);
        found = true;
      } else fields.append(name, value);
    }
    if (!found) throw new TypeError("ACIC continuation token field is missing");
    return request(
      "acic-continuation",
      url.toString(),
      {
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: this.origin,
        Referer: this.#pageUrl,
      },
      fields.toString(),
    );
  }
}

export function discover(url: string, html: string): Setup | null {
  const page = secureURL(url);
  const data = pageData(html);
  const calls = data.scripts.flatMap((script) =>
    [...script.matchAll(/\bacic\s*\.\s*setupACIC\s*\(/g)].map((match) => ({
      script,
      index: match.index + match[0].length,
    })),
  );
  if (!calls.length) return null;
  if (calls.length !== 1 || data.forms.length > 1)
    throw new TypeError("Ambiguous ACIC setup");
  const call = calls[0];
  if (!call) throw new TypeError("Malformed ACIC setup");
  const values = bootstrap(call.script, call.index);
  const ref = requiredString(values["data-ref-id"], "ref ID");
  const locale = requiredString(values["data-locale"], "locale");
  const config = requiredString(values["data-host-config"], "host config");
  const hostMatch = /^prod\.([A-Za-z]+)Amazon$/.exec(config);
  const knownHosts = Object.values(hosts).map((item) => `www.amazon.${item}`);
  const currentHost = knownHosts.includes(page.hostname);
  const suffix = hosts[hostMatch?.[1]?.toUpperCase() ?? ""];
  if (!currentHost && !suffix)
    throw new TypeError("Unsupported ACIC host config");
  const hostname = currentHost ? page.hostname : `www.amazon.${suffix}`;
  const iframe = values["data-iframe-id"];
  const hasDiv = Object.hasOwn(values, "data-div");
  if ((iframe !== undefined) === hasDiv)
    throw new TypeError("ACIC setup requires one mount");
  if (iframe !== undefined) requiredString(iframe, "mount");
  const options: Record<string, unknown> = {
    clientData: requiredString(values["data-context"], "context"),
    challengeType: requiredString(
      values["data-challenge-type"],
      "challenge type",
    ),
    locale,
    externalId: requiredString(values["data-external-id"], "external ID"),
    enableHeaderFooter: false,
    enableBypassMechanism: false,
    enableModalView: false,
    eventTrigger: null,
    aaExternalToken: null,
    forceJsFlush: iframe !== undefined,
    aamationToken: null,
    pageId: null,
  };
  for (const [key, target] of Object.entries(optionNames)) {
    if (!Object.hasOwn(values, key)) continue;
    const value = values[key];
    if (
      [
        "enableHeaderFooter",
        "enableBypassMechanism",
        "enableModalView",
        "forceJsFlush",
      ].includes(target) &&
      typeof value !== "boolean"
    )
      throw new TypeError("Invalid ACIC boolean option");
    if (
      ![
        "enableHeaderFooter",
        "enableBypassMechanism",
        "enableModalView",
        "forceJsFlush",
      ].includes(target) &&
      value !== null &&
      typeof value !== "string"
    )
      throw new TypeError("Invalid ACIC option");
    options[target] = value;
  }
  return new Setup(
    `https://${hostname}/aaut/verify/${encodeURIComponent(ref)}`,
    locale,
    page.origin,
    JSON.stringify(options),
    data.forms[0] ?? null,
    page.href,
  );
}

export class Waf {
  readonly problemUrl: string;
  readonly locale: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly roundsRequired: number;
  readonly #provider: string;
  constructor(
    provider: string,
    locale: string,
    origin: string,
    query: URLSearchParams,
    roundsRequired: number,
  ) {
    this.#provider = provider;
    this.problemUrl = `${provider}/problem?${query.toString()}`;
    this.locale = locale;
    this.roundsRequired = roundsRequired;
    this.headers = {
      Origin: origin,
      Referer: `${origin}/`,
      "Content-Type": "text/plain;charset=UTF-8",
    };
  }
  verificationUrl(problem: Readonly<Record<string, unknown>>): string {
    if (
      problem.region !== undefined &&
      problem.region !== null &&
      typeof problem.region !== "string"
    )
      throw new TypeError("Invalid WAF problem region");
    const url = new URL(`${this.#provider}/verify`);
    if (problem.region) url.searchParams.set("region", problem.region);
    return url.toString();
  }
}

export function discoverWaf(url: string, html: string): Waf | null {
  const page = secureURL(url);
  const data = pageData(html);
  const scripts = data.sources.filter((source) =>
    /\/captcha\.js(?:[?#]|$)/.test(source),
  );
  const matches = data.scripts.flatMap((script) => [
    ...script.matchAll(
      /\b(?:const|let|var)\s+wafInputProperties\s*=\s*Object\.assign\s*\(\s*([\s\S]*?)\s*,\s*wafOnLoadProperty\s*\)/g,
    ),
  ]);
  const marker = data.scripts.some((script) =>
    /\bwafInputProperties\s*=/.test(script),
  );
  if (!scripts.length && !marker) return null;
  if (scripts.length !== 1 || matches.length !== 1)
    throw new TypeError("Malformed or ambiguous WAF view");
  const scriptUrl = secureURL(scripts[0] ?? "", page.href);
  if (
    !(
      scriptUrl.hostname === "captcha.awswaf.com" ||
      scriptUrl.hostname.endsWith(".captcha.awswaf.com")
    ) ||
    !scriptUrl.pathname.endsWith("/captcha.js") ||
    scriptUrl.search
  )
    throw new TypeError("Invalid WAF provider URL");
  let value: unknown;
  try {
    value = JSON.parse(matches[0]?.[1] ?? "");
  } catch {
    throw new TypeError("Malformed WAF properties");
  }
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new TypeError("Malformed WAF properties");
  const keys = new Set<string>();
  for (const entry of splitTop(
    (matches[0]?.[1] ?? "").trim().slice(1, -1),
    ",",
  )) {
    const key = JSON.parse(splitTop(entry, ":")[0] ?? "") as string;
    if (keys.has(key)) throw new TypeError("Ambiguous WAF properties");
    keys.add(key);
  }
  const properties = value as Record<string, unknown>;
  const locale = requiredString(
    properties.defaultLocale,
    "WAF locale",
  ).toLowerCase();
  const problem = requiredString(properties.problem, "WAF problem");
  const id = requiredString(properties.id, "WAF ID");
  if (
    !Number.isInteger(properties.visualSolutionsRequired) ||
    (properties.visualSolutionsRequired as number) < 1
  )
    throw new TypeError("Invalid WAF solution count");
  const query = new URLSearchParams({
    kind: "visual",
    domain: page.hostname,
    locale,
    problem,
    num_solutions_required: String(properties.visualSolutionsRequired),
    id,
  });
  return new Waf(
    scriptUrl.origin + scriptUrl.pathname.slice(0, -"/captcha.js".length),
    locale,
    page.origin,
    query,
    properties.visualSolutionsRequired as number,
  );
}
