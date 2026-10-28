export function httpURL(value: string, name: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError(`${name} must be an absolute HTTP(S) URL`);
  }
  if (!["http:", "https:"].includes(url.protocol) || !url.hostname) {
    throw new TypeError(`${name} must be an absolute HTTP(S) URL`);
  }
  return url;
}

/** Caller-owned document. Discovery never fetches or executes its contents. */
export class Page {
  readonly url: string;
  readonly html: string;

  constructor(url: string, html: string) {
    httpURL(url, "Page.url");
    if (typeof html !== "string")
      throw new TypeError("Page.html must be a string");
    this.url = url;
    this.html = html;
    Object.freeze(this);
  }
}

/** A classic script occurrence; columns and offsets use JavaScript UTF-16 indices. */
export interface ScriptReference {
  readonly rawSource: string;
  readonly tagIndex: number;
  readonly line: number;
  readonly column: number;
}

export type JsonValue =
  | string
  | number
  | boolean
  | null
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };
