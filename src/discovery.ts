import { Parser } from "htmlparser2";
import { Pixel, type Protection, Sbsd, Sensor } from "./akamai.js";
import { Page, type ScriptReference } from "./models.js";

export interface FindOptions {
  readonly where?: (protection: Protection) => boolean;
}

/** Retain ambiguous candidates and occurrences; never fetch or execute a script. */
export function findProtections(
  page: Page,
  options: FindOptions = {},
): Protection[] {
  if (!(page instanceof Page))
    throw new TypeError("findProtections requires a Page");
  if (options.where !== undefined && typeof options.where !== "function") {
    throw new TypeError("where must be a protection predicate");
  }
  const document = new URL(page.url);
  let baseSource: string | undefined;
  const sources: ScriptReference[] = [];
  const challenges = new Map<string, number>();
  const inert: string[] = [];
  let inline = false;
  let scriptIndex = 0;
  const lineStarts = [0];
  for (const match of page.html.matchAll(/\n/g))
    lineStarts.push(match.index + 1);
  const parser = new Parser(
    {
      onopentag(tag, attributes) {
        const index = scriptIndex;
        if (tag === "script") scriptIndex += 1;
        if (tag === "template" || tag === "noscript") inert.push(tag);
        if (inert.length > 0) return;
        if (
          tag === "base" &&
          baseSource === undefined &&
          Object.hasOwn(attributes, "href")
        ) {
          baseSource = (attributes.href ?? "").trim();
        }
        if (tag !== "script") return;
        const scriptType = (attributes.type ?? "").trim().toLowerCase();
        inline =
          !Object.hasOwn(attributes, "nomodule") &&
          ["", "text/javascript", "application/javascript"].includes(
            scriptType,
          );
        if (!inline) return;
        const source = (attributes.src ?? "").trim();
        if (source) {
          let low = 0;
          let high = lineStarts.length;
          while (low + 1 < high) {
            const middle = Math.floor((low + high) / 2);
            if ((lineStarts[middle] ?? 0) <= parser.startIndex) low = middle;
            else high = middle;
          }
          sources.push(
            Object.freeze({
              rawSource: source,
              tagIndex: index,
              line: low + 1,
              column: parser.startIndex - (lineStarts[low] ?? 0),
            }),
          );
        }
        if (Object.hasOwn(attributes, "src")) inline = false;
      },
      ontext(data) {
        if (inert.length > 0 || !inline) return;
        // Python's Unicode word boundary excludes letters/numbers before the marker.
        for (const match of data.matchAll(
          /(?<![\p{L}\p{N}_])bazadebezolkohpepadr\s*=\s*(['"])([0-9]+)\1/gu,
        )) {
          const challenge = match[2];
          if (challenge !== undefined && !challenges.has(challenge)) {
            challenges.set(challenge, parser.startIndex + match.index);
          }
        }
      },
      onclosetag(tag) {
        if (tag === "script") inline = false;
        if (inert.at(-1) === tag) inert.pop();
      },
    },
    { decodeEntities: true, recognizeSelfClosing: true },
  );
  parser.end(page.html);
  let base = document;
  try {
    const candidate = new URL(baseSource ?? "", document);
    if (candidate.protocol === "http:" || candidate.protocol === "https:")
      base = candidate;
  } catch {
    // A malformed or non-HTTP base does not invalidate the caller's document.
  }
  const found: Protection[] = [];
  for (const reference of sources) {
    let source: URL;
    try {
      source = new URL(reference.rawSource, base);
    } catch {
      continue;
    }
    if (source.origin !== document.origin) continue;
    source.hash = "";
    const scriptURL = source.href;
    const path = source.pathname.replace(/(?:%[0-9a-f]{2})+/gi, (encoded) =>
      Buffer.from(encoded.replaceAll("%", ""), "hex").toString("utf8"),
    );
    if (/^\/akam\/13\/[0-9a-fA-F]+$/.test(path)) {
      for (const [challenge, challengeOffset] of challenges) {
        found.push(
          new Pixel(page, scriptURL, challenge, {
            provenance: reference,
            challengeOffset,
          }),
        );
      }
      continue;
    }
    // Deliberately inspect raw parameter names/values, not URLSearchParams decoding.
    const query = new Map<string, string[]>();
    for (const part of source.search.slice(1).split("&")) {
      const separator = part.indexOf("=");
      const name = separator < 0 ? part : part.slice(0, separator);
      const value = separator < 0 ? "" : part.slice(separator + 1);
      const values = query.get(name) ?? [];
      values.push(value);
      query.set(name, values);
    }
    const versions = query.get("v") ?? [];
    if (
      versions.some((version) =>
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
          version,
        ),
      )
    ) {
      if (versions.length === 1 && (query.get("t")?.length ?? 0) <= 1) {
        found.push(new Sbsd(page, scriptURL, { provenance: reference }));
      }
      continue;
    }
    if (path && !/\.(?:js|mjs|cjs)$/i.test(path)) {
      found.push(new Sensor(page, scriptURL, { provenance: reference }));
    }
  }
  return options.where === undefined ? found : found.filter(options.where);
}
