import { randomUUID } from "node:crypto";
import {
  abckCounters,
  isEnough,
  NullgateClient,
  Page,
  PixelParams,
  type Protection,
  SbsdParams,
  SensorParams,
  type Solution,
} from "@nullgate/sdk";
import { createSession } from "wreq-js";

const userAgent =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";
const targetURL = process.env.TARGET_URL;
const apiKey = process.env.NULLGATE_API_KEY;
if (!targetURL || !apiKey)
  throw new Error("Set TARGET_URL and NULLGATE_API_KEY");
const identity = process.env.NULLGATE_IDENTITY ?? randomUUID();
const cancellation = new AbortController();
const onInterrupt = () => {
  cancellation.abort(new Error("Cancelled"));
};
process.once("SIGINT", onInterrupt);
const signal = AbortSignal.any([
  cancellation.signal,
  AbortSignal.timeout(90_000),
]);
const api = new NullgateClient({
  apiKey,
  ...(process.env.NULLGATE_BASE_URL
    ? { baseURL: process.env.NULLGATE_BASE_URL }
    : {}),
  ...(process.env.ANALYTICS_URL
    ? { analyticsURL: process.env.ANALYTICS_URL }
    : {}),
});
const target = await createSession({
  browser: "chrome_146",
  os: "windows",
  timeout: 30_000,
  defaultHeaders: { "User-Agent": userAgent },
  ...(process.env.TARGET_PROXY ? { proxy: process.env.TARGET_PROXY } : {}),
});

async function script(protection: Protection): Promise<string> {
  const response = await target.fetch(protection.scriptURL, {
    headers: { Referer: protection.page.url },
    redirect: "manual",
    signal,
  });
  if (!response.ok)
    throw new Error(`Script fetch returned HTTP ${response.status}`);
  return response.text();
}

async function submit(solution: Solution, pageURL: string): Promise<void> {
  await solution.wait({ signal });
  const headers = new Headers(solution.headers);
  if (!headers.has("Referer")) headers.set("Referer", pageURL);
  if (!headers.has("Origin")) headers.set("Origin", new URL(pageURL).origin);
  const response = await target.fetch(solution.url, {
    method: solution.method,
    headers: Object.fromEntries(headers),
    body: solution.body,
    redirect: "manual",
    signal,
  });
  await response.text();
  console.log(
    `Target POST: HTTP ${response.status}, request_id=${solution.requestId}`,
  );
  if (!response.ok) {
    console.error(
      "Target rejection is an observation, not proof that generation failed.",
    );
    const delivered = await solution.report({ signal });
    throw new Error(
      `Target rejected POST (HTTP ${response.status}); report delivered=${delivered}`,
    );
  }
}

function generationCookies(
  pageURL: string,
  sensorOnly = false,
): Record<string, string> {
  const scoped = target.getCookies(pageURL);
  const all = target.getAllCookies();
  return Object.fromEntries(
    Object.entries(scoped).filter(([name, value]) => {
      if (sensorOnly && name !== "_abck" && name !== "bm_sz") return false;
      const matching = all.filter(
        (cookie) => cookie.name === name && cookie.value === value,
      );
      if (matching.length === 0)
        throw new Error(
          "Target provider returned a cookie without visibility metadata",
        );
      if (matching.some((cookie) => cookie.httpOnly)) {
        if (matching.some((cookie) => !cookie.httpOnly)) {
          throw new Error(
            "Ambiguous cookie visibility; supply the page's script-visible cookie context explicitly",
          );
        }
        return false;
      }
      return true;
    }),
  );
}

try {
  let response = await target.fetch(targetURL, { signal });
  let completed = false;
  let lastBlocking: Solution | undefined;
  // Each re-fetched document gets a new Nullgate session, not a reused document state.
  for (let document = 0; document < 3; document += 1) {
    const page = new Page(response.url || targetURL, await response.text());
    const found = api.findProtections(page);
    const blocking = found.filter(
      (candidate) => candidate.kind === "sbsd" && candidate.blocking,
    );
    if (blocking.length > 1)
      throw new Error(
        "Ambiguous blocking SBSD candidates; select the intended source explicitly",
      );
    const session = api.open({ identity, userAgent });
    try {
      const block = blocking[0];
      if (block?.kind === "sbsd") {
        if (lastBlocking) {
          await lastBlocking.report({ signal });
          throw new Error(
            "Blocking SBSD remains after one submission and page re-fetch",
          );
        }
        const solution = await session.solve(
          new SbsdParams(block, await script(block), {
            cookies: generationCookies(page.url),
          }),
          { signal },
        );
        await submit(solution, page.url);
        lastBlocking = solution;
        // A successful SBSD POST is not clearance: fetch the original page again.
        response = await target.fetch(targetURL, { signal });
        continue;
      }
      if (!response.ok)
        throw new Error(
          `Target page returned HTTP ${response.status}; no supported blocking flow was discovered`,
        );
      if (found.length === 0) {
        console.log(
          "No supported candidates found; inspect the page for target-specific success.",
        );
        completed = true;
        break;
      }
      for (const kind of ["pixel", "sensor", "sbsd"] as const) {
        if (found.filter((candidate) => candidate.kind === kind).length > 1) {
          throw new Error(
            `Ambiguous ${kind} candidates; select the intended source explicitly`,
          );
        }
      }
      for (const protection of found) {
        if (protection.kind === "sensor") continue;
        const source = await script(protection);
        const params =
          protection.kind === "pixel"
            ? new PixelParams(protection, source)
            : new SbsdParams(protection, source, {
                cookies: generationCookies(page.url),
              });
        await submit(await session.solve(params, { signal }), page.url);
      }
      const sensor = found.find((candidate) => candidate.kind === "sensor");
      if (sensor?.kind === "sensor") {
        const source = await script(sensor);
        let previousGeneration = -1;
        let responseCount = 0;
        let sent = 0;
        while (true) {
          signal.throwIfAborted();
          const cookies = generationCookies(page.url, true);
          const [, generation] = abckCounters(cookies._abck);
          if (generation >= 0 && generation !== previousGeneration) {
            responseCount = 0;
            previousGeneration = generation;
          }
          if (isEnough(cookies._abck, responseCount)) break;
          if (sent >= 4)
            throw new Error(
              "Ordinary-send cookie gate remains open after the diagnostic ceiling; this is not an acceptance verdict",
            );
          const solution = await session.solve(
            new SensorParams(sensor, source, { cookies }),
            { signal },
          );
          await submit(solution, page.url);
          responseCount += 1;
          sent += 1;
        }
        console.log(
          "Ordinary-send cookie gate closed; target acceptance is still caller-specific.",
        );
      }
      response = await target.fetch(targetURL, { signal });
      const verified = new Page(
        response.url || targetURL,
        await response.text(),
      );
      if (
        api
          .findProtections(verified)
          .some((candidate) => candidate.kind === "sbsd" && candidate.blocking)
      ) {
        throw new Error(
          "The original page still presents a blocking SBSD challenge after submission",
        );
      }
      if (!response.ok)
        throw new Error(
          `Target re-fetch returned HTTP ${response.status}; status alone does not identify the cause`,
        );
      console.log(
        `Target re-fetch: HTTP ${response.status}; inspect the body for your target-specific success criterion.`,
      );
      completed = true;
      break;
    } finally {
      session.close();
    }
  }
  if (!completed)
    throw new Error(
      "Document diagnostic ceiling reached; the final target page remains unverified",
    );
} finally {
  process.removeListener("SIGINT", onInterrupt);
  api.close();
  await target.close();
}
