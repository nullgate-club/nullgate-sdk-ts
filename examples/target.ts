import { randomUUID } from "node:crypto";
import {
  NullgateClient,
  Page,
  PixelParams,
  SbsdParams,
  SensorParams,
} from "@nullgate/sdk";
import { createSession } from "wreq-js";

const targetURL = process.env.TARGET_URL;
const apiKey = process.env.NULLGATE_API_KEY;
if (!targetURL || !apiKey)
  throw new Error("Set TARGET_URL and NULLGATE_API_KEY");
const userAgent =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";
const target = await createSession({
  browser: "chrome_146",
  os: "windows",
  timeout: 30_000,
  defaultHeaders: { "User-Agent": userAgent },
});
const api = new NullgateClient({
  apiKey,
  ...(process.env.NULLGATE_BASE_URL
    ? { baseURL: process.env.NULLGATE_BASE_URL }
    : {}),
  ...(process.env.ANALYTICS_URL
    ? { analyticsURL: process.env.ANALYTICS_URL }
    : {}),
});

try {
  const response = await target.fetch(targetURL);
  const page = new Page(response.url || targetURL, await response.text());
  const [protection] = api.findProtections(page);
  if (!protection) {
    console.log(`No supported candidate found (page HTTP ${response.status})`);
  } else {
    const scriptResponse = await target.fetch(protection.scriptURL, {
      headers: { Referer: page.url },
      redirect: "manual",
    });
    if (!scriptResponse.ok)
      throw new Error(`Script fetch returned HTTP ${scriptResponse.status}`);
    const script = await scriptResponse.text();
    const cookies = target.getCookies(page.url);
    let params: PixelParams | SensorParams | SbsdParams;
    switch (protection.kind) {
      case "pixel":
        params = new PixelParams(protection, script);
        break;
      case "sensor":
        params = new SensorParams(protection, script, {
          cookies: Object.fromEntries(
            Object.entries(cookies).filter(
              ([name]) => name === "_abck" || name === "bm_sz",
            ),
          ),
        });
        break;
      case "sbsd":
        params = new SbsdParams(protection, script, {
          cookies: Object.fromEntries(
            Object.entries(cookies).filter(([name]) =>
              ["bm_so", "sbsd_o", "bm_s"].includes(name),
            ),
          ),
        });
        break;
    }
    const session = api.open({
      identity: process.env.NULLGATE_IDENTITY ?? randomUUID(),
      userAgent,
    });
    try {
      const solution = await session.solve(params);
      await solution.wait();
      const result = await target.fetch(solution.url, {
        method: solution.method,
        headers: {
          Referer: page.url,
          Origin: new URL(page.url).origin,
          ...solution.headers,
        },
        body: solution.body,
        redirect: "manual",
      });
      console.log(
        `Target POST: HTTP ${result.status}, request_id=${solution.requestId}`,
      );
      console.log(await result.text());
    } finally {
      session.close();
    }
  }
} finally {
  api.close();
  await target.close();
}
