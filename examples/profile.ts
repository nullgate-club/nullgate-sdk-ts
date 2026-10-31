import { randomUUID } from "node:crypto";
import {
  NullgateClient,
  Page,
  Target,
  ThreatMetrix,
  ThreatMetrixCollector,
  ThreatMetrixParams,
} from "@nullgate/sdk";
import { createSession, createTransport, fetch as targetFetch } from "wreq-js";

const targetURL = process.env.TARGET_URL;
const apiKey = process.env.NULLGATE_API_KEY;
if (!targetURL || !apiKey)
  throw new Error("Set TARGET_URL and NULLGATE_API_KEY");
const proxy = process.env.TARGET_PROXY ?? null;
const collectorURL = process.env.TMX_COLLECTOR_URL;
const orgId = process.env.TMX_ORG_ID;
const sessionId = process.env.TMX_SESSION_ID;
if (
  [collectorURL, orgId, sessionId].some((value) => value !== undefined) &&
  (!collectorURL || !orgId || !sessionId)
) {
  throw new Error(
    "Direct collector mode requires TMX_COLLECTOR_URL, TMX_ORG_ID, and TMX_SESSION_ID",
  );
}
const userAgent =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";
// Construct Target first so invalid proxy configuration cannot start paid work.
const target = new Target(
  async (request) => {
    const response = await targetFetch(request.url, {
      transport,
      ...(request.credentials === "include"
        ? { session: cookies }
        : { cookieMode: "ephemeral" as const }),
      method: request.method,
      headers: { ...request.headers },
      body: request.body,
      redirect: "manual",
      signal: request.signal,
      timeout: 30_000,
    });
    return {
      status: response.status,
      headers: Object.fromEntries(response.headers.entries()),
      body: new Uint8Array(await response.arrayBuffer()),
    };
  },
  { proxy },
);
const transport = await createTransport({
  browser: "chrome_146",
  os: "windows",
  ...(proxy ? { proxy } : {}),
});
const cookies = await createSession({ browser: "chrome_146", os: "windows" });
const api = new NullgateClient({
  apiKey,
  ...(process.env.NULLGATE_PROFILE_BASE_URL
    ? { profileBaseURL: process.env.NULLGATE_PROFILE_BASE_URL }
    : {}),
  ...(process.env.ANALYTICS_URL
    ? { analyticsURL: process.env.ANALYTICS_URL }
    : {}),
});
const session = api.open({
  identity: process.env.NULLGATE_IDENTITY ?? randomUUID(),
  userAgent,
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
});
try {
  const response = await targetFetch(targetURL, {
    transport,
    session: cookies,
    headers: { "User-Agent": userAgent },
    timeout: 30_000,
  });
  const page = new Page(response.url || targetURL, await response.text());
  const protection =
    collectorURL !== undefined && orgId !== undefined && sessionId !== undefined
      ? new ThreatMetrixCollector(page, collectorURL, orgId, sessionId)
      : api.findProtections(page, {
          where: (candidate) => candidate instanceof ThreatMetrix,
        })[0];
  if (
    !(protection instanceof ThreatMetrix) &&
    !(protection instanceof ThreatMetrixCollector)
  )
    throw new Error(
      `No ThreatMetrix tags found (page HTTP ${response.status})`,
    );
  const profile = await session.profile(
    new ThreatMetrixParams(protection),
    target,
  );
  try {
    console.log(`Profile ready, request_id=${profile.requestId}`);
    // This example explicitly leaves its document. Keep the handle alive instead
    // while your application is still using the page; close never invents departure.
    await profile.pagehide({ persisted: false });
    await profile.waitForCollected();
    console.log("Collectors finished; this is not a target acceptance verdict");
  } finally {
    await profile.close();
  }
} finally {
  await session[Symbol.asyncDispose]();
  await api[Symbol.asyncDispose]();
  await cookies.close();
  await transport.close();
}
