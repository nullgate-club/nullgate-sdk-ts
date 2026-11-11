import { randomUUID } from "node:crypto";
import { Nullgate, type TargetFetch } from "@nullgate/sdk";

const orgId = "181rzcrc";
const sessionId = process.env.TMX_SESSION_ID ?? randomUUID();
const userAgent =
  process.env.USER_AGENT ??
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";

// Port of the site's wenkse wrapper URL builder: joke(sessionId, "94").
function collectorUrl(sessionId: string): string {
  const lower = 78_364_164_096;
  const span = 2_742_745_743_359;
  const draw = () => Math.floor(Math.random() * span);
  const token = () => (draw() + lower).toString(36);
  const first = draw();
  let second = draw();
  second = (second - (second % 256) + 6 + first) % span;
  const orgKey =
    (((885_187_064_159 + first) % span) + lower).toString(36) +
    (second + lower).toString(36);
  const path = token() + (first + lower).toString(36);
  const sessionKey = token() + token();
  const extraKey = token() + token();
  return `https://dfme.kleinanzeigen.de/${path}.js?${orgKey}=${orgId}&${sessionKey}=${sessionId}&${extraKey}=94`;
}

const response = await fetch(
  process.env.TARGET_URL ?? "https://www.kleinanzeigen.de/m-einloggen.html",
  { headers: { "User-Agent": userAgent }, redirect: "manual" },
);
if (!response.ok)
  throw new Error(`Page request returned HTTP ${response.status}`);
const page = new Nullgate()
  .session({ userAgent })
  .page(response.url, await response.text());
// Replace fetch with your client when the target needs its existing cookie jar or proxy.
const send: TargetFetch = async (request) => {
  const response = await fetch(request.url, {
    method: request.method,
    headers: request.headers,
    body: request.body === null ? null : new Uint8Array(request.body),
    credentials: request.credentials,
    redirect: "manual",
    signal: request.signal,
  });
  return {
    status: response.status,
    headers: Object.fromEntries(response.headers),
    body: new Uint8Array(await response.arrayBuffer()),
  };
};
const tmx = await page.threatmetrix({
  send,
  collector: { url: collectorUrl(sessionId), orgId, sessionId },
});
try {
  await tmx.waitForCollected();
  // Use this sessionId in sessionStorage and the site's ulp-wenkse-session-id field.
  // This example performs no login and leaves the document explicitly.
  await tmx.pagehide();
} finally {
  await tmx.close();
}
