import { readFile } from "node:fs/promises";
import { Nullgate, type TargetFetch } from "@nullgate/sdk";

const userAgent =
  process.env.USER_AGENT ??
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";
const page = new Nullgate()
  .session({ userAgent })
  .page(
    process.env.PAGE_URL ?? "https://shop.example/login",
    await readFile("page.html", "utf8"),
  );
// Native fetch has no cookie jar. Use your client here when the site needs one.
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
const tmx = await page.threatmetrix({ send });
try {
  await tmx.waitForCollected();
  await tmx.pagehide();
} finally {
  await tmx.close();
}
