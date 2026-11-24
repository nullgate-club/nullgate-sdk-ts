import { readFile } from "node:fs/promises";
import { Nullgate, type TargetFetch } from "@nullgate/sdk";

const page = new Nullgate()
  .session({
    userAgent:
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36",
  })
  .page("https://identity.example/login", await readFile("page.html", "utf8"));

// Use your own cookie-aware client when the target requires a cookie jar.
const send: TargetFetch = async (request) => {
  const response = await fetch(request.url, {
    method: request.method,
    headers: request.headers,
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

const result = await page.protect({
  script: await readFile("pingone.js", "utf8"),
  send,
});
// Submit result.data with the target's normal sign-in request.
console.log(result.requestId);
