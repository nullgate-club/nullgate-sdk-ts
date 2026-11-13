# @nullgate/sdk

Prepare target requests from observed pages for Node.js 22.22 or newer. Send them with your own HTTP client.

```sh
npm install github:nullgate-club/nullgate-sdk-ts
export NULLGATE_API_KEY="your-key"
```

## Akamai

```typescript
import { Nullgate } from "@nullgate/sdk";

const url = "https://www.nike.com/";
const userAgent =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";
const http = (url: string) =>
  fetch(url, { headers: { "User-Agent": userAgent } });
const response = await http(url);
const cookies = Object.fromEntries(
  response.headers.getSetCookie().map((cookie) => {
    const pair = cookie.split(";", 1)[0] ?? "";
    const separator = pair.indexOf("=");
    return [pair.slice(0, separator), pair.slice(separator + 1)];
  }),
);
const page = new Nullgate()
  .session({ userAgent })
  .page(response.url, await response.text());
if (!page.sensorUrl) throw new Error("This page has no sensor script");
const sensor = await page.sensor({
  script: await (await http(page.sensorUrl)).text(),
  cookies,
});
await sensor.wait();
const sent = await fetch(sensor.url, {
  method: "POST",
  body: sensor.body,
  headers: {
    ...sensor.headers,
    "User-Agent": userAgent,
    Cookie: Object.entries(cookies)
      .map(([name, value]) => name + "=" + value)
      .join("; "),
  },
});
console.log(sent.status);
```

- Reporting: `await result.report()` or `await ng.report(requestId)` returns HTTP delivery status, not target acceptance or a refund.
- Pass `scriptUrl` to choose a script. Relative URLs resolve against the page URL. Results preserve server header casing and order. Keep passing `script` to `page.sensor()`; the SDK omits retained scripts and retries once with the full script if required.
- API transport: `new Nullgate(key, { fetch })` injects API HTTP only and sees gzip bytes for bodies of at least 1024 bytes from the first request; HTTP 415 disables gzip, while reporting and ThreatMetrix sockets stay unchanged.
- Inputs: `prepareInputs([{ id: "password", value }])` returns `PreparedInput[]` accepted by sensor and FWCIM without sending raw passwords.
- Cookies: `abckCounters(value)` returns `[limit, generation]`; `isEnough(value, responseCount)` checks ordinary-send eligibility, not target acceptance.
- Amazon: `await page.fwcim({ form: "#signin", timing, inputs: { ap_email: email } })` returns `metadata1` for your form.
- ThreatMetrix: `await using tmx = await page.threatmetrix({ send })`, or pass `collector: { url, orgId, sessionId }` for [Kleinanzeigen](examples/kleinanzeigen.ts). Call `await tmx.pagehide()` when leaving.
- Classifier: `await ng.classify({ images: await readFile("photo.jpg"), labels: ["cat", "dog"] })` returns `{ model, results }` with one `{ label, scores }` per image. Pass up to 32 JPEG, PNG, or WebP images as `Uint8Array`; `scores` follow `labels` order. Optional `model`: `"fast"`, `"balanced"`, or `"precise"`. The SDK sends raw bytes as `multipart/form-data` without gzip, so an injected `fetch` receives a `FormData` body.
- Errors: catch `NullgateError` and inspect `code`, `message`, `requestId`, and `status`. Maintenance retries are automatic.

[Documentation](https://nullgate.club) · [Examples](examples) · Check: `npm run check`.
