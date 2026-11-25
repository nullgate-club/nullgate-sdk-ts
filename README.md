<div align="center">

<img src="assets/readme.png" alt="Nullgate" width="100%">

# @nullgate/sdk

**Solve protection pages through the local Nullgate HTTP API.**

[![Node.js 22.22+](https://img.shields.io/badge/node.js-22.22%2B-5FA04E?logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Products](https://img.shields.io/badge/products-Akamai%20%C2%B7%20Amazon%20%C2%B7%20ThreatMetrix%20%C2%B7%20Classifier-56856a)](#-products)
[![Docs](https://img.shields.io/badge/docs-nullgate.club-56856a)](https://nullgate.club)
[![Telegram bot](https://img.shields.io/badge/Telegram-%40nullgate__app-26A5E4?logo=telegram&logoColor=white)](https://t.me/nullgate_app)

</div>

## Quick start

1. Start the [Nullgate HTTP API](https://github.com/nullgate-club/http-api) once.
   Enter your API key in its CLI. The SDK does not need the key.
2. Install the SDK:

   ```sh
   npm install github:nullgate-club/nullgate-sdk-ts
   ```

3. Solve a page with your own URL, user agent, and proxy:

   ```typescript
   import { Solver } from "@nullgate/sdk";

   const { cookies, result } = await new Solver().solve({
     type: "akamai",
     url: "https://example.com/",
     userAgent: "your browser user agent",
     proxy: "http://127.0.0.1:8080",
     session: "shop",
   });
   console.log(result, cookies);
   ```

Use the returned cookies with the same user agent and proxy for subsequent requests.
The local API supports `akamai`, `threatmetrix`, `pingone`, and `amazon_acic`.
It does not run a browser or guarantee later target acceptance.
See [`examples/solve.ts`](examples/solve.ts).

`new Solver({ baseUrl, timeoutMs, fetch })` accepts an optional API address,
deadline in milliseconds, and custom fetch implementation. The defaults are
`http://127.0.0.1:8191` and 190000 ms. Pass `signal` to cancel a solve.
Paid solves are never retried automatically.

## Advanced: prepared requests

The existing `Nullgate` client prepares requests for your own HTTP client.
It requires an API key and runs on Node.js 22.22 or newer.
For example, prepare and send an Akamai sensor:

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

| Product         | Prepared request                               | Guide                                                 |
| --------------- | ---------------------------------------------- | ----------------------------------------------------- |
| Akamai          | `page.sensor()`, `page.pixel()`, `page.sbsd()` | [Akamai](https://nullgate.club/en/akamai)             |
| Amazon FWCIM    | `page.fwcim()`                                 | [Amazon](https://nullgate.club/en/amazon)             |
| Amazon ACIC     | `ng.acicPow()`, `ng.acicWaf()`                 | [ACIC](https://nullgate.club/en/amazon-acic)          |
| ThreatMetrix    | `page.threatmetrix()`                          | [ThreatMetrix](https://nullgate.club/en/threatmetrix) |
| PingOne Protect | `page.protect()`                               | [Example](examples/pingone.ts)                        |
| Classifier      | `ng.classify()`, `ng.match()`                  | [Classifier](https://nullgate.club/en/classifier)     |

See also [sessions](https://nullgate.club/en/sessions),
[errors](https://nullgate.club/en/errors), and [billing](https://nullgate.club/en/billing).

## 📦 Products

### Akamai pixel iframe

Use `await page.pixel({ script, iframe: true })` to model a hidden, restricted
cross-origin frame. This option requires an updated server. Omit it for the default
behavior and compatibility with older servers.

### Amazon FWCIM

`await page.fwcim({ form: "#signin", timing, inputs: { ap_email: email } })` returns
`metadata1` for your form.

### Amazon ACIC

**PoW.** Call `const proof = await ng.acicPow({ challengeType, html, startedAtMs })`,
then `await proof.wait()` before you submit. Assign `proof.response` directly to the
ACIC body without encoding it again.

- `startedAtMs` is optional and uses Unix milliseconds. It must be no more than
  10 minutes before or 1 minute after server time. The server uses its current time
  when omitted.
- `proof.sendAt` is in Unix seconds.
- See [the example](examples/acic.ts).

**WAF.** Pass the original AWS problem to
`const { clientSolution } = await ng.acicWaf({ problem })`. Build the body for your
own AWS request with
`acicWafVerificationBody({ problem, solution: clientSolution, elapsedMs, locale })`,
imported from `@nullgate/sdk`. Measure `elapsedMs` from when the problem arrived.

Both ACIC calls use the normal gzip path and are never retried automatically. Each
successful generation is charged once.

**Discovery.** Import `acic` for `discover(url, html)`, `parseResult(headers)` and
`discoverWaf(url, html)`. The returned setup builds `start()`, `answer(...)` and
`continuation(...)` requests for your existing HTTP client. The
[complete example](examples/acic.ts) handles PoW, WAF rounds, voucher submission and
the continuation form. See the [ACIC guide](https://nullgate.club/en/amazon-acic).

### ThreatMetrix

Open a profile with `await using tmx = await page.threatmetrix({ send })`, or pass
`collector: { url, orgId, sessionId }` for [Kleinanzeigen](examples/kleinanzeigen.ts).
Call `await tmx.pagehide()` when leaving.

### Classifier

```typescript
const classified = await ng.classify({
  images: await readFile("photo.jpg"),
  labels: ["cat", "dog"],
});
```

- Returns `{ model, results }` with one `{ label, scores }` per image.
- Pass up to 32 JPEG, PNG, or WebP images as `Uint8Array`.
- `scores` follow `labels` order.
- Optional `model`: `"fast"`, `"balanced"`, or `"precise"`.

`ng.match()` scores images against text queries and returns one result per image.
Scores are independent probabilities in query order.

```typescript
const matched = await ng.match({
  images: await readFile("photo.jpg"),
  queries: ["a cat", "a dog"],
});
```

## 🛠️ Advanced

**API transport.** `new Nullgate(key, { fetch })` injects API HTTP only.

**Compression.**

- An injected `fetch` sees gzip bytes for bodies of at least 1024 bytes from the
  first request.
- HTTP 415 disables gzip, while reporting and ThreatMetrix sockets stay unchanged.
- Classifier calls send raw bytes as `multipart/form-data` without gzip, so an
  injected `fetch` receives a `FormData` body.

**Sensor scripts.**

- Pass `scriptUrl` to choose a script. Relative URLs resolve against the page URL.
- Keep passing `script` to `page.sensor()`. The SDK omits retained scripts and retries
  once with the full script if required.
- Results preserve server header casing and order.

**Prepared inputs.** `prepareInputs([{ id: "password", value }])` returns
`PreparedInput[]` accepted by sensor and FWCIM without sending raw passwords.

**Cookies.** `abckCounters(value)` returns `[limit, generation]`.
`isEnough(value, responseCount)` checks ordinary-send eligibility, not target acceptance.

**Reporting.** `await result.report()` or `await ng.report(requestId)` returns HTTP
delivery status, not target acceptance or a refund.

## ⚠️ Errors

`SolverError` extends `NullgateError`. Inspect `code`, `message`, `stage`,
`requestId`, `status`, and `cause` for a local solve failure.
`transport_error` means the SDK could not reach the server. Start the HTTP API
and check `baseUrl`. `timeout` means the solve timed out.
`invalid_response` means the server returned an invalid response.

The advanced `Nullgate` client retries maintenance responses automatically.
See the [error reference](https://nullgate.club/en/errors).

## 📚 Examples

- [`examples/akamai.ts`](examples/akamai.ts)
- [`examples/amazon.ts`](examples/amazon.ts)
- [`examples/acic.ts`](examples/acic.ts)
- [`examples/threatmetrix.ts`](examples/threatmetrix.ts)
- [`examples/kleinanzeigen.ts`](examples/kleinanzeigen.ts)

[Documentation](https://nullgate.club)

## 🧑‍💻 Development

```sh
npm run check
```
