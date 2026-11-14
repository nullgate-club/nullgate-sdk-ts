<div align="center">

<img src="https://nullgate.club/assets/avatar.svg" alt="nullgate" width="96">

# @nullgate/sdk

**Prepare target requests from observed pages. Send them with your own HTTP client.**

[![Node.js 22.22+](https://img.shields.io/badge/node.js-22.22%2B-5FA04E?logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Products](https://img.shields.io/badge/products-Akamai%20%C2%B7%20Amazon%20%C2%B7%20ThreatMetrix%20%C2%B7%20Classifier-56856a)](#-what-it-does)
[![Docs](https://img.shields.io/badge/docs-nullgate.club-56856a)](https://nullgate.club)
[![Telegram bot](https://img.shields.io/badge/Telegram-%40nullgate__app-26A5E4?logo=telegram&logoColor=white)](https://t.me/nullgate_app)

</div>

## 🧭 What it does

The SDK talks to the Nullgate API and gives you ready request data: URLs, bodies,
headers, and form values. It never sends anything to the target site. You send the
prepared requests with your own HTTP client, such as `fetch`. It runs on Node.js 22.22
or newer.

| Product      | What you get                        | SDK method                                     | Guide                                                 |
| ------------ | ----------------------------------- | ---------------------------------------------- | ----------------------------------------------------- |
| Akamai       | Sensor, pixel, and SBSD requests    | `page.sensor()`, `page.pixel()`, `page.sbsd()` | [Akamai](https://nullgate.club/en/akamai)             |
| Amazon FWCIM | The `metadata1` form value          | `page.fwcim()`                                 | [Amazon](https://nullgate.club/en/amazon)             |
| Amazon ACIC  | PoW and AWS WAF answers             | `ng.acicPow()`, `ng.acicWaf()`                 | [ACIC](https://nullgate.club/en/amazon-acic)          |
| ThreatMetrix | A full profiling session            | `page.threatmetrix()`                          | [ThreatMetrix](https://nullgate.club/en/threatmetrix) |
| Classifier   | Image labels and text-query matches | `ng.classify()`, `ng.match()`                  | [Classifier](https://nullgate.club/en/classifier)     |

Shared topics: [sessions](https://nullgate.club/en/sessions),
[errors](https://nullgate.club/en/errors), and [billing](https://nullgate.club/en/billing).

## 🚀 Quick start

1. Get an API key in the Telegram bot [@nullgate_app](https://t.me/nullgate_app).
2. Install the SDK from Git and set your key:

   ```sh
   npm install github:nullgate-club/nullgate-sdk-ts
   export NULLGATE_API_KEY="your-key"
   ```

3. Prepare and send an Akamai sensor:

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

## 📦 Products

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

Catch `NullgateError` and inspect `code`, `message`, `requestId`, and `status`.
Maintenance retries are automatic. See the [error reference](https://nullgate.club/en/errors).

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
