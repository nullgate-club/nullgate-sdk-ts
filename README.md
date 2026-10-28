# Nullgate TypeScript / JavaScript SDK

An ESM SDK for Node.js 22.22 or newer. JavaScript and TypeScript use the same API; the package includes TypeScript declarations. The core uses native `fetch` for Nullgate, not for your target website.

This SDK requires the updated Nullgate backend with `X-Request-ID` and analytics.
Until the backend cutover, point `baseURL` and `analyticsURL` at an updated preview
deployment; the target example reads `NULLGATE_BASE_URL` and `ANALYTICS_URL`.
It is not compatible with the old production API. Python users of that API should
remain on the Python SDK's `main` branch.

## Install from source

```sh
npm install "git+https://github.com/nullgate-club/nullgate-sdk-ts.git#main"
```

Git installation runs the package's `prepare` build. Git, Node.js 22.22+ and npm
must be available, and npm must be allowed to install the package's development
dependencies and run lifecycle scripts so TypeScript can build `dist/`. Do not
use `--ignore-scripts` for this source install. The SDK is not released to npm.

## One generation

Install `wreq-js@3.2.0` alongside the SDK for this target example. Set `TARGET_URL`
and `NULLGATE_API_KEY`; use `NULLGATE_BASE_URL` and `ANALYTICS_URL` for an updated
preview backend. `NULLGATE_IDENTITY` optionally supplies a stable identity UUID.

```ts
import { randomUUID } from "node:crypto";
import { NullgateClient, Page, SensorParams } from "@nullgate/sdk";
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
  defaultHeaders: { "User-Agent": userAgent },
});
const client = new NullgateClient({
  apiKey,
  ...(process.env.NULLGATE_BASE_URL
    ? { baseURL: process.env.NULLGATE_BASE_URL }
    : {}),
  ...(process.env.ANALYTICS_URL
    ? { analyticsURL: process.env.ANALYTICS_URL }
    : {}),
});
const session = client.open({
  identity: process.env.NULLGATE_IDENTITY ?? randomUUID(),
  userAgent,
});
try {
  const response = await target.fetch(targetURL);
  const page = new Page(response.url || targetURL, await response.text());
  const [sensor] = client.findProtections(page, {
    where: (candidate) => candidate.kind === "sensor",
  });
  if (sensor?.kind === "sensor") {
    const source = await target.fetch(sensor.scriptURL, {
      headers: { Referer: page.url },
      redirect: "manual",
    });
    if (!source.ok) throw new Error(`Script HTTP ${source.status}`);
    const cookies = Object.fromEntries(
      Object.entries(target.getCookies(page.url)).filter(
        ([name]) => name === "_abck" || name === "bm_sz",
      ),
    );
    const solution = await session.solve(
      new SensorParams(sensor, await source.text(), { cookies }),
    );
    await solution.wait();
    const result = await target.fetch(solution.url, {
      method: solution.method,
      headers: solution.headers,
      body: solution.body,
      redirect: "manual",
    });
    console.log(result.status, await result.text());
  } else {
    console.log("No sensor candidate found");
  }
} finally {
  session.close();
  client.close();
  await target.close();
}
```

This sends **one generation**, not a clearance verdict. The full
[target example](examples/target.ts) also handles Pixel and SBSD parameters,
without choosing among ambiguous candidates.

A client can serve multiple documents. A session belongs to **one document** and
binds an identity UUID, user agent, optional timezone, and isolated `X-State-ID`.
Keep the same session for further generations of that document; open a new
session whenever a new document is fetched. Calls within a session are
sequential; separate sessions can run concurrently. Keep the native target
session and its cookie jar across documents.

`session.close()` affects only that session. `client.close()` aborts active
requests and closes all sessions. Both support `Symbol.asyncDispose`. A solution
can report through its originating client until that client closes.

## Discovery and typed parameters

`new Page(url, html)` stores caller-supplied content.
`client.findProtections(page, { where?, panic? })` and the standalone
`findProtections` are synchronous and never fetch or execute JavaScript.

Discovery always returns a list: no candidates means `[]`, and one candidate
means a one-element list. The optional `where` predicate runs **before** the
ambiguity check. More than one remaining candidate throws the exported
`AmbiguousProtectionError` by default; its `candidates` property retains all
matching candidates. Use `{ panic: false }` to inspect all candidates, optionally
with `where`. No candidate is silently selected or deduplicated.

Candidates are a discriminated union of `Pixel`, `Sensor`, and `Sbsd`. Each retains
`page`, `scriptURL`, and script-tag provenance. Pixel also retains `challenge`
and `challengeOffset`, including ambiguous challenges and duplicate occurrences.
SBSD `blocking` means the raw `t` query parameter is present, including `t=`.
Sensor discovery is a finite same-origin classic-script heuristic, not proof that
the source contains a supported sensor. Unknown JavaScript assets are not solvers.

Parameters are paired with their matching concrete protection:

- `new PixelParams(pixel, script)`
- `new SensorParams(sensor, script, { cookies?, inputs?, actions? })`
- `new SbsdParams(sbsd, script, { cookies? })`

`script` is source text fetched by the caller from the candidate's `scriptURL`. Cookies are explicit string mappings. For Sensor, missing/null inputs or actions preserve server defaults; empty arrays explicitly override them. `inputs` contains caller-filled field attributes and optional raw `value` strings. Values are summarized and SHA-256 hashed locally as UTF-16LE before transmission. `prepareInputs` exposes the same operation for callers who need the prepared representation. Actions use the service's explicit JSON event format; input/change action values must already be summaries, not raw secrets.

## Solutions, cancellation, and reports

`await session.solve(params, { signal? })` returns a readonly ready request:

- `method` is `"POST"`; `url`, `headers`, and `body` are ready for your target provider.
- `body` is a **string**. Do not JSON-encode it again.
- `sendAt` is an absolute Unix timestamp in seconds; `await solution.wait({ signal? })` waits until it is ready.
- `requestId` comes from the actual `X-Request-ID` response header.
- `await solution.report({ signal? })` or `await client.report(requestId, { signal? })` sends only `{ request_id }` to analytics.

Report `true` means HTTP delivery, not diagnostic acceptance, target clearance, or refund. Reports have a finite three-second default timeout, no redirects, no retries, and no API key/state/cookie headers. Remote HTTP/network failures return `false`; cancellation, closed-client, configuration, and programming errors propagate.

Client configuration supports `baseURL`, `analyticsURL`, `timeoutMs`, `reportTimeoutMs`, and a native-fetch-compatible `fetch` seam. Defaults are `https://akamai.nullgate.club` and `https://analytics.nullgate.club`. API failures expose `NullgateAPIError.statusCode`, `.requestId`, and `.detail`; detail is deliberately excluded from normal error inspection because server validation details can contain private inputs. Malformed successful results raise `NullgateProtocolError` rather than inventing defaults.

## Browser-like target example

```sh
git clone https://github.com/nullgate-club/nullgate-sdk-ts.git
cd nullgate-sdk-ts
npm ci
node examples/target.ts
```

Set `TARGET_URL` and `NULLGATE_API_KEY` before running. Optional settings are
`NULLGATE_IDENTITY`, `NULLGATE_BASE_URL`, and `ANALYTICS_URL`.

Run the TypeScript example from the source checkout, not from `node_modules`:
Node's native type stripping does not support `.ts` files inside dependencies.
`npm ci` installs the locked native `wreq-js@3.2.0` example dependency and builds
the SDK through `prepare`.

The [complete target example](examples/target.ts) uses the maintained native
`wreq-js` BoringSSL transport with `browser: "chrome_146"`, `os: "windows"`, and a
matching user agent. It fetches one page and one script, constructs concrete
parameters, generates once, waits, and POSTs the exact solution body and headers.
It prints the target status and response body; it does not retry, automatically
continue across documents, or claim clearance.

Native `target.getCookies(page.url)` owns URL scoping. The explicit generation
mapping keeps `_abck` and `bm_sz` for Sensor, and `bm_so`, `sbsd_o`, and `bm_s` for
SBSD; missing names stay absent. Customer authentication cookies remain in the
native jar for target requests, not in generation parameters. These getters
are native HTTP-cookie access, not a reconstruction of `document.cookie`.

If the document requires another generation, read the updated native cookies
and solve again in the same Nullgate session. `abckCounters` and `isEnough`
describe the ordinary Sensor send gate, not acceptance. After blocking SBSD,
fetch the original page again to inspect the result and open a new session for
that new document. A successful POST alone is not clearance.

## Development

`make setup` installs locked dependencies; `make format` applies Biome fixes; `make check` runs Biome, strict TypeScript checking, the declaration build, and behavioral `node:test` coverage. The target provider is an example/development dependency, not a core SDK dependency.

Standalone CI runs `npm ci` and `npm run check` on Node.js 22.22. The locked
development dependencies also cover the runnable target example. Canonical
SDK quickstart: [docs.nullgate.club/en/quickstart](https://docs.nullgate.club/en/quickstart).
