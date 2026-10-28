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

## Client and document lifetime

```ts
import { NullgateClient, Page, SensorParams } from "@nullgate/sdk";

export async function generateSensor(
  client: NullgateClient,
  page: Page,
  script: string,
  identity: string,
  userAgent: string,
) {
  const candidates = client.findProtections(page, {
    where: (protection) => protection.kind === "sensor",
  });
  const protection = candidates[0];
  if (candidates.length !== 1 || protection?.kind !== "sensor") {
    throw new Error("Select exactly one sensor candidate before generation");
  }
  const session = client.open({ identity, userAgent });
  try {
    return await session.solve(new SensorParams(protection, script));
  } finally {
    session.close();
  }
}
```

Create the reusable client with `new NullgateClient({ apiKey })`; close it in your outer `finally` block. A returned solution can still report through its originating client until that client closes. `client.close()` aborts its active requests and closes all sessions. `session.close()` affects only that session. Both support `Symbol.asyncDispose`.

A session belongs to one document and binds an identity UUID, user agent, optional timezone, and isolated `X-State-ID`. Calls in the same session are sequential even when submitted concurrently. Different sessions can run concurrently. Use a **new session for each new document**. The target cookie jar is separate and stays with your target HTTP provider.

## Discovery and typed parameters

`new Page(url, html)` stores caller-supplied content. `client.findProtections(page, { where? })` and the standalone `findProtections` are synchronous and never perform network requests or execute JavaScript.

Discovery returns a discriminated union of `Pixel`, `Sensor`, and `Sbsd`. Every candidate retains `page`, `scriptURL`, and its script-tag provenance. Pixel candidates additionally retain `challenge` and `challengeOffset`; ambiguous challenges and duplicate occurrences are not silently discarded. SBSD `blocking` means the raw `t` query parameter is present, including `t=`. Sensor discovery is a finite same-origin classic-script heuristic, not proof that the source contains a supported sensor. Unknown JavaScript assets are not solvers.

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

Set `TARGET_URL` and `NULLGATE_API_KEY` before running. Optional settings are `TARGET_PROXY`, `NULLGATE_IDENTITY`, `NULLGATE_BASE_URL`, and `ANALYTICS_URL`.

Run the TypeScript example from the source checkout, not from `node_modules`:
Node's native type stripping does not support `.ts` files inside dependencies.
`npm ci` installs the locked native `wreq-js@3.2.0` example dependency and builds
the SDK through `prepare`.

The [complete target example](examples/target.ts) uses the maintained `wreq-js` native BoringSSL transport with `browser: "chrome_146"`, `os: "windows"`, a matching user agent, one cookie jar, and reused connections. It has no standard-client fallback. It fetches page/script content, generates, waits, and posts exact solution bytes. Sensor continuation uses `abckCounters`/`isEnough` with finite diagnostic ceilings. A closed cookie gate is not acceptance. Blocking SBSD is checked by fetching the original page again, never by treating POST 200 as clearance.

Sensor generation receives only script-visible `_abck`/`bm_sz` cookies. SBSD receives the actual page-scoped script-visible cookie context. Native jar scoping owns domain/path/secure/expiry matching; the example excludes HttpOnly cookies and reports visibility ambiguity rather than guessing.

## Development

`make setup` installs locked dependencies; `make format` applies Biome fixes; `make check` runs Biome, strict TypeScript checking, the declaration build, and behavioral `node:test` coverage. The target provider is an example/development dependency, not a core SDK dependency.

Standalone CI runs `npm ci` and `npm run check` on Node.js 22.22. The locked
development dependencies also cover the runnable target example. Canonical
SDK-first documentation: [docs.nullgate.club](https://docs.nullgate.club).
