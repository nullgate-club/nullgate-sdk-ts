# Nullgate TypeScript / JavaScript SDK

An ESM SDK for Node.js 22.22 or newer. JavaScript and TypeScript use the same API; the package includes TypeScript declarations. The core uses native `fetch` for Nullgate, not for your target website.

The default endpoints are `https://akamai.nullgate.club` for generation,
`https://threatmetrix.nullgate.club` for active profiling, and
`https://analytics.nullgate.club` for optional diagnostic reports.

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
and `NULLGATE_API_KEY`. `NULLGATE_BASE_URL` and `ANALYTICS_URL` override the default
services; `NULLGATE_IDENTITY` optionally supplies a stable identity UUID.

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

A client can serve multiple documents. A session binds an identity UUID, user
agent, optional timezone, and isolated `X-State-ID`. Keep the same session for
Akamai continuations of one document; open a new session for a newly fetched
Akamai document. ThreatMetrix can reuse the same session across fresh `Page`
objects, with one active `Profile` handle per document. Starting work within a
session is sequential; active profiles and separate sessions can run concurrently.
Keep the native target session and its cookie jar across documents.

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

Candidates are a discriminated union of `Pixel`, `Sensor`, `Sbsd`, and
`ThreatMetrix`. Each retains `page`, `scriptURL`, and script-tag provenance. Pixel also retains `challenge`
and `challengeOffset`, including ambiguous challenges and duplicate occurrences.
SBSD `blocking` means the raw `t` query parameter is present, including `t=`.
Sensor discovery is a finite same-origin classic-script heuristic, not proof that
the source contains a supported sensor. Unknown JavaScript assets are not solvers.
ThreatMetrix detection recognizes a `/tags.js` script with exactly one nonempty
`org_id` and `session_id`, including cross-origin tags. It has provider
`"threatmetrix"` and kind `"profile"`; mixed-provider candidates still participate
in the same ambiguity check.

Parameters are paired with their matching concrete protection:

- `new PixelParams(pixel, script)`
- `new SensorParams(sensor, script, { cookies?, inputs?, actions? })`
- `new SbsdParams(sbsd, script, { cookies? })`
- `new ThreatMetrixParams(threatMetrix, { inputs?, actions? })` for `session.profile`, not `session.solve`

`script` is source text fetched by the caller from the candidate's `scriptURL`. Cookies are explicit string mappings. For Sensor, missing/null inputs or actions preserve server defaults; empty arrays explicitly override them. `inputs` contains caller-filled field attributes and optional raw `value` strings. Values are summarized and SHA-256 hashed locally as UTF-16LE before transmission. `prepareInputs` exposes the same operation for callers who need the prepared representation. Actions use the service's explicit JSON event format; input/change action values must already be summaries, not raw secrets.

## Active ThreatMetrix profiles

Run `node examples/profile.ts` with `TARGET_URL` and `NULLGATE_API_KEY` for the
[complete native target example](examples/profile.ts). `TARGET_PROXY` is optional:
unset/empty explicitly means direct; otherwise the example applies the same proxy
to its native HTTP transport and SDK-owned TURN/TCP stream.
`NULLGATE_PROFILE_BASE_URL` overrides the profiling service independently of
Akamai's `NULLGATE_BASE_URL`.

Construct `new ThreatMetrix(page, tagsURL)` when the actual tags URL is already
known, or use discovery. The SDK sends the existing `Page` document ID and
started-at clock, actual tags URL, and session timezone. It never executes a
collector locally or creates source hashes, versions, or a source profile.
Optional observations reuse Sensor's `InputField` and `Action` types and local
preparation. Raw field values are summarized and SHA-256 hashed locally as
UTF-16LE before the profile is queued; action input/change values must already
be prepared `InputValue` summaries. No raw input text is sent or keyboard events
invented. Absent/null observation lists are omitted from `start`; explicit empty
lists remain `[]`, preserving caller clear/no-automatic-action intent. Supplied
observations are snapshotted before paid work begins.

`new Target(fetchCallback, { proxy })` requires an explicit local route: `null`
or `""` means direct; HTTP, HTTPS, and SOCKS5 URLs are supported. TURN endpoints
resolve locally once and the numeric address is pinned to the selected route.
SOCKS5h is rejected rather than silently changing its remote-only DNS semantics.
Configuration is checked before paid work. Proxy credentials never enter the
WebSocket payload, diagnostics, or ordinary object/error inspection. Environment
proxies are not adopted by the SDK's WebSocket or TURN connection.
Cancellation or the gather deadline stops waiting for an OS lookup and prevents
any later target connection. An already-submitted OS lookup can still finish in
the background; its result or failure is consumed without starting target work.

The callback receives `{ role, url, method, headers, body, credentials, signal }`.
`body` is `Uint8Array | null`: null is absent, and an empty array is a present
empty body. Return `{ status, headers, body }` after reading the complete response;
response `body` must be raw bytes, never a decoded/re-encoded string. Return actual
4xx/5xx responses too. Only connection failures become `http.error`.
The SDK records completion time when those bytes arrive and performs base64 wire
encoding itself.

Use your existing native TLS transport and URL-scoped cookie jar. `include` must
send and retain cookies in that jar; `omit` must neither send its cookies nor
retain response cookies in it. The Wreq example shares one native transport for
both paths, selecting the existing session for include and a discarded
single-request cookie context for omit. A callback must honor its AbortSignal.

`await session.profile(params, target, { signal? })` returns an active `Profile`
at `ready`, not after all delayed work. The SDK has one WebSocket reader,
concurrent HTTP and ICE operations, and serialized writes. It gathers only a
TURN relay over TCP through the explicit route; the maintained TURN provider
owns authentication, allocation, and refresh. The resulting candidate is an
actual UDP relay, not a TCP relay, host candidate, or local UDP probe.
Allocation failure reports a null observation, never fabricated addresses or
timing and never a direct fallback after proxy failure.

- `profile.requestId` identifies the actual profiling request.
- `profile.isCollected` / `await profile.waitForCollected({ signal? })` describe
  completion of all installed collectors, independently of readiness.
- `await profile.pagehide({ atMs?, persisted?, signal? })` sends an explicit
  caller departure and waits for its acknowledgement while servicing operations.
  Defaults are the current wall clock and `persisted: false`; BFCache callers
  must pass `persisted: true` when that is the observed fact.
- `await profile.close()` and `Symbol.asyncDispose` cancel pending work and
  release owned resources. Neither sends an implicit pagehide. Session/client
  close also cancels their profiles; await their async disposal for cleanup.
- `profile.error` retains a background failure. Service, protocol, and transport
  errors expose their request ID and status where available.
- `await profile.report({ signal? })` uses the same credential-free analytics
  path as a solution; it is not a target-acceptance or refund verdict.

Allocations stay alive until `ice.release` or owned cleanup. After a candidate
has been reported, unexpected TURN stream loss or refresh failure terminates the
profile with `NullgateTransportError` and its request ID, cancels sibling work,
and rejects pending collection/departure waits. Explicit release, cancellation,
and owner close remain normal cleanup. Cleanup cancels and joins pending
transactions/refresh, attempts the provider's authenticated `Refresh(0)`, and
closes the TCP stream even if the release acknowledgement is lost. A new page
gets a new `Page` and profile handle; a bfcache restore is not fabricated by close.

## Solutions, cancellation, and reports

`await session.solve(params, { signal? })` returns a readonly ready request:

- `method` is `"POST"`; `url`, `headers`, and `body` are ready for your target provider.
- `body` is a **string**. Do not JSON-encode it again.
- `sendAt` is an absolute Unix timestamp in seconds; `await solution.wait({ signal? })` waits until it is ready.
- `requestId` comes from the actual `X-Request-ID` response header.
- `await solution.report({ signal? })` or `await client.report(requestId, { signal? })` sends only `{ request_id }` to analytics.

Report `true` means HTTP delivery, not diagnostic acceptance, target clearance, or refund. Reports have a finite three-second default timeout, no redirects, no retries, and no API key/state/cookie headers. Remote HTTP/network failures return `false`; cancellation, closed-client, configuration, and programming errors propagate.

Client configuration supports `baseURL`, `profileBaseURL`, `analyticsURL`, `timeoutMs`, `reportTimeoutMs`, and a native-fetch-compatible HTTP `fetch` seam. The profiling URL defaults to `https://threatmetrix.nullgate.club`; HTTP(S) is converted to WS(S) for the profile handshake. Its API-key, user-agent, and state headers are sent using maintained `ws`, not a handwritten WebSocket implementation. `timeoutMs` bounds profile startup and each ICE gather; it does not end a ready document. API failures expose `NullgateAPIError.statusCode`, `.requestId`, and `.detail`; detail is deliberately excluded from normal error inspection because server validation details can contain private inputs. Malformed successful results raise `NullgateProtocolError` rather than inventing defaults.

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
