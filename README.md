# @nullgate/sdk

Prepare target requests from observed pages. You send them with your own HTTP client.
Requires Node.js 22.22 or newer.

```sh
npm install @nullgate/sdk
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

Pass `scriptUrl` to choose a script. Relative URLs resolve against the page URL.

Amazon: `await page.fwcim({ form: "#signin", timing, inputs: { ap_email: email } })` returns `metadata1` for your form.

ThreatMetrix: `await using tmx = await page.threatmetrix({ send })`; call `await tmx.pagehide()` when leaving.

Errors: catch `NullgateError` and inspect `code`, `message`, `requestId`, and `status`. Maintenance retries are automatic.

[Documentation](https://docs.nullgate.club) · [Examples](examples) · Check: `npm run check`.
