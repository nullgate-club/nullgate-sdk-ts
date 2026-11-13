import {
  type Match,
  Nullgate,
  NullgateError,
  type TargetFetch,
} from "@nullgate/sdk";

const ng = new Nullgate("fake-key", {
  baseUrl: "http://localhost:8080",
  timeout: 30,
});
const page = ng
  .session({ userAgent: "browser" })
  .page("https://shop.example", "<html></html>");
const sensorUrl: string | null = page.sensorUrl;
void sensorUrl;
void page.sensor({
  script: "source",
  cookies: new Map([["_abck", "cookie"]]),
  inputs: { email: "user@example.com" },
});
void page.pixel({ script: "source", scriptUrl: "https://shop.example/pixel" });
void page.sbsd({ script: "source", cookies: {} });
void page.fwcim({
  form: "#login",
  timing: { navigationStart: 1 },
  inputs: [
    {
      id: "email",
      value: "user@example.com",
      geometry: { width: 10, height: 20 },
    },
  ],
});
const send: TargetFetch = async () => ({
  status: 200,
  headers: {},
  body: new Uint8Array(),
});
void page.threatmetrix({ send });
void ng.account();
void ng.usage({ interval: "day" });
void ng.classify({ images: new Uint8Array([1]), labels: ["cat", "dog"] });
void ng.classify({
  images: [Buffer.from([1])],
  labels: ["cat", "dog"],
  model: "fast",
});
const match: Promise<Match> = ng.match({
  images: [Buffer.from([1])],
  queries: ["cat"],
});
void match;
const error: Error = new NullgateError("invalid_page", "Invalid page");
void error;
