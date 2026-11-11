import { readFile } from "node:fs/promises";
import { Nullgate } from "@nullgate/sdk";

// Save the observed HTML and browser performance.timing JSON before running.
const url = process.env.PAGE_URL ?? "https://www.amazon.com/ap/signin";
const html = await readFile("page.html", "utf8");
const timing: Record<string, number> = JSON.parse(
  await readFile("timing.json", "utf8"),
);
const userAgent =
  process.env.USER_AGENT ??
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";
const page = new Nullgate().session({ userAgent }).page(url, html);
const fwcim = await page.fwcim({
  form: "#signIn",
  timing,
  inputs: { ap_email: process.env.EMAIL ?? "user@example.com" },
});
await fwcim.wait();
const form = new URLSearchParams({
  ap_email: process.env.EMAIL ?? "user@example.com",
});
form.set("metadata1", fwcim.metadata1);
// Send form through your existing client, with its existing target cookies.
