import { Solver } from "@nullgate/sdk";

const url = process.env.TARGET_URL;
const userAgent = process.env.USER_AGENT;
if (!url || !userAgent) throw new Error("Set TARGET_URL and USER_AGENT");

const { cookies, result } = await new Solver().solve({
  type: "akamai",
  url,
  userAgent,
  ...(process.env.PROXY && { proxy: process.env.PROXY }),
  session: "shop",
});
console.log(result, cookies);
