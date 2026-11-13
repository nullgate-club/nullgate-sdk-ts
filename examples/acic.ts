import { readFile } from "node:fs/promises";
import { Nullgate } from "@nullgate/sdk";

const html = await readFile("acic.html", "utf8");
const challengeType = process.env.ACIC_CHALLENGE_TYPE;
if (!challengeType) throw new Error("Set ACIC_CHALLENGE_TYPE");
const proof = await new Nullgate().acicPow({ challengeType, html });
await proof.wait();
const acicBody = { response: proof.response };
// Submit acicBody through your existing Amazon client with its current state.
console.log("ACIC response ready:", typeof acicBody.response);
