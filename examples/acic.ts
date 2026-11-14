import {
  acic,
  acicWafVerificationBody,
  Nullgate,
  type TargetRequest,
} from "@nullgate/sdk";

const stageKinds: Readonly<Record<string, "pow" | "waf">> = {
  PROOF_OF_WORK_LEVEL_3: "pow",
  PROOF_OF_WORK_LEVEL_3_CHAIN_WAF_ADVERSARIAL_SYNTHETIC_GRID_V2_LEVEL_2: "pow",
  WAF_ADVERSARIAL_SYNTHETIC_GRID_V2_LEVEL_2: "waf",
  WAF_ADVERSARIAL_SYNTHETIC_GRID_V2_LEVEL_3: "waf",
};

/** fetchTarget owns target cookies, proxy, User-Agent and timeouts. */
export async function solveAcic(
  ng: Nullgate,
  fetchTarget: typeof fetch,
  entry: Response,
): Promise<Response> {
  const setup = acic.discover(entry.url, await entry.clone().text());
  if (!setup) return entry;

  const send = async (
    request: TargetRequest,
    redirect: "error" | "follow" = "error",
  ): Promise<Response> => {
    const response = await fetchTarget(request.url, {
      method: request.method,
      headers: request.headers,
      body: request.body as BodyInit | null,
      credentials: request.credentials,
      signal: request.signal,
      redirect,
    });
    if (redirect === "error" && response.status !== 200)
      throw new Error(`ACIC returned HTTP ${response.status}`);
    return response;
  };

  let response = await send(setup.start());
  const seen = new Set<string>();
  while (true) {
    const state = acic.parseResult(response.headers);
    if (!state) throw new Error("Amazon returned no ACIC result header");
    if (state.actionType === "PASS")
      return send(setup.continuation(state), "follow");
    if (seen.has(state.actionType))
      throw new Error("ACIC repeated a stage; stop instead of paying again");
    seen.add(state.actionType);
    let answer: string;
    if (stageKinds[state.actionType] === "pow") {
      const proof = await ng.acicPow({
        challengeType: state.actionType,
        html: await response.text(),
      });
      await proof.wait();
      answer = proof.response;
    } else if (stageKinds[state.actionType] === "waf") {
      const waf = acic.discoverWaf(response.url, await response.text());
      if (!waf || ![2, 3].includes(waf.roundsRequired))
        throw new Error("Unsupported WAF view or round policy");
      const fetched = await fetchTarget(waf.problemUrl, {
        headers: waf.headers,
        credentials: "omit",
        redirect: "error",
      });
      if (!fetched.ok) throw new Error(`AWS returned HTTP ${fetched.status}`);
      let problem: Record<string, unknown> = await fetched.json();
      let presentedAt = performance.now();
      let voucher: string | undefined;
      for (let round = 0; round < waf.roundsRequired; round++) {
        const selection = await ng.acicWaf({ problem });
        const body = acicWafVerificationBody({
          problem: {
            state: problem.state,
            key: problem.key,
            hmac_tag: problem.hmac_tag,
          },
          solution: selection.clientSolution,
          elapsedMs: performance.now() - presentedAt,
          locale: waf.locale,
        });
        const verified = await fetchTarget(waf.verificationUrl(problem), {
          method: "POST",
          headers: waf.headers,
          body: JSON.stringify(body),
          credentials: "omit",
          redirect: "error",
        });
        if (!verified.ok)
          throw new Error(`AWS returned HTTP ${verified.status}`);
        const result: Record<string, unknown> = await verified.json();
        if (
          typeof result.captcha_voucher === "string" &&
          result.captcha_voucher
        ) {
          voucher = result.captcha_voucher;
          break;
        }
        if (
          result.success !== true ||
          !result.problem ||
          typeof result.problem !== "object" ||
          Array.isArray(result.problem)
        )
          throw new Error("AWS rejected the WAF answer");
        problem = result.problem as Record<string, unknown>;
        presentedAt = performance.now();
      }
      if (!voucher)
        throw new Error("AWS returned no voucher within its round policy");
      answer = state.voucherResponse(voucher);
    } else {
      throw new Error("Unsupported ACIC stage");
    }
    response = await send(setup.answer(state, answer));
  }
}
