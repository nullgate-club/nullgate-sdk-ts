import { setTimeout as sleep } from "node:timers/promises";

export interface OperationOptions {
  readonly signal?: AbortSignal;
}

export interface SolutionData {
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
  /** Absolute earliest target POST time in Unix seconds. */
  readonly sendAt: number;
  readonly requestId: string;
}

export type Reporter = (
  requestId: string,
  options?: OperationOptions,
) => Promise<boolean>;

/** A ready target request. Sending it and judging the target remain caller-owned. */
export class Solution implements SolutionData {
  readonly method = "POST";
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
  readonly sendAt: number;
  readonly requestId: string;
  readonly #reporter: Reporter;

  constructor(data: SolutionData, reporter: Reporter) {
    this.url = data.url;
    this.headers = Object.freeze({ ...data.headers });
    this.body = data.body;
    this.sendAt = data.sendAt;
    this.requestId = data.requestId;
    this.#reporter = reporter;
    Object.freeze(this);
  }

  async wait(options: OperationOptions = {}): Promise<void> {
    options.signal?.throwIfAborted();
    let remaining = this.sendAt * 1000 - Date.now();
    while (remaining > 0) {
      await sleep(
        Math.min(remaining, 2_147_483_647),
        undefined,
        options.signal === undefined ? {} : { signal: options.signal },
      );
      remaining = this.sendAt * 1000 - Date.now();
    }
  }

  /** True means HTTP delivery, not accepted diagnostics, target clearance, or refund. */
  report(options: OperationOptions = {}): Promise<boolean> {
    return this.#reporter(this.requestId, options);
  }
}
