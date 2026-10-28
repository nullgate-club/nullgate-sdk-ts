import {
  AmbiguousProtectionError,
  type ClientOptions,
  type FindOptions,
  findProtections,
  NullgateClient,
  type Page,
  Pixel,
  PixelParams,
  type Protection,
  Sbsd,
  SbsdParams,
  Sensor,
  SensorParams,
  type Solution,
} from "@nullgate/sdk";

/** Compiled, not executed: consumer-facing discriminants and variant pairing. */
export async function typedConsumer(
  options: ClientOptions,
  protection: Protection,
  signal: AbortSignal,
): Promise<void> {
  const client = new NullgateClient(options);
  const session = client.open({
    identity: "11111111-2222-4333-8444-555555555555",
    userAgent: "Windows Chrome146",
  });
  try {
    let solution: Solution;
    switch (protection.kind) {
      case "pixel":
        solution = await session.solve(new PixelParams(protection, "source"), {
          signal,
        });
        break;
      case "sensor":
        solution = await session.solve(
          new SensorParams(protection, "source", {
            inputs: [{ type: "password", value: "kept local" }],
            actions: [],
            cookies: {},
          }),
          { signal },
        );
        break;
      case "sbsd":
        solution = await session.solve(
          new SbsdParams(protection, "source", { cookies: {} }),
          { signal },
        );
        break;
    }
    await solution.wait({ signal });
    const body: string = solution.body;
    const delivered: boolean = await solution.report({ signal });
    void body;
    void delivered;
  } finally {
    await session[Symbol.asyncDispose]();
    await client[Symbol.asyncDispose]();
  }
}

export function rejectedPairings(page: Page): void {
  const discovery: FindOptions = { panic: false };
  const candidates: Protection[] = findProtections(page, discovery);
  const retained: readonly Protection[] = new AmbiguousProtectionError(
    candidates,
  ).candidates;
  void retained;
  // @ts-expect-error The ambiguity option must be a boolean.
  findProtections(page, { panic: "false" });
  const pixel = new Pixel(page, "https://target.example/akam/13/abc", "12");
  const sensor = new Sensor(page, "https://target.example/sensor");
  const sbsd = new Sbsd(
    page,
    "https://target.example/sbsd?v=11111111-2222-4333-8444-555555555555",
  );
  // @ts-expect-error Pixel parameters cannot contain a Sensor.
  new PixelParams(sensor, "source");
  // @ts-expect-error Sensor parameters cannot contain a Pixel.
  new SensorParams(pixel, "source");
  // @ts-expect-error SBSD parameters cannot contain a Sensor.
  new SbsdParams(sensor, "source");
  // @ts-expect-error Pixel parameters cannot contain an SBSD.
  new PixelParams(sbsd, "source");
}
