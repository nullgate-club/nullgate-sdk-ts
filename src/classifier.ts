import { NullgateError } from "./errors.js";

export interface ClassifyOptions {
  /** Raw JPEG, PNG, or WebP bytes; one image or up to 32. */
  readonly images: Uint8Array | readonly Uint8Array[];
  /** Candidate labels; at least two. */
  readonly labels: readonly string[];
  /** Omitted means the server default. */
  readonly model?: "fast" | "balanced" | "precise";
}
export interface ClassificationResult {
  /** The highest-scoring label. */
  readonly label: string;
  /** Probabilities in `labels` order; they sum to 1. */
  readonly scores: readonly number[];
}
export interface Classification {
  readonly model: string;
  /** One result per image, in request order. */
  readonly results: readonly ClassificationResult[];
}

const maxImages = 32;

export function classifyBody(options: ClassifyOptions): FormData {
  if (options === null || typeof options !== "object")
    throw new TypeError("classify options must be an object");
  const images =
    options.images instanceof Uint8Array ? [options.images] : options.images;
  if (
    !Array.isArray(images) ||
    images.some((image) => !(image instanceof Uint8Array))
  )
    throw new TypeError("images must be a Uint8Array or an array of them");
  if (images.length < 1 || images.length > maxImages)
    throw new TypeError(`images must contain 1 to ${maxImages} images`);
  if (images.some((image) => image.byteLength === 0))
    throw new TypeError("images cannot contain an empty image");
  if (!Array.isArray(options.labels) || options.labels.length < 2)
    throw new TypeError("labels must contain at least two labels");
  const form = new FormData();
  // Blob copies only the view's own bytes; part order is result order.
  for (const image of images)
    form.append("image", new Blob([image as Uint8Array<ArrayBuffer>]));
  for (const label of options.labels) form.append("label", label);
  if (options.model != null) form.append("model", options.model);
  return form;
}

export function classification(
  data: Record<string, unknown>,
  images: number,
  labels: number,
): Classification {
  const results = data.results;
  if (
    typeof data.model !== "string" ||
    !Array.isArray(results) ||
    results.length !== images ||
    results.some(
      (result) =>
        result === null ||
        typeof result !== "object" ||
        typeof result.label !== "string" ||
        !Array.isArray(result.scores) ||
        result.scores.length !== labels ||
        result.scores.some((score: unknown) => typeof score !== "number"),
    )
  )
    throw new NullgateError(
      "protocol_error",
      "Malformed classification response",
    );
  return {
    model: data.model,
    results: results.map(({ label, scores }) => ({ label, scores })),
  };
}
