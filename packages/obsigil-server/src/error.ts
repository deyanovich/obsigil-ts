// Verification failures are uniform and opaque to the bearer (the
// uniform-failure rule of the Security Considerations, spec §16.6).

/** The internal cause of a rejection — for server-side logging/telemetry
 *  ONLY (via {@link VerifyPolicy.onReject}). A verifier MUST NOT signal
 *  *why* a token was rejected to the bearer (the uniform-failure rule of the Security Considerations, spec §16.6). */
export type Reason =
  | "malformed"
  | "unsupported"
  | "auth-failed"
  | "empty-mandate"
  | "too-large"
  | "non-canonical"
  | "bad-tid"
  | "missing-clause"
  | "expired"
  | "audience-mismatch";

/** The single, opaque failure {@link clauses} (and the diagnostic
 *  {@link clausesUnchecked} / {@link mandatePlaintext}) throws on any
 *  rejection. Its message is uniform across every cause (the uniform-failure rule of the Security Considerations, spec §16.6); the
 *  granular {@link Reason} is delivered out-of-band to `policy.onReject`,
 *  never attached here. */
export class ObsigilError extends Error {
  constructor() {
    super("obsigil: token rejected");
    this.name = "ObsigilError";
  }
}
