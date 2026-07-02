// obsigil-server — backend for obsigil mandate tokens: mint and verify
// under a secret mandate key, enforcing the reserved fields (Reserved fields, spec §8).

export { mint } from "./mint.js";
export type { MintInput } from "./mint.js";
export { clauses, clausesUnchecked, mandatePlaintext } from "./verify.js";
export type { VerifyPolicy, KeysOrPolicy } from "./verify.js";
export { ObsigilError } from "./error.js";
export type { Reason } from "./error.js";
export { issuedAt } from "./reserved.js";
export type { Claims, Clauses } from "./reserved.js";
export { generateKey, generateKeyBytes, coerceMandateKey } from "./keys.js";
export type { MandateKeyInput } from "./keys.js";
export { generateUuidV7, isUuidV7, uuidV7Time } from "./uuid.js";

// Re-exported for convenience (the published manifest key, the value types).
export { MANIFEST_KEY } from "@obsigil/core";
export type { Alg, Encoding, NumericDate } from "@obsigil/core";
