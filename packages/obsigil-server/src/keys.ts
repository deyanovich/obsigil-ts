// Mandate key handling (the mandate, Construction §5.1; the Key format, §6.2).
// A mandate key is a uniformly random 64-byte value, distinct from the public
// manifest key. It is supplied as its canonical hex string (the default) or as
// raw bytes.

import { MANIFEST_KEY, decodeHex, encodeHex } from "@obsigil/core";

/** A mandate key as its canonical hex string (128 lowercase hex digits, the
 *  default form, the Key format §6.2) or as raw 64 bytes (the alternative). */
export type MandateKeyInput = string | Uint8Array;

/** Generate a fresh mandate key as its canonical text form: 128 lowercase hex
 *  digits (the Key format, §6.2) — the form to store as a secret (an
 *  environment variable) and pass to `mint` / `clauses`. `generateKeyBytes` is
 *  the raw-64-byte alternative. */
export function generateKey(): string {
  return encodeHex(generateKeyBytes());
}

/** Generate a fresh 64-byte mandate key from the platform CSPRNG (the Key
 *  format, §6.2) — the raw-octet alternative to `generateKey`. */
export function generateKeyBytes(): Uint8Array {
  const key = new Uint8Array(64);
  crypto.getRandomValues(key);
  return key;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** Reject a key that cannot be a mandate key: wrong length, or the public
 *  manifest key — accepting which would let anyone mint mandates (the mandate, Construction, §5.1).
 *  Throws a (non-uniform) configuration error; this is a deployment bug,
 *  not a token rejection. */
export function assertMandateKey(key: Uint8Array): void {
  if (key.length !== 64) {
    throw new Error("obsigil: mandate key must be 64 bytes");
  }
  if (equalBytes(key, MANIFEST_KEY)) {
    throw new Error("obsigil: mandate key must not be the public manifest key");
  }
  if (isAllZero(key)) {
    throw new Error("obsigil: mandate key must not be all-zero");
  }
}

/** Constant-time all-zero test. An all-zero key is never a CSPRNG output and
 *  signals operator misconfiguration (a zeroed/placeholder secret); rejected
 *  for parity with the reference implementations. */
function isAllZero(key: Uint8Array): boolean {
  let acc = 0;
  for (const b of key) acc |= b;
  return acc === 0;
}

/** Normalize a mandate key to its 64 raw bytes, accepting the canonical hex
 *  string (128 lowercase hex digits, the default form §6.2) or raw bytes (the
 *  alternative). Uppercase is rejected, not lowercased, and the key material is
 *  the decoded bytes, not the hex characters. A malformed key throws a
 *  (non-uniform) configuration error, never the uniform token rejection (the
 *  Key format, §6.2). */
export function coerceMandateKey(key: MandateKeyInput): Uint8Array {
  if (typeof key === "string") {
    const bytes = decodeHex(key);
    if (bytes === null || bytes.length !== 64) {
      throw new Error("obsigil: mandate key must be 128 lowercase hexadecimal digits");
    }
    key = bytes;
  }
  assertMandateKey(key);
  return key;
}
