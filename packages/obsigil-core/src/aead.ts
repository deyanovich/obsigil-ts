// Deterministic AEAD seal/open for an obsigil half (the Algorithm registry, spec §6).
//
// Both registered algorithms key from a single 64-byte master and are used
// deterministically: no random nonce, no associated data (the key material
// §6.1 and sealing-output layout §6.2 of the Algorithm registry).
//
//   Code 0 (AES-SIV, RFC 5297): the full 64-byte master IS the AES-256-SIV
//     key (bytes 0-31 the S2V/CMAC key, bytes 32-63 the CTR key). Invoked
//     with a ZERO-element associated-data vector — S2V called with no AD
//     components, not one empty component. Layout: synthetic-IV(16) || ct.
//
//   Code 1 (AES-GCM-SIV, RFC 8452): the 32-byte key is HKDF-Expand(PRK =
//     master, info = "gcmsiv", L = 32) over HMAC-SHA-256 — Expand only, no
//     Extract. Invoked with a fixed all-zero 12-byte nonce and no AAD;
//     the fixed nonce is not emitted. Layout: ct || auth-tag(16).
//
// All noble import paths and primitive choices are isolated to this file:
// it is the single place to adjust if a dependency's module layout differs.

import { aessiv, gcmsiv } from "@noble/ciphers/aes.js";
import { expand } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import type { Alg } from "./types.js";

// info = the six ASCII bytes of "gcmsiv" (key material, Algorithm registry, spec §6.1).
const GCMSIV_INFO = new Uint8Array([0x67, 0x63, 0x6d, 0x73, 0x69, 0x76]);
// Fixed all-zero 12-byte nonce for deterministic AES-GCM-SIV (sealing-output layout, Algorithm registry, spec §6.2).
const GCMSIV_NONCE = new Uint8Array(12);

/** Derive the 32-byte AES-256-GCM-SIV key from a 64-byte master via
 *  HKDF-Expand only (no Extract), PRK = master, info = "gcmsiv" (key material, Algorithm registry, spec §6.1). */
function gcmsivKey(master: Uint8Array): Uint8Array {
  return expand(sha256, master, GCMSIV_INFO, 32);
}

/** Seal a half's plaintext (its canonical CBOR map, Serialization, spec §7) under a 64-byte
 *  master with the AEAD named by `alg`. Output layout per the sealing-output layout of the Algorithm registry, spec §6.2. */
export function seal(
  plaintext: Uint8Array,
  master: Uint8Array,
  alg: Alg,
): Uint8Array {
  if (alg === "0") return aessiv(master).encrypt(plaintext); // IV || ct
  return gcmsiv(gcmsivKey(master), GCMSIV_NONCE).encrypt(plaintext); // ct || tag
}

/** Open a sealed half under a 64-byte master. Returns the plaintext, or
 *  `null` on authentication failure, an unsupported/unknown algorithm
 *  code, or any cipher error. Never throws — the caller folds `null` into
 *  a uniform rejection (the uniform-failure rule of the Security
 *  Considerations, spec §16.6). `alg` is the raw code read from the
 *  token; codes other than the registered `0`/`1` yield `null`. */
export function open(
  sealed: Uint8Array,
  master: Uint8Array,
  alg: string,
): Uint8Array | null {
  try {
    if (alg === "0") return aessiv(master).decrypt(sealed);
    if (alg === "1") return gcmsiv(gcmsivKey(master), GCMSIV_NONCE).decrypt(sealed);
    return null;
  } catch {
    return null;
  }
}
