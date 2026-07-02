// Core obsigil types. See the obsigil spec sections cited inline.

/** Seconds since the Unix epoch (JWT NumericDate); used by `exp`. */
export type NumericDate = number;

/** A token's text encoding, named by its separator (Token structure, spec §4): `.` => b64,
 *  `~` => hex. */
export type Encoding = "b64" | "hex";

/** An algorithm code naming a half's AEAD (the Algorithm registry, spec §6). obsigil v1 registers
 *  `0` (AES-SIV, RFC 5297) and `1` (AES-GCM-SIV, RFC 8452). The grammar
 *  permits any `0`-`9`/`a`-`z`; unregistered codes are rejected at
 *  decryption, not at parse. */
export type Alg = "0" | "1";

/** Lowest legal decoded length of a sealed half (the sealing-output layout
 *  of the Algorithm registry, spec §6.2): the AEAD's
 *  16-byte floor (synthetic IV or auth tag) plus at least one byte for the
 *  canonical CBOR map (the empty map `0xa0`) the plaintext now carries. */
export const MIN_HALF_BYTES = 17;

/** Largest decoded half a verifier admits before trial decryption (the
 *  limits-and-robustness rule of the Security Considerations, spec
 *  §16.10): a bound on attacker-controlled work, 64 KiB by default. */
export const MAX_DECODED_BYTES = 64 * 1024;
