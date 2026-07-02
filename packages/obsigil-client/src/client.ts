// The obsigil front-end client surface. A front end does two things, and
// holds no mandate key:
//
//   1. claims  — open the keyless manifest for display (advisory).
//   2. mandate / authorizationHeader — hand the backend the mandate to
//      enforce, as the manifest-absent ".0mandate" token (forwarding the mandate, Audiences, spec §9).
//
// Two noun accessors mirror the two halves as standalone tokens (the
// encoded `manifest` half and the encoded `mandate` half) and one keyless
// read (`manifestPlaintext`) yields the manifest's raw CBOR octets.
//
// Manifest claims are NEVER authoritative (the manifest-is-non-authoritative
// rule of the Security Considerations, spec §16.7): they drive UI only.
// The mandate is never decrypted here — the client has no key — so the
// mandate path is pure string work and is blind to the mandate's
// algorithm and serialization.

import {
  MANIFEST_KEY,
  MAX_DECODED_BYTES,
  MIN_HALF_BYTES,
  decodeB64url,
  decodeHex,
  decodeManifest,
  open,
  parseToken,
} from "@obsigil/core";
import type { Encoding, NumericDate } from "@obsigil/core";

/** Public manifest claims (Reserved fields, spec §8). Reserved names carry fixed meaning;
 *  every other name is opaque application data. All claims are advisory —
 *  a reader MUST NOT make a security decision from them (the
 *  manifest-is-non-authoritative rule of the Security Considerations, spec §16.7). */
export interface Claims {
  /** Issuer, for display. Required in a present manifest (the iss reserved field, spec §8.6). */
  iss: string;
  /** Advisory refresh hint only; never authoritative (the exp reserved field, spec §8.3). */
  exp?: NumericDate;
  [claim: string]: unknown;
}

function decodeText(text: string, encoding: Encoding): Uint8Array | null {
  return encoding === "b64" ? decodeB64url(text) : decodeHex(text);
}

/**
 * The manifest's advisory claims, for display. Keyless and advisory.
 *
 * Decrypts the manifest half with the public {@link MANIFEST_KEY} under
 * algorithm code `0` (AES-SIV) or `1` (AES-GCM-SIV), then strictly decodes
 * its canonical CBOR map as a manifest (Serialization §7, the iss reserved field §8.6) — only the reserved
 * iss and exp claims are recognized; a mandate-only reserved key (tid/aud/sub)
 * or an unknown negative key is rejected. Returns the claims, or `null` when
 * there is nothing trustworthy to display: no manifest half, a malformed
 * token, non-canonical text or CBOR encoding, an oversized half,
 * authentication failure, an unsupported algorithm, or a manifest missing its
 * required reserved `iss` (the iss reserved field, spec §8.6).
 *
 * Never throws and never an oracle — `null` means "display nothing". The
 * front end MUST treat the result as advisory only (the
 * manifest-is-non-authoritative rule of the Security Considerations, spec §16.7); a manifest
 * `exp`, if present, is a refresh hint, never enforcement (the exp reserved field, spec §8.3).
 */
export function claims(token: string): Claims | null {
  // The required `iss` comes only from the reserved key −5; decodeManifest
  // rejects any mandate-only reserved key.
  const plain = manifestPlaintext(token);
  if (plain === null || plain.length < 1) return null;
  const fields = decodeManifest(plain);
  if (fields === null || typeof fields.iss !== "string") return null;
  return fields as Claims;
}

/**
 * The encoded manifest half on its own, as the manifest-only token form
 * (Token structure, spec §4): the manifest ciphertext, its algorithm code, then the
 * separator — e.g. `"<manifest>0."`. The mirror of {@link mandate}.
 *
 * Pure string transform — no key, no decryption. Returns `null` when the
 * token carries no manifest half or is malformed.
 */
export function manifest(token: string): string | null {
  const parsed = parseToken(token);
  if (!parsed.ok) return null;
  const { manifest, separator } = parsed.token;
  if (manifest === null) return null;
  return manifest.text + manifest.algCode + separator;
}

/**
 * The manifest half's raw plaintext: the canonical CBOR octets, decrypted
 * keyless under the public {@link MANIFEST_KEY}. The byte-level mirror of
 * {@link claims}, for callers that want the undecoded map (Serialization §7, the iss reserved field §8.6).
 *
 * Returns `null` — never throws, never an oracle — when there is no manifest
 * half, the token is malformed, the text is non-canonical, the half is below
 * the floor or oversized, the algorithm is unsupported, or authentication
 * fails. Advisory only (the manifest-is-non-authoritative rule of the Security Considerations, spec §16.7).
 */
export function manifestPlaintext(token: string): Uint8Array | null {
  const parsed = parseToken(token);
  if (!parsed.ok) return null;

  const { encoding, manifest } = parsed.token;
  if (manifest === null) return null;

  // Bound the encoded half before decoding (the limits-and-robustness rule,
  // §16.10): a cheap over-estimate (hex is densest at 2 chars/byte) so an
  // oversize manifest can't force an unbounded decode.
  if (manifest.text.length > MAX_DECODED_BYTES * 2 + 8) return null;
  const sealed = decodeText(manifest.text, encoding);
  if (sealed === null || sealed.length < MIN_HALF_BYTES || sealed.length > MAX_DECODED_BYTES) {
    return null;
  }

  // `open` returns null for any algorithm code the client does not
  // implement, so an unsupported manifest simply yields nothing.
  return open(sealed, MANIFEST_KEY, manifest.algCode);
}

/**
 * The mandate to send to the backend: the manifest-absent `.0mandate`
 * form (forwarding the mandate, Audiences, spec §9), itself a well-formed obsigil token whose leading
 * separator and algorithm code still name the encoding and cipher.
 *
 * Pure string transform — no key, no decryption — so it works for any
 * mandate algorithm code or serialization, including ones the client
 * cannot open. Returns `null` when the token carries no mandate half or is
 * malformed.
 */
export function mandate(token: string): string | null {
  const parsed = parseToken(token);
  if (!parsed.ok) return null;
  if (parsed.token.mandate === null) return null;
  return parsed.token.separator + parsed.token.mandatePart;
}

/**
 * The `Authorization` header value carrying the mandate, e.g.
 * `"Bearer .0mandate"`. Returns `null` when {@link mandate} is `null`.
 *
 * The obsigil spec defines the token, not its HTTP framing; `Bearer` is
 * the default because the mandate is a bearer credential (the
 * bearer-credential rule of the Security Considerations, spec §16.9) and
 * the scheme rides existing server middleware. Pass `scheme: ""` to get
 * the bare mandate token with no prefix.
 */
export function authorizationHeader(
  token: string,
  scheme = "Bearer",
): string | null {
  const m = mandate(token);
  if (m === null) return null;
  return scheme.length > 0 ? `${scheme} ${m}` : m;
}
