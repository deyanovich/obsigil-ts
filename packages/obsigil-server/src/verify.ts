// Verifying — the authoritative backend side (Audiences §9, Security
// Considerations §16, Reserved fields §8). Every
// rejection collapses to one opaque ObsigilError; the granular cause goes
// to policy.onReject for internal logging only (the uniform-failure rule of
// the Security Considerations, spec §16.6).
//
// Three layered reads share the same authentication path and differ only in
// how far they validate the recovered mandate:
//
//   mandatePlaintext  — authenticate only; return the raw CBOR octets.
//   clausesUnchecked  — authenticate + canonical-CBOR decode + classify;
//                       SKIP the policy value-checks (tid-is-v7, exp
//                       presence/expiry, aud match).
//   clauses           — the full verify: every policy value-check enforced.
//
// All three still reject a wrong key, a half below the floor / oversized,
// non-canonical CBOR, an unknown negative key, and a wrong-typed reserved
// field — those are structural, not policy.

import { MAX_DECODED_BYTES, MIN_HALF_BYTES, decodeB64url, decodeHalf, decodeHex, open, parseToken } from "@obsigil/core";
import type { Encoding, NumericDate } from "@obsigil/core";
import { ObsigilError } from "./error.js";
import type { Reason } from "./error.js";
import { coerceMandateKey } from "./keys.js";
import type { MandateKeyInput } from "./keys.js";
import type { Clauses } from "./reserved.js";
import { isUuidV7, uuidFromBytes } from "./uuid.js";

/** Largest clock-skew leeway a verifier honours, regardless of policy (the
 *  limits-and-robustness rule of the Security Considerations, spec
 *  §16.10) — a bound so a hostile leeway cannot resurrect a long-expired exp. */
const MAX_LEEWAY_SECONDS = 60;

export interface VerifyPolicy {
  /** Candidate mandate key(s); tried in order (the trial-decryption rule of the Security Considerations, §16.5).
   *  Each key is its canonical hex string (the default, the Key format §6.2) or
   *  raw 64 bytes. */
  keys: MandateKeyInput | MandateKeyInput[];
  /** This verifier's identifier, checked against a present `aud` (the aud reserved field, §8.4). */
  audience?: string;
  /** Clock-skew leeway in seconds for `exp`; clamped to 60 s (the exp reserved field §8.3; the limits-and-robustness rule of the Security Considerations §16.10). */
  leewaySeconds?: number;
  /** Pin "now" (NumericDate seconds) instead of the system clock. */
  now?: NumericDate;
  /** Largest decoded half to admit before trial decryption (default 64 KiB,
   *  the limits-and-robustness rule of the Security Considerations, spec §16.10). */
  maxDecodedBytes?: number;
  /** Internal diagnostics only — never surface the reason to the bearer. */
  onReject?: (reason: Reason) => void;
}

function decode(text: string, encoding: Encoding): Uint8Array | null {
  return encoding === "b64" ? decodeB64url(text) : decodeHex(text);
}

/** The candidate keys a diagnostic read needs, or a full policy to draw them
 *  from. `clausesUnchecked` / `mandatePlaintext` consume only the keys (and
 *  any size bound / onReject hook), so a bare key or key list suffices. */
export type KeysOrPolicy = VerifyPolicy | MandateKeyInput | MandateKeyInput[];

function asPolicy(arg: KeysOrPolicy): VerifyPolicy {
  if (typeof arg === "string" || arg instanceof Uint8Array || Array.isArray(arg)) {
    return { keys: arg };
  }
  return arg;
}

type Fail = { ok: false; reason: Reason };

/** Tier 1 — authenticate the mandate half and return its raw plaintext
 *  octets. Parses, bounds the decoded size, then trial-decrypts across the
 *  candidate keys (forwarding the mandate, Audiences §9; the trial-decryption
 *  §16.5 and limits-and-robustness §16.10 rules of the Security
 *  Considerations). No CBOR decode, no policy check. */
function authenticate(token: string, policy: VerifyPolicy): { ok: true; plain: Uint8Array } | Fail {
  const parsed = parseToken(token);
  if (!parsed.ok) return { ok: false, reason: "malformed" };

  const { encoding, mandate } = parsed.token;
  if (mandate === null) return { ok: false, reason: "empty-mandate" };
  if (mandate.algCode !== "0" && mandate.algCode !== "1") {
    return { ok: false, reason: "unsupported" };
  }

  // Bound attacker-controlled work BEFORE decoding (the limits-and-robustness
  // rule of the Security Considerations, spec §16.10): reject an oversize
  // encoded half up front by a cheap over-estimate (hex is densest at 2
  // chars/byte), so a huge token can't force an unbounded decode
  // allocation/scan; the exact decoded length is checked below.
  const maxBytes = policy.maxDecodedBytes ?? MAX_DECODED_BYTES;
  if (mandate.text.length > maxBytes * 2 + 8) return { ok: false, reason: "too-large" };
  const sealed = decode(mandate.text, encoding);
  if (sealed === null || sealed.length < MIN_HALF_BYTES) {
    return { ok: false, reason: "malformed" };
  }
  if (sealed.length > maxBytes) return { ok: false, reason: "too-large" };

  // Accept each candidate as a hex string (the default) or raw bytes (the Key
  // format, §6.2); a malformed key is a config error, not a token rejection.
  const rawKeys = Array.isArray(policy.keys) ? policy.keys : [policy.keys];
  const keys = rawKeys.map(coerceMandateKey);

  let plain: Uint8Array | null = null;
  for (const key of keys) {
    plain = open(sealed, key, mandate.algCode);
    if (plain !== null) break;
  }
  if (plain === null) return { ok: false, reason: "auth-failed" };
  return { ok: true, plain };
}

/** Tier 2 — authenticate, then strictly decode the canonical CBOR map and
 *  classify the sign-split namespace, failing closed on any unrecognized
 *  negative key or wrong-typed reserved field (Serialization §7, Reserved fields §8). The binary
 *  `tid` (16-byte CBOR form, the tid reserved field, spec §8.2) is normalized to its string. NO
 *  policy value-check: tid-is-v7, exp presence/expiry, and aud match are
 *  left to {@link clauses}. */
function decodeClauses(token: string, policy: VerifyPolicy): { ok: true; clauses: Clauses } | Fail {
  const auth = authenticate(token, policy);
  if (!auth.ok) return auth;

  const fields = decodeHalf(auth.plain);
  if (fields === null) return { ok: false, reason: "non-canonical" };

  // Normalize the binary `tid` (16-byte CBOR form, the tid reserved field, spec §8.2) to its string.
  let tid: unknown = fields.tid;
  if (tid instanceof Uint8Array && tid.length === 16) tid = uuidFromBytes(tid);
  return { ok: true, clauses: { ...fields, tid } as Clauses };
}

type Inner = { ok: true; clauses: Clauses } | Fail;

const AUD_ENC = new TextEncoder();

/** Constant-time byte equality (no early exit): 1 if equal, else 0. */
function ctEqZero(a: Uint8Array, b: Uint8Array): number {
  let diff = a.length ^ b.length;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0 ? 1 : 0;
}

/** Constant-time `aud` membership over the decoded text (the uniform-failure
 *  rule of the Security Considerations, §16.6: don't leak which entry matched;
 *  §8.4 raw byte-exact test). Every entry is compared with no early exit,
 *  mirroring the reference implementation. */
function audContains(aud: string[], me: string): boolean {
  const meBytes = AUD_ENC.encode(me);
  let hit = 0;
  for (const a of aud) hit |= ctEqZero(AUD_ENC.encode(a), meBytes);
  return hit === 1;
}

/** Tier 3 — the full verify: every policy value-check enforced. */
function verifyInner(token: string, policy: VerifyPolicy): Inner {
  const decoded = decodeClauses(token, policy);
  if (!decoded.ok) return decoded;
  const c = decoded.clauses;

  if (!isUuidV7(c.tid)) return { ok: false, reason: "bad-tid" };
  if (typeof c.exp !== "number") return { ok: false, reason: "missing-clause" };

  const now = policy.now ?? Math.floor(Date.now() / 1000);
  const leeway = Math.min(Math.max(policy.leewaySeconds ?? 0, 0), MAX_LEEWAY_SECONDS);
  if (now >= c.exp + leeway) return { ok: false, reason: "expired" };

  if (c.aud !== undefined) {
    // decodeHalf has already guaranteed a non-empty array of text strings.
    const aud = c.aud as string[];
    if (policy.audience === undefined || !audContains(aud, policy.audience)) {
      return { ok: false, reason: "audience-mismatch" };
    }
  }

  return { ok: true, clauses: c };
}

/**
 * Verify a token's mandate and return its clauses (Audiences §9, Security Considerations §16, Reserved fields §8).
 * Accepts a full token or the forwarded `.0mandate` form; the manifest is
 * never parsed or trusted. On any failure throws a single {@link
 * ObsigilError} (the uniform-failure rule of the Security Considerations, spec §16.6); the granular cause is delivered to
 * `policy.onReject` for internal logging only.
 */
export function clauses(token: string, policy: VerifyPolicy): Clauses {
  const result = verifyInner(token, policy);
  if (result.ok) return result.clauses;
  policy.onReject?.(result.reason);
  throw new ObsigilError();
}

/**
 * Diagnostic read: authenticate the mandate and canonically decode its
 * clauses, but SKIP the policy value-checks (tid-is-UUIDv7, exp
 * presence/expiry, aud match). A wrong key, a half below the floor /
 * oversized, non-canonical CBOR, an unknown negative key, or a wrong-typed
 * reserved field are still rejected. Pass the candidate key(s) directly or a
 * full {@link VerifyPolicy}. Throws a single {@link ObsigilError} on failure.
 *
 * For inspection/telemetry on an already-trusted channel — NOT an
 * authorization decision; use {@link clauses} to enforce.
 */
export function clausesUnchecked(token: string, keys: KeysOrPolicy): Clauses {
  const policy = asPolicy(keys);
  const result = decodeClauses(token, policy);
  if (result.ok) {
    // Require the reserved clauses to be structurally PRESENT (not the value
    // policy — no UUIDv7/expiry/audience checks) so the returned Clauses and
    // its accessors (issuedAt) stay total, matching the reference.
    const c = result.clauses;
    if (typeof c.tid !== "string") {
      policy.onReject?.("bad-tid");
      throw new ObsigilError();
    }
    if (typeof c.exp !== "number") {
      policy.onReject?.("missing-clause");
      throw new ObsigilError();
    }
    return c;
  }
  policy.onReject?.(result.reason);
  throw new ObsigilError();
}

/**
 * Diagnostic read: authenticate the mandate and return its raw plaintext —
 * the canonical CBOR octets — with no decode and no policy check. A wrong
 * key, a malformed token, a half below the floor, or an oversized half are
 * still rejected. Pass the candidate key(s) directly or a full {@link
 * VerifyPolicy}. Throws a single {@link ObsigilError} on failure.
 */
export function mandatePlaintext(token: string, keys: KeysOrPolicy): Uint8Array {
  const policy = asPolicy(keys);
  const result = authenticate(token, policy);
  if (result.ok) return result.plain;
  policy.onReject?.(result.reason);
  throw new ObsigilError();
}
