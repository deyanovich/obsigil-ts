// Minting — the trusted issuer side (Construction, spec §5). Descriptive errors: minting
// is not bearer-facing, so detail here is not an oracle.

import { MANIFEST_KEY, RESERVED_NAMES, encodeB64url, encodeHex, encodeHalf, seal } from "@obsigil/core";
import type { Alg, Encoding, HalfFields, NumericDate } from "@obsigil/core";
import { coerceMandateKey } from "./keys.js";
import type { MandateKeyInput } from "./keys.js";
import { generateUuidV7, isUuidV7, uuidToBytes } from "./uuid.js";

export interface MintInput {
  /** Application clauses (opaque data). Reserved names here are ignored —
   *  set reserved fields via the dedicated options below. */
  clauses: Record<string, unknown>;
  /** The secret mandate key: its canonical hex string (128 lowercase hex
   *  digits, the default form, the Key format §6.2) or the raw 64 bytes. */
  mandateKey: MandateKeyInput;
  /** Authoritative expiry, NumericDate seconds (the exp reserved field, spec §8.3). */
  exp: NumericDate;
  /** Override the auto-generated UUIDv7 `tid` (the tid reserved field, spec §8.2). */
  tid?: string;
  /** Intended verifiers; must be non-empty if set (the aud reserved field, spec §8.4). */
  aud?: string[];
  /** Subject authorized (the sub reserved field, spec §8.5). */
  sub?: string;
  /** Issuer, for audit (the iss reserved field, spec §8.6). */
  iss?: string;
  /** Mandate algorithm code (default `"0"`, AES-SIV). */
  alg?: Alg;
  /** Token-wide text encoding (default `"b64"`). */
  encoding?: Encoding;
  /** Optional public manifest half (keyless). */
  manifest?: {
    iss: string;
    claims?: Record<string, unknown>;
    exp?: NumericDate;
    alg?: Alg;
  };
}

function encodeText(bytes: Uint8Array, encoding: Encoding): string {
  return encoding === "b64" ? encodeB64url(bytes) : encodeHex(bytes);
}

/** Application clauses with any reserved name filtered out, so a reserved
 *  field cannot be spoofed through `clauses` (Reserved fields, spec §8). */
function appData(app: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(app)) {
    if (!(RESERVED_NAMES as readonly string[]).includes(k)) out[k] = v;
  }
  return out;
}

/** Mint a token (Token structure §4, Construction §5). */
export function mint(input: MintInput): string {
  const mandateKey = coerceMandateKey(input.mandateKey);
  const encoding = input.encoding ?? "b64";
  const separator = encoding === "b64" ? "." : "~";

  const tid = input.tid ?? generateUuidV7();
  if (!isUuidV7(tid)) throw new Error("obsigil: tid must be a UUIDv7");
  if (input.aud && input.aud.length === 0) {
    throw new Error("obsigil: aud must be a non-empty array");
  }
  // exp is a NumericDate — a CBOR integer (the exp reserved field, §8.3). A
  // non-integer would encode as a float that every verifier (incl. this one)
  // rejects, so fail loudly at mint instead.
  if (!Number.isInteger(input.exp)) {
    throw new Error("obsigil: exp must be an integer NumericDate");
  }

  // The mandate half: reserved fields at their negative keys (tid always the
  // 16-byte binary form, the tid reserved field, spec §8.2), application data at text keys.
  const fields: HalfFields = {
    tid: uuidToBytes(tid),
    exp: input.exp,
    app: appData(input.clauses),
  };
  if (input.iss !== undefined) fields.iss = input.iss;
  if (input.aud !== undefined) fields.aud = input.aud;
  if (input.sub !== undefined) fields.sub = input.sub;

  const mandateAlg = input.alg ?? "0";
  const mandateText = encodeText(seal(encodeHalf(fields), mandateKey, mandateAlg), encoding);
  const mandatePart = mandateAlg + mandateText;

  let manifestPart = "";
  if (input.manifest) {
    const m = input.manifest;
    const mfields: HalfFields = { iss: m.iss, app: appData(m.claims ?? {}) };
    if (m.exp !== undefined) mfields.exp = m.exp;
    const manifestAlg = m.alg ?? "0";
    const manifestText = encodeText(seal(encodeHalf(mfields), MANIFEST_KEY, manifestAlg), encoding);
    manifestPart = manifestText + manifestAlg;
  }

  return manifestPart + separator + mandatePart;
}
