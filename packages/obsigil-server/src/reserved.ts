// Reserved fields (spec §8). The library owns the reserved names; every
// other name is opaque application data. The names map to negative integer
// keys on the wire (see `RESERVED_KEYS` in obsigil-core); these interfaces
// are the decoded, developer-facing shapes.

import type { NumericDate } from "@obsigil/core";
import { uuidV7Time } from "./uuid.js";

/** Verified mandate clauses (Reserved fields, spec §8). Reserved fields carry fixed
 *  meaning; the rest is application data. `tid` is the canonical UUIDv7
 *  string. */
export interface Clauses {
  /** Authoritative expiry (the exp reserved field, spec §8.3). */
  exp: NumericDate;
  /** Unique token id, UUIDv7 (the tid reserved field, spec §8.2). */
  tid: string;
  /** Issuer, for audit (the iss reserved field, spec §8.6). */
  iss?: string;
  /** Intended verifiers (the aud reserved field, spec §8.4). */
  aud?: string[];
  /** Subject authorized (the sub reserved field, spec §8.5). */
  sub?: string;
  [claim: string]: unknown;
}

/** Public manifest claims (Reserved fields, spec §8). Advisory only (the manifest-is-non-authoritative rule of the Security Considerations, §16.7). */
export interface Claims {
  /** Issuer, for display. Required in a present manifest (the iss reserved field, spec §8.6). */
  iss: string;
  /** Advisory refresh hint only (the exp reserved field, spec §8.3). */
  exp?: NumericDate;
  [claim: string]: unknown;
}

/** A reserved accessor over verified {@link Clauses}: the mandate's issue
 *  time (NumericDate seconds), derived from the UUIDv7 `tid`'s embedded
 *  48-bit millisecond timestamp (the tid reserved field, spec §8.2). Companion to the by-name
 *  reserved fields (`exp`/`tid`/`sub`/`iss`/`aud`) the record already
 *  surfaces. The `tid` is the verified canonical UUIDv7 string. */
export function issuedAt(clauses: Clauses): NumericDate {
  return uuidV7Time(clauses.tid);
}
