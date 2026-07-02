// A token half's field set (Serialization §7, Reserved fields §8). Both halves are one canonical
// CBOR map: reserved fields at negative integer keys (tid -1, exp -2, aud -3,
// sub -4, iss -5), application data at non-negative integer / text-string
// keys. obsigil owns the entire negative-key space, so an unrecognized
// negative key is rejected fail-closed.
//
// The sign IS the namespace: a reserved field is read ONLY from its negative
// key. An application key — even one whose text happens to be a reserved name
// like "exp" — is opaque data and can never satisfy or shadow a reserved
// field. `encodeHalf` builds and canonically encodes the map; `decodeHalf`
// (mandate) and `decodeManifest` strictly decode it, classify the sign-split
// namespace, type-check every reserved field, and return a flat object
// (reserved by name — `tid` as its 16 raw bytes — plus application data).
// They return null for any non-canonical input, an unrecognized negative key,
// or a wrong-typed reserved field, so a caller can fold every such failure
// into one uniform rejection (the uniform-failure rule of the Security
// Considerations, spec §16.6). The manifest accepts only the iss
// and exp reserved keys; any other reserved key (a mandate-only tid/aud/sub,
// or an unknown one) is rejected (the iss reserved field §8.6; the
// manifest-is-non-authoritative rule of the Security Considerations §16.7).

import { CborFloat, decodeStrict, encodeCanonical } from "./serial/cbor.js";

/** Reserved field name → its negative integer key (Reserved fields, spec §8). */
export const RESERVED_KEYS = { tid: -1, exp: -2, aud: -3, sub: -4, iss: -5 } as const;

/** The reserved field names obsigil interprets. Every other name is opaque
 *  application data. */
export const RESERVED_NAMES = ["tid", "exp", "aud", "sub", "iss"] as const;

type ReservedName = keyof typeof RESERVED_KEYS;

const KEY_TO_NAME: Record<number, ReservedName> = {
  [-1]: "tid",
  [-2]: "exp",
  [-3]: "aud",
  [-4]: "sub",
  [-5]: "iss",
};

const RESERVED_NAME_SET: ReadonlySet<string> = new Set(RESERVED_NAMES);

/** The reserved keys a manifest may carry (the iss reserved field, spec §8.6): iss (required by the
 *  caller) and an advisory exp. tid/aud/sub are mandate-only. */
const MANIFEST_NAMES: ReadonlySet<ReservedName> = new Set(["iss", "exp"]);

/** Reserved fields a half carries, by name, plus opaque application data.
 *  `tid` is its 16 raw bytes; the caller converts a UUID string first. */
export interface HalfFields {
  tid?: Uint8Array;
  exp?: number;
  aud?: string[];
  sub?: string;
  iss?: string;
  /** Application data (reserved names must already be filtered out). */
  app?: Record<string, unknown>;
}

/** A decoded half: reserved fields by name (`tid` still its 16 raw bytes)
 *  plus application data at their own keys. */
export interface DecodedHalf {
  tid?: Uint8Array;
  exp?: number;
  aud?: string[];
  sub?: string;
  iss?: string;
  [appKey: string]: unknown;
}

/** Build and canonically encode a half's CBOR map (Serialization, spec §7). */
export function encodeHalf(fields: HalfFields): Uint8Array {
  const m = new Map<number | string, unknown>();
  if (fields.tid !== undefined) m.set(RESERVED_KEYS.tid, fields.tid);
  if (fields.exp !== undefined) m.set(RESERVED_KEYS.exp, fields.exp);
  if (fields.aud !== undefined) m.set(RESERVED_KEYS.aud, fields.aud);
  if (fields.sub !== undefined) m.set(RESERVED_KEYS.sub, fields.sub);
  if (fields.iss !== undefined) m.set(RESERVED_KEYS.iss, fields.iss);
  for (const [k, v] of Object.entries(fields.app ?? {})) {
    if (v !== undefined) m.set(k, v);
  }
  return encodeCanonical(m);
}

/** Strictly decode a mandate half and classify the sign-split namespace
 *  (Serialization §7, Reserved fields §8). All five reserved keys are recognized. */
export function decodeHalf(plain: Uint8Array): DecodedHalf | null {
  return classify(plain, null);
}

/** Strictly decode a manifest half (the iss reserved field §8.6; the
 *  manifest-is-non-authoritative rule of the Security Considerations §16.7). Only the iss and exp
 *  reserved keys are recognized; any mandate-only reserved key (tid/aud/sub)
 *  or an unknown negative key is rejected. */
export function decodeManifest(plain: Uint8Array): DecodedHalf | null {
  return classify(plain, MANIFEST_NAMES);
}

/** Decode and classify a half. `allowed`, when non-null, restricts which
 *  reserved fields may appear (the manifest's iss/exp). A reserved field is
 *  read ONLY from its negative key; an application key named like a reserved
 *  field stays opaque and is dropped so it can never reach a reserved slot. */
function classify(plain: Uint8Array, allowed: ReadonlySet<ReservedName> | null): DecodedHalf | null {
  let value: unknown;
  try {
    value = decodeStrict(plain);
  } catch {
    return null;
  }
  if (!(value instanceof Map)) return null;

  const reserved: DecodedHalf = {};
  const app: Record<string, unknown> = {};
  for (const [k, v] of value as Map<number | string, unknown>) {
    if (typeof k === "number" && k < 0) {
      const name = KEY_TO_NAME[k];
      if (name === undefined) return null; // unknown negative key — fail closed
      if (allowed !== null && !allowed.has(name)) return null; // not a manifest claim
      if (!checkReserved(name, v)) return null;
      reserved[name] = v as never;
    } else {
      const key = typeof k === "number" ? String(k) : k;
      // An application key named like a reserved field is opaque but
      // ambiguous in a flat result; drop it so it can never shadow the
      // reserved slot (which is read only from the negative key).
      if (RESERVED_NAME_SET.has(key)) continue;
      app[key] = toAppValue(v);
    }
  }
  return { ...app, ...reserved };
}

/** Whether a reserved value has its required CBOR type (Reserved fields, spec §8). */
function checkReserved(name: ReservedName, v: unknown): boolean {
  switch (name) {
    case "tid":
      return v instanceof Uint8Array && v.length === 16; // 16-byte byte string (the tid reserved field, §8.2)
    case "exp":
      return typeof v === "number"; // NumericDate integer (a float decodes to CborFloat)
    case "aud":
      return Array.isArray(v) && v.length > 0 && v.every((e) => typeof e === "string");
    case "sub":
    case "iss":
      return typeof v === "string";
  }
}

/** Convert a decoded application value to its plain JS form: unwrap floats,
 *  turn nested CBOR maps into objects, recurse into arrays. */
function toAppValue(v: unknown): unknown {
  if (v instanceof CborFloat) return v.value;
  if (Array.isArray(v)) return v.map(toAppValue);
  if (v instanceof Map) {
    const obj: Record<string, unknown> = {};
    for (const [k, val] of v as Map<number | string, unknown>) {
      obj[typeof k === "number" ? String(k) : k] = toAppValue(val);
    }
    return obj;
  }
  return v;
}
