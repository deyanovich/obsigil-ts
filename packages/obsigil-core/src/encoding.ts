// Strict, canonical text encoders/decoders for obsigil halves (Token
// structure, spec §4).
//
// Both encodings are canonical and strict. A decoder MUST reject
// non-canonical input: `=` padding, whitespace, any out-of-alphabet
// character, a b64 symbol whose unused trailing bits are non-zero, a b64
// string whose length is 1 modulo 4, or an odd-length hex string. The
// canonical form a producer emits is always lowercase. We hand-roll these
// because stock decoders (`atob`, etc.) do not enforce that strictness.
//
// Every decoder returns `null` on any violation rather than throwing, so
// callers can fold the failure into a uniform rejection (the uniform-failure
// rule of the Security Considerations, spec §16.6).

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// Reverse lookup: ASCII code -> 6-bit value, or -1 if outside the alphabet.
const B64URL_REV: Int16Array = (() => {
  const t = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64URL.length; i++) t[B64URL.charCodeAt(i)] = i;
  return t;
})();

function b64Symbol(s: string, i: number): number {
  const code = s.charCodeAt(i);
  if (code >= 128) return -1;
  return B64URL_REV[code] ?? -1;
}

/** Decode URL-safe base64 with no padding (Token structure, spec §4). Returns null on any
 *  non-canonical input. */
export function decodeB64url(s: string): Uint8Array | null {
  const len = s.length;
  if (len % 4 === 1) return null; // impossible no-padding length
  const fullGroups = (len / 4) | 0;
  const rem = len - fullGroups * 4; // 0, 2, or 3
  const out = new Uint8Array(fullGroups * 3 + (rem === 0 ? 0 : rem - 1));
  let oi = 0;
  let si = 0;
  for (let g = 0; g < fullGroups; g++) {
    const a = b64Symbol(s, si++);
    const b = b64Symbol(s, si++);
    const c = b64Symbol(s, si++);
    const d = b64Symbol(s, si++);
    if (a < 0 || b < 0 || c < 0 || d < 0) return null;
    out[oi++] = (a << 2) | (b >> 4);
    out[oi++] = ((b & 0x0f) << 4) | (c >> 2);
    out[oi++] = ((c & 0x03) << 6) | d;
  }
  if (rem === 2) {
    const a = b64Symbol(s, si++);
    const b = b64Symbol(s, si++);
    if (a < 0 || b < 0) return null;
    if ((b & 0x0f) !== 0) return null; // non-zero trailing bits
    out[oi++] = (a << 2) | (b >> 4);
  } else if (rem === 3) {
    const a = b64Symbol(s, si++);
    const b = b64Symbol(s, si++);
    const c = b64Symbol(s, si++);
    if (a < 0 || b < 0 || c < 0) return null;
    if ((c & 0x03) !== 0) return null; // non-zero trailing bits
    out[oi++] = (a << 2) | (b >> 4);
    out[oi++] = ((b & 0x0f) << 4) | (c >> 2);
  }
  return out;
}

/** Encode bytes as URL-safe base64 with no padding (Token structure, spec §4). */
export function encodeB64url(bytes: Uint8Array): string {
  let out = "";
  const len = bytes.length;
  let i = 0;
  for (; i + 3 <= len; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out +=
      B64URL[(n >> 18) & 63]! +
      B64URL[(n >> 12) & 63]! +
      B64URL[(n >> 6) & 63]! +
      B64URL[n & 63]!;
  }
  const rem = len - i;
  if (rem === 1) {
    const n = bytes[i]! << 16;
    out += B64URL[(n >> 18) & 63]! + B64URL[(n >> 12) & 63]!;
  } else if (rem === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out +=
      B64URL[(n >> 18) & 63]! + B64URL[(n >> 12) & 63]! + B64URL[(n >> 6) & 63]!;
  }
  return out;
}

const HEX = "0123456789abcdef";

function hexVal(code: number): number {
  if (code >= 0x30 && code <= 0x39) return code - 0x30; // 0-9
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10; // a-f (lowercase)
  return -1;
}

/** Decode lowercase hex of even length (Token structure, spec §4). Uppercase is rejected:
 *  the canonical form is lowercase. A deployment that wants to tolerate
 *  case-mangling transport lowercases the token before calling this. */
export function decodeHex(s: string): Uint8Array | null {
  const len = s.length;
  if (len % 2 !== 0) return null;
  const out = new Uint8Array(len >> 1);
  for (let i = 0; i < len; i += 2) {
    const hi = hexVal(s.charCodeAt(i));
    const lo = hexVal(s.charCodeAt(i + 1));
    if (hi < 0 || lo < 0) return null;
    out[i >> 1] = (hi << 4) | lo;
  }
  return out;
}

/** Encode bytes as lowercase hex (Token structure, spec §4). */
export function encodeHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]!;
    out += HEX[b >> 4]! + HEX[b & 0x0f]!;
  }
  return out;
}
