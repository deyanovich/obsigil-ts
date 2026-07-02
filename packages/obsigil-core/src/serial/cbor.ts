// Canonical CBOR codec (RFC 8949 §4.2) for obsigil's pure-data field set
// (Serialization, spec §7). This is the single serialization: each half's plaintext is one
// canonical CBOR map, with no leading format tag.
//
// `encodeCanonical` emits the core deterministic encoding: definite lengths,
// shortest-form integers / lengths / floats (the smallest of float16 /
// float32 / float64 that round-trips the value), and map keys sorted by
// their encoded bytes. `decodeStrict` is its inverse and rejects any
// non-canonical input — indefinite lengths, non-shortest arguments or
// floats, duplicate or unsorted map keys, trailing bytes, and tags — so a
// decoded half re-encodes to the exact bytes it came from.
//
// Maps are modelled as `Map<number | string, CborValue>` so an integer key
// (obsigil's reserved negative keys, Reserved fields, spec §8) stays distinct from a text
// key — a plain object keyed by `String(k)` would collapse the two. Byte
// strings decode to `Uint8Array` (how the 16-byte binary `tid` arrives,
// the tid reserved field, spec §8.2); CBOR floats decode to a {@link CborFloat} wrapper so a
// reserved field encoded as a float (e.g. an integer-valued `exp`) is
// distinguishable from a genuine integer.

const utf8Decode = new TextDecoder("utf-8", { fatal: true });
const utf8Encode = new TextEncoder();

/** A decoded CBOR floating-point value, kept distinct from an integer so the
 *  reserved-field type checks (Reserved fields, spec §8) can reject a float where an integer
 *  is required. Application floats are unwrapped to plain numbers. */
export class CborFloat {
  constructor(readonly value: number) {}
}

/** A value the canonical codec can represent (pure data, Serialization, spec §7). */
export type CborValue =
  | number
  | string
  | boolean
  | null
  | Uint8Array
  | CborFloat
  | CborValue[]
  | Map<number | string, CborValue>;

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

/** Canonically encode a pure-data value (RFC 8949 §4.2). */
export function encodeCanonical(value: unknown): Uint8Array {
  const out: number[] = [];
  writeValue(out, value);
  return Uint8Array.from(out);
}

function writeHead(out: number[], major: number, n: number): void {
  const m = major << 5;
  if (n < 24) out.push(m | n);
  else if (n < 0x100) out.push(m | 24, n);
  else if (n < 0x10000) out.push(m | 25, n >>> 8, n & 0xff);
  else if (n < 0x100000000) {
    out.push(m | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  } else {
    const hi = Math.floor(n / 0x100000000);
    const lo = n >>> 0;
    out.push(
      m | 27,
      (hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff,
      (lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff,
    );
  }
}

function writeBytes(out: number[], major: number, bytes: Uint8Array): void {
  writeHead(out, major, bytes.length);
  for (const b of bytes) out.push(b);
}

function writeInt(out: number[], v: number): void {
  if (v >= 0) writeHead(out, 0, v);
  else writeHead(out, 1, -1 - v);
}

/** Encode one map key (an integer or text string) to its canonical bytes. */
function encodeKey(k: number | string): Uint8Array {
  const out: number[] = [];
  if (typeof k === "number") writeInt(out, k);
  else writeBytes(out, 3, utf8Encode.encode(k));
  return Uint8Array.from(out);
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i]! !== b[i]!) return a[i]! - b[i]!;
  }
  return a.length - b.length;
}

function writeMap(out: number[], entries: Array<[number | string, unknown]>): void {
  const encoded = entries.map(([k, v]) => {
    const key = encodeKey(k);
    const val: number[] = [];
    writeValue(val, v);
    return { key, val: Uint8Array.from(val) };
  });
  encoded.sort((a, b) => compareBytes(a.key, b.key)); // RFC 8949 §4.2 bytewise
  writeHead(out, 5, encoded.length);
  for (const { key, val } of encoded) {
    for (const b of key) out.push(b);
    for (const b of val) out.push(b);
  }
}

function writeValue(out: number[], v: unknown): void {
  if (v === null || v === undefined) {
    out.push(0xf6); // null
  } else if (typeof v === "boolean") {
    out.push(v ? 0xf5 : 0xf4);
  } else if (v instanceof CborFloat) {
    writeFloat(out, v.value);
  } else if (typeof v === "number") {
    if (Number.isInteger(v)) {
      // Beyond ±2^53 a JS number cannot round-trip an exact integer, so the
      // 8-byte head would silently corrupt: fail closed instead.
      if (!Number.isSafeInteger(v)) throw new Error("cbor: integer out of safe range");
      writeInt(out, v);
    } else writeFloat(out, v);
  } else if (typeof v === "string") {
    writeBytes(out, 3, utf8Encode.encode(v));
  } else if (v instanceof Uint8Array) {
    writeBytes(out, 2, v);
  } else if (Array.isArray(v)) {
    writeHead(out, 4, v.length);
    for (const item of v) writeValue(out, item);
  } else if (v instanceof Map) {
    writeMap(out, [...(v as Map<number | string, unknown>)]);
  } else if (typeof v === "object") {
    const entries = Object.entries(v as Record<string, unknown>).filter(([, val]) => val !== undefined);
    writeMap(out, entries);
  } else {
    throw new Error("cbor: cannot encode value of this type");
  }
}

// ---- shortest-form float (RFC 8949 §4.2) ----------------------------------

/** Emit `value` as the shortest IEEE 754 width (half/single/double) that
 *  round-trips it exactly. NaN is forbidden: its bit patterns are not
 *  canonical across the reference implementations, so obsigil's CBOR rejects
 *  it on both encode and decode. */
function writeFloat(out: number[], value: number): void {
  if (Number.isNaN(value)) throw new Error("cbor: NaN is not permitted");
  const half = doubleToHalf(value);
  if (half !== null) {
    out.push(0xf9, (half >> 8) & 0xff, half & 0xff);
    return;
  }
  if (Math.fround(value) === value) {
    const buf = new Uint8Array(4);
    new DataView(buf.buffer).setFloat32(0, value);
    out.push(0xfa, buf[0]!, buf[1]!, buf[2]!, buf[3]!);
    return;
  }
  const buf = new Uint8Array(8);
  new DataView(buf.buffer).setFloat64(0, value);
  out.push(0xfb, ...buf);
}

/** The shortest float width (2/4/8 bytes) that round-trips `value`. */
function shortestFloatWidth(value: number): 2 | 4 | 8 {
  if (doubleToHalf(value) !== null) return 2;
  if (Math.fround(value) === value) return 4;
  return 8;
}

/** Validate a decoded float read at `width` bytes: reject NaN (non-canonical
 *  across the reference ports) and any non-shortest encoding. */
function readFloat(value: number, width: 2 | 4 | 8): CborFloat {
  if (Number.isNaN(value)) throw new Error("cbor: NaN is not permitted");
  if (shortestFloatWidth(value) !== width) throw new Error("cbor: non-shortest float");
  return new CborFloat(value);
}

/** Decode a 16-bit IEEE 754 half to a double. */
function halfToDouble(h: number): number {
  const sign = h & 0x8000 ? -1 : 1;
  const exp = (h >> 10) & 0x1f;
  const mant = h & 0x3ff;
  if (exp === 0) return sign * mant * 2 ** -24; // zero / subnormal
  if (exp === 0x1f) return mant ? NaN : sign * Infinity;
  return sign * (1 + mant / 1024) * 2 ** (exp - 15); // normal
}

/** The 16-bit half encoding of `value` if it round-trips exactly, else null.
 *  A reconstruct-and-compare guards the bit twiddling, so an imperfect case
 *  falls through to the wider widths rather than corrupting. */
function doubleToHalf(value: number): number | null {
  if (Number.isNaN(value)) return 0x7e00; // canonical quiet NaN
  if (value === Infinity) return 0x7c00;
  if (value === -Infinity) return 0xfc00;

  const sign = value < 0 || Object.is(value, -0) ? 0x8000 : 0;
  const a = Math.abs(value);
  if (a === 0) return sign;

  const bits = doubleBits(a);
  const exp = Number((bits >> 52n) & 0x7ffn);
  const mant = bits & 0xfffffffffffffn;

  let half: number;
  const e = exp - 1023 + 15; // rebias double -> half
  if (e >= 0x1f) {
    return null; // overflows half's normal range -> needs a wider width
  } else if (e <= 0) {
    // Subnormal half: value = mant_h * 2^-24, mant_h in [1, 1023].
    const scaled = a / 2 ** -24;
    if (!Number.isInteger(scaled) || scaled < 1 || scaled > 0x3ff) return null;
    half = sign | scaled;
  } else {
    if ((mant & 0x3ffffffffffn) !== 0n) return null; // needs > 10 mantissa bits
    half = sign | (e << 10) | Number(mant >> 42n);
  }
  return halfToDouble(half) === value ? half : null;
}

const f64buf = new DataView(new ArrayBuffer(8));
function doubleBits(value: number): bigint {
  f64buf.setFloat64(0, value);
  return f64buf.getBigUint64(0);
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

/** Strictly decode canonical CBOR (RFC 8949 §4.2). Throws on any
 *  non-canonical or non-pure-data input. */
export function decodeStrict(bytes: Uint8Array): CborValue {
  const [value, offset] = readValue(bytes, 0);
  if (offset !== bytes.length) throw new Error("cbor: trailing data");
  return value;
}

function need(b: Uint8Array, pos: number, n: number): void {
  if (pos + n > b.length) throw new Error("cbor: unexpected end of input");
}

/** Read an argument (additional info), enforcing shortest-form encoding. */
function readArg(b: Uint8Array, pos: number, info: number): [number, number] {
  if (info < 24) return [info, pos];
  if (info === 24) {
    need(b, pos, 1);
    const v = b[pos]!;
    if (v < 24) throw new Error("cbor: non-shortest argument");
    return [v, pos + 1];
  }
  if (info === 25) {
    need(b, pos, 2);
    const v = (b[pos]! << 8) | b[pos + 1]!;
    if (v < 0x100) throw new Error("cbor: non-shortest argument");
    return [v, pos + 2];
  }
  if (info === 26) {
    need(b, pos, 4);
    const v = ((b[pos]! << 24) | (b[pos + 1]! << 16) | (b[pos + 2]! << 8) | b[pos + 3]!) >>> 0;
    if (v < 0x10000) throw new Error("cbor: non-shortest argument");
    return [v, pos + 4];
  }
  if (info === 27) {
    need(b, pos, 8);
    const hi = ((b[pos]! << 24) | (b[pos + 1]! << 16) | (b[pos + 2]! << 8) | b[pos + 3]!) >>> 0;
    const lo = ((b[pos + 4]! << 24) | (b[pos + 5]! << 16) | (b[pos + 6]! << 8) | b[pos + 7]!) >>> 0;
    if (hi === 0) throw new Error("cbor: non-shortest argument");
    const v = hi * 0x100000000 + lo;
    // Beyond 2^53 a JS double cannot hold the integer exactly; rather than
    // diverge from the u64-exact reference ports, reject it.
    if (v > Number.MAX_SAFE_INTEGER) throw new Error("cbor: integer out of safe range");
    return [v, pos + 8];
  }
  throw new Error("cbor: reserved or indefinite length not allowed");
}

function readValue(b: Uint8Array, pos: number): [CborValue, number] {
  if (pos >= b.length) throw new Error("cbor: unexpected end of input");
  const ib = b[pos]!;
  pos++;
  const major = ib >> 5;
  const info = ib & 0x1f;
  switch (major) {
    case 0:
      return readArg(b, pos, info);
    case 1: {
      const [n, p] = readArg(b, pos, info);
      return [-1 - n, p];
    }
    case 2: {
      const [len, p] = readArg(b, pos, info);
      need(b, p, len);
      return [b.slice(p, p + len), p + len];
    }
    case 3: {
      const [len, p] = readArg(b, pos, info);
      need(b, p, len);
      return [utf8Decode.decode(b.subarray(p, p + len)), p + len];
    }
    case 4: {
      const [len, p] = readArg(b, pos, info);
      let cur = p;
      const arr: CborValue[] = [];
      for (let i = 0; i < len; i++) {
        const [v, pp] = readValue(b, cur);
        arr.push(v);
        cur = pp;
      }
      return [arr, cur];
    }
    case 5: {
      const [len, p] = readArg(b, pos, info);
      let cur = p;
      const m = new Map<number | string, CborValue>();
      let prevKey: Uint8Array | null = null;
      for (let i = 0; i < len; i++) {
        const keyStart = cur;
        const [k, p1] = readValue(b, cur);
        if (typeof k !== "number" && typeof k !== "string") {
          throw new Error("cbor: map key must be an integer or text string");
        }
        const keyBytes = b.subarray(keyStart, p1);
        if (prevKey !== null) {
          const cmp = compareBytes(prevKey, keyBytes);
          if (cmp === 0) throw new Error("cbor: duplicate map key");
          if (cmp > 0) throw new Error("cbor: map keys out of canonical order");
        }
        prevKey = keyBytes;
        const [v, p2] = readValue(b, p1);
        m.set(k, v);
        cur = p2;
      }
      return [m, cur];
    }
    case 6:
      throw new Error("cbor: tags are not supported (pure-data only)");
    default: {
      // major 7: simple values and floats
      if (info === 20) return [false, pos];
      if (info === 21) return [true, pos];
      if (info === 22) return [null, pos];
      if (info === 25) {
        need(b, pos, 2);
        return [readFloat(halfToDouble((b[pos]! << 8) | b[pos + 1]!), 2), pos + 2];
      }
      if (info === 26) {
        need(b, pos, 4);
        return [readFloat(new DataView(b.buffer, b.byteOffset + pos, 4).getFloat32(0), 4), pos + 4];
      }
      if (info === 27) {
        need(b, pos, 8);
        return [readFloat(new DataView(b.buffer, b.byteOffset + pos, 8).getFloat64(0), 8), pos + 8];
      }
      throw new Error("cbor: unsupported simple value");
    }
  }
}
