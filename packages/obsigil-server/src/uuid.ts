// UUIDv7 (RFC 9562) for the mandate's required `tid` (the tid reserved field, spec §8.2): a 48-bit
// big-endian Unix-millisecond timestamp, version/variant bits, and CSPRNG
// randomness. The timestamp field doubles as the mandate's issue time.

const HEX = "0123456789abcdef";

function bytesToUuid(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < 16; i++) {
    s += HEX[b[i]! >> 4]! + HEX[b[i]! & 0x0f]!;
    if (i === 3 || i === 5 || i === 7 || i === 9) s += "-";
  }
  return s;
}

/** Generate a UUIDv7 with the given Unix-millisecond time (default now). */
export function generateUuidV7(nowMs: number = Date.now()): string {
  const b = new Uint8Array(16);
  const ms = BigInt(Math.floor(nowMs));
  b[0] = Number((ms >> 40n) & 0xffn);
  b[1] = Number((ms >> 32n) & 0xffn);
  b[2] = Number((ms >> 24n) & 0xffn);
  b[3] = Number((ms >> 16n) & 0xffn);
  b[4] = Number((ms >> 8n) & 0xffn);
  b[5] = Number(ms & 0xffn);
  crypto.getRandomValues(b.subarray(6));
  b[6] = (b[6]! & 0x0f) | 0x70; // version 7
  b[8] = (b[8]! & 0x3f) | 0x80; // variant 0b10
  return bytesToUuid(b);
}

const UUID_V7_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/** Whether `value` is a well-formed UUIDv7 string (the tid reserved field, spec §8.2). */
export function isUuidV7(value: unknown): value is string {
  return typeof value === "string" && UUID_V7_RE.test(value);
}

/** The issue time (NumericDate, seconds) embedded in a UUIDv7's 48-bit
 *  millisecond field, floored to whole seconds (the tid reserved field, spec §8.2). */
export function uuidV7Time(tid: string): number {
  const ms = Number.parseInt(tid.replace(/-/g, "").slice(0, 12), 16);
  return Math.floor(ms / 1000);
}

/** The 16 raw bytes of a UUID string — the binary `tid` form CBOR carries
 *  (the tid reserved field, spec §8.2). */
export function uuidToBytes(uuid: string): Uint8Array {
  const hex = uuid.replace(/-/g, "");
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

/** The canonical UUID string from its 16 raw bytes. */
export function uuidFromBytes(bytes: Uint8Array): string {
  return bytesToUuid(bytes);
}
