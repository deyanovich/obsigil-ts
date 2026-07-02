// obsigil-core — policy-free primitives shared by obsigil-client and
// obsigil-server. Token grammar, strict text encodings, deterministic AEAD
// seal/open, and the single canonical CBOR serialization (the format
// sections, Token structure through Serialization, spec §4-§7).

export { parseToken } from "./token.js";
export type { ParsedToken, ParseResult, ParseError, TokenHalf } from "./token.js";

export { decodeB64url, encodeB64url, decodeHex, encodeHex } from "./encoding.js";

export { seal, open } from "./aead.js";

export { MANIFEST_KEY } from "./manifest-key.js";

export { CborFloat, decodeStrict, encodeCanonical } from "./serial/cbor.js";
export type { CborValue } from "./serial/cbor.js";

export { decodeHalf, decodeManifest, encodeHalf, RESERVED_KEYS, RESERVED_NAMES } from "./half.js";
export type { DecodedHalf, HalfFields } from "./half.js";

export { MIN_HALF_BYTES, MAX_DECODED_BYTES } from "./types.js";
export type { Alg, Encoding, NumericDate } from "./types.js";
