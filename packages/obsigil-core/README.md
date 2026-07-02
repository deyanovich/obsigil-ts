# @obsigil/core

Policy-free obsigil primitives shared by `@obsigil/client` and
`@obsigil/server`. This package knows the *format* (the format
sections, Token structure through Serialization, spec §4–§7); it
makes no trust or enforcement decisions — those belong to the
consumers.

This is the **low-level wire surface**. The everyday API is
`@obsigil/client` (keyless front end) and `@obsigil/server` (keyed
backend) — thin policy layers over these primitives. Usually pulled
in transitively; install directly (`pnpm add @obsigil/core`) only to
work at the wire level. ESM-only, Node ≥ 20. Pre-1.0: the primitive
surface may still shift before 1.0.

## Usage

```ts
import {
  parseToken,
  decodeB64url,
  decodeHex,
  open,
  decodeManifest,
  MANIFEST_KEY,
} from "@obsigil/core";

// A keyless manifest read built from primitives — what
// @obsigil/client's `claims` does, minus its policy guards:
const parsed = parseToken(token); // structural split only
if (parsed.ok && parsed.token.manifest) {
  const { algCode, text } = parsed.token.manifest;
  const decode =
    parsed.token.encoding === "b64" ? decodeB64url : decodeHex;
  const sealed = decode(text); // strict: null on non-canonical text
  const plain = sealed && open(sealed, MANIFEST_KEY, algCode);
  const half = plain && decodeManifest(plain); // canonical CBOR only
  half?.iss; // advisory issuer, if every step held
}
```

Every decoder in the chain fails soft (`null`), never throws, and
accepts only the canonical form — a caller folds any `null` into one
uniform rejection (the uniform-failure rule of the Security
Considerations, spec §16.6).

## What's here

- **Token grammar** (`parseToken`) — split a token on its single
  separator, read each present half's algorithm code, derive the
  text encoding. Purely structural: no decoding, no decryption, no
  registry check (Token structure, spec §4).
- **Text encodings** (`decodeB64url` / `encodeB64url` / `decodeHex`
  / `encodeHex`) — strict, canonical URL-safe base64 (no padding)
  and lowercase hex. Decoders return `null` on any non-canonical
  input — padding, whitespace, out-of-alphabet, non-zero trailing
  bits, bad length (Token structure, spec §4).
- **AEAD** (`seal` / `open`) — deterministic AES-SIV (code `0`) and
  AES-GCM-SIV (code `1`) over a 64-byte master, with the key
  derivation and output layout the spec pins (the Algorithm
  registry, spec §6). `open` never throws; it returns `null` on
  auth failure or an unsupported code.
- **Canonical CBOR** (`encodeCanonical` / `decodeStrict`) — the
  single serialization (Serialization, spec §7). `encodeCanonical`
  emits the RFC 8949 §4.2 core deterministic encoding (definite
  lengths, shortest-form ints / lengths / floats, byte-sorted map
  keys); `decodeStrict` rejects any non-canonical input, so a
  decoded value re-encodes to the same bytes.
- **Half model** (`encodeHalf` / `decodeHalf`) — a token half's
  field set: reserved fields at negative integer keys
  (`RESERVED_KEYS`: tid −1, exp −2, aud −3, sub −4, iss −5),
  application data at non-negative integer / text keys. `decodeHalf`
  classifies the sign-split namespace, type-checks the reserved
  fields, and fails closed on an unrecognized negative key
  (Reserved fields, spec §8).

All cryptographic dependencies (`@noble/ciphers`, `@noble/hashes`)
are isolated to `src/aead.ts`.

## Determinism

Sealing takes no nonce: the same plaintext under the same key, code,
and encoding always yields the same bytes (the deterministic-sealing
rule of the Security Considerations §16.4; Conformance and test
vectors §13). The library seals the exact canonical CBOR octets it
is given and normalizes nothing inside the seal.

## License

Licensed under either of

- Apache License, Version 2.0
  ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as
above, without any additional terms or conditions.
