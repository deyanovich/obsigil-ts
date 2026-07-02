# @obsigil/client

Front-end client for [obsigil](https://obsigil.org) mandate tokens.
A front end does two things, and holds **no mandate key**:

1. **Read the manifest claims** for display — keyless, advisory.
2. **Forward the mandate** to the backend for enforcement.

## Install

```sh
pnpm add @obsigil/client
```

ESM-only; requires Node ≥ 20 (or a browser / edge runtime with
global WebCrypto).

## API

```ts
import {
  claims,
  manifest,
  manifestPlaintext,
  mandate,
  authorizationHeader,
  MANIFEST_KEY,
} from "@obsigil/client";

// 1. Read the manifest claims (keyless, advisory — never authoritative; the
//    manifest-is-non-authoritative rule of the Security Considerations, §16.7)
const c = claims(token); // Claims | null
if (c) renderUserChrome(c.iss);

// 2. Send the mandate to the backend (the manifest-absent form; forwarding
//    the mandate, Audiences, §9)
const auth = authorizationHeader(token); // "Bearer .0mandate" | null
if (auth) fetch("/api", { headers: { Authorization: auth } });
else reauthenticate();
```

- **`claims(token): Claims | null`** — decrypts the manifest with
  the public `MANIFEST_KEY` under algorithm code `0` (AES-SIV) or
  `1` (AES-GCM-SIV) and strictly decodes its canonical CBOR map
  (Serialization, spec §7). Returns `null` — "display nothing" — on
  anything untrustworthy: no manifest, malformed token, bad
  encoding, an oversized half, auth failure, unsupported algorithm,
  non-canonical CBOR, or a manifest missing its required `iss` (the
  iss reserved field, spec §8.6). Never throws, never an oracle.
- **`manifest(token): string \| null`** — the encoded manifest half
  on its own, as the manifest-only token form `"<manifest>0."` (the
  mirror of `mandate`). Pure string work; no key.
- **`manifestPlaintext(token): Uint8Array \| null`** — the manifest
  half's raw canonical-CBOR octets, decrypted keyless under
  `MANIFEST_KEY` (the byte-level mirror of `claims`). Advisory
  only.
- **`mandate(token): string \| null`** — the manifest-absent
  `.0mandate` token to hand the backend (forwarding the mandate,
  Audiences, spec §9). Pure string work; no key, no decryption;
  forwards even a mandate the client cannot open.
- **`authorizationHeader(token, scheme?): string \| null`** —
  `mandate()` prefixed with a scheme (default `Bearer`; the
  bearer-credential rule of the Security Considerations, spec
  §16.9). Pass `""` for the bare token.
- **`MANIFEST_KEY: Uint8Array`** — the 64-byte public manifest key
  pinned by the spec (the published manifest key, Construction,
  §5.2), baked in.

## Trust model

Manifest claims are **advisory only** and attacker-forgeable: the
manifest is sealed keyless (the published manifest key §5.2; the
manifest-is-non-authoritative rule of the Security Considerations
§16.7). Never make an access-control decision from them.
Authoritative subject/role/issuer come from the backend after it
verifies the mandate. A manifest `exp`, if present, is a refresh
hint — never enforcement (the exp reserved field, spec §8.3).

## Bundle

Supporting both algorithm codes pulls in noble's `aessiv` and
`gcmsiv` + HKDF-SHA-256, the b64url/hex decoders, and the strict
canonical-CBOR decoder. No minting, no mandate decryption.

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
