# @obsigil/server

Backend for [obsigil](https://obsigil.org) mandate tokens: **mint**
and **verify** under a secret mandate key, enforcing the reserved
fields. This package holds the secret key; the front end holds none
(see `@obsigil/client`).

## Install

```sh
pnpm add @obsigil/server
```

ESM-only; requires Node ≥ 20 (global WebCrypto `crypto`).

## Keys

A mandate key is 64 bytes, supplied as its **canonical hex form**
(128 lowercase hex digits) by default — the form read from a secret
environment variable — or as raw `Uint8Array` bytes.

```ts
import { generateKey, generateKeyBytes } from "@obsigil/server";

const keyHex = generateKey();        // 128-char hex, store as a secret
const keyBytes = generateKeyBytes(); // the raw-64-byte alternative
```

Every operation that takes a key accepts the hex string or raw
bytes. A malformed key (wrong length, uppercase/non-hex, the public
manifest key, or all-zero) throws a plain configuration `Error` —
never the uniform token rejection.

## Mint

```ts
import { mint } from "@obsigil/server";

const token = mint({
  clauses: { role: "admin" },      // opaque application data
  mandateKey: keyHex,              // hex (or a Uint8Array)
  exp: 4_000_000_000,              // required NumericDate (integer seconds)
  aud: ["api"],                    // optional intended verifiers
  sub: "u42",                      // optional subject
  manifest: { iss: "auth.example", claims: { theme: "dark" } }, // optional public half
});
```

`tid` defaults to a fresh UUIDv7; algorithm defaults to AES-SIV
(`"0"`) and encoding to base64url. `exp` must be an integer.

## Verify

```ts
import { clauses } from "@obsigil/server";

const c = clauses(token, {
  keys: keyHex,            // one key or an array (trial decryption); hex or bytes
  audience: "api",         // checked against a present `aud` (constant-time)
  leewaySeconds: 30,       // clock-skew allowance, clamped to 60 s
  // now: 1_700_000_000,   // pin the clock (tests); omit to read the system clock
  onReject: (r) => log(r), // granular cause for internal logging only
});
c.role; // "admin"
```

`clauses` authenticates the mandate under a candidate key, then
enforces policy: `exp` not past, `aud` membership, `tid` a
well-formed UUIDv7, reserved-field types. **Every** rejection
collapses to a single opaque `ObsigilError` — the granular `Reason`
is delivered to `onReject` for internal logging only, never to the
bearer (the uniform-failure rule of the Security Considerations,
§16.6).

## Reserved accessors and the diagnostic tier

Verified `clauses` surface the reserved fields by name (`exp`,
`tid`, `sub`, `iss`, `aud`); `issuedAt(clauses)` derives the issue
time from the UUIDv7 `tid`.

Below `clauses`, two backend-internal diagnostic reads skip the
policy value-checks but still authenticate (they never expose
unauthenticated bytes) and must stay non-bearer-facing:

- **`clausesUnchecked(token, keys)`** — authenticate and canonically
  decode, but skip the `exp`/`aud`/`tid`-version checks. Still
  rejects a wrong key, non-canonical CBOR, an unknown negative key,
  or a wrong-typed reserved field, and still requires `tid` and
  `exp` present so the accessors stay total.
- **`mandatePlaintext(token, keys)`** — authenticate and return the
  raw decrypted CBOR octets, with no decode.

## Trust model

The mandate is authoritative; the manifest is not (this package
verifies only the mandate). All rejections are uniform and opaque
to the bearer (§16.6). Transport tokens over a confidential,
authenticated channel and keep `exp` short (the bearer-credential
rule, §16.9).

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
