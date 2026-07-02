# obsigil-ts

TypeScript implementation of the [obsigil](https://obsigil.org)
mandate-token format — a JWT-like credential split into a public
**manifest** and an encrypted **mandate**, each an authenticated,
deterministically-encrypted ciphertext (AES-SIV / AES-GCM-SIV) in
compact text. Built on
[`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers).

A pnpm workspace monorepo. The shared, policy-free primitives live
in `@obsigil/core`; each consumer is a thin policy layer on top.

## Packages

| Package | Role |
|---|---|
| [`@obsigil/core`](packages/obsigil-core) | Token grammar, strict b64url/hex codecs, deterministic AEAD, the single canonical CBOR serialization (the format sections, Token structure through Serialization, spec §4–§7). No policy. |
| [`@obsigil/client`](packages/obsigil-client) | Front-end client (keyless): `claims` reads the advisory manifest, `manifest` / `mandate` forward each half as a standalone token, `manifestPlaintext` yields the manifest's raw octets. Holds no mandate key. |
| [`@obsigil/server`](packages/obsigil-server) | Backend (keyed): `mint` and `clauses` (verify) under a secret key, enforcing the reserved fields (Reserved fields, spec §8); keys are hex by default (or raw bytes), and `generateKey` mints one (hex; `generateKeyBytes` for raw bytes); a diagnostic tier (`clausesUnchecked`, `mandatePlaintext`) reads without the policy value-checks; `issuedAt` derives the issue time from `tid`. |

Both consumers reuse `@obsigil/core`'s parser, codecs, and AEAD, so
the TS stack stays byte-compatible with the Rust reference per the
Conformance and test vectors section (spec §13).

The packages are ESM-only (`"type": "module"`) and target **Node ≥
20** — they use the global WebCrypto `crypto`, un-flagged only from
Node 20 (and available in browsers / edge runtimes). CBOR
application integers are limited to the JavaScript safe-integer
range (2^53−1); a value beyond it is rejected rather than silently
rounded (`exp` NumericDates are far below this in practice).

## Install

```sh
pnpm add @obsigil/server   # backend: mint and verify
pnpm add @obsigil/client   # front end: read manifest, forward mandate
```

`@obsigil/core` is pulled in transitively; install it directly only
to use the wire-level primitives on their own.

## Quickstart

```ts
import { generateKey, mint, clauses } from "@obsigil/server";
import { claims, authorizationHeader } from "@obsigil/client";

const key = generateKey(); // 128-char hex — store as a secret

// Backend: mint under the secret mandate key.
const token = mint({
  clauses: { role: "admin" },
  mandateKey: key,
  exp: Math.floor(Date.now() / 1000) + 300,
  manifest: { iss: "auth.example" },
});

// Front end: keyless advisory read, then forward the mandate.
const c = claims(token); // Claims | null — display only
const auth = authorizationHeader(token); // "Bearer .0…" | null

// Backend: verify — authenticate, then enforce the reserved fields.
const verified = clauses(token, { keys: key });
verified.role; // "admin"
```

## Status

Pre-1.0: the API may still change before 1.0. The wire format it
implements is pinned by the spec and the cross-language vectors.

## Conformance

The TS stack implements canonical CBOR (RFC 8949 §4.2) and the
validation rules of Reserved fields (spec §8) and Limits and
robustness (§16.10). The package suites cover round-trip, the
verification ladder, and the negative cases; a conformance suite
checks both directions against the shared, language-agnostic
[`obsigil-test-vectors`](https://gitlab.com/obsigil/obsigil-test-vectors):
the TS stack reproduces the Rust reference's tokens (AES-SIV /
AES-GCM-SIV, HKDF, b64/hex, canonical CBOR) byte-for-byte and
rejects every negative case.

## Development

Requires Node ≥ 20 and pnpm.

```sh
pnpm install
pnpm build      # tsc -b across the workspace
pnpm test       # vitest run
```

The conformance suites resolve `obsigil-test-vectors` from the
sibling checkout, overridable with `OBSIGIL_TEST_VECTORS`; they skip
if it is absent. Set `OBSIGIL_REQUIRE_VECTORS=1` (as CI does) to
turn a missing vectors checkout into a hard failure instead of a
silent skip.

The build emits Node-ESM-native output (`moduleResolution:
"NodeNext"`, explicit `.js` import specifiers), which bundlers also
consume directly. All `@noble` imports are isolated to
`packages/obsigil-core/src/aead.ts`.

## Spec

The normative format is the obsigil specification at
<https://obsigil.org>. Section references throughout the source lead
with the section's name (e.g. the Serialization section, spec §7) so
they survive spec renumbering; the appended number is a convenience,
not the anchor.

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
