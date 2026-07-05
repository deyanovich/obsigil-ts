CHANGELOG
=========

All notable changes to the obsigil TypeScript packages (`@obsigil/core`,
`@obsigil/server`, `@obsigil/client`) are documented in this file. The
three are versioned in lockstep.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
but note that pre-1.0 releases may not adhere strictly to all
guidelines.


[Unreleased]
------------


[1.0.0] - 2026-07-05
--------------------

First stable release, implementing obsigil spec v1.0. No code or
wire-format change from 0.1.0; existing tokens are unaffected.


[0.1.0] - 2026-07-01
--------------------

First public release of the obsigil TypeScript implementation: a
pnpm-workspace monorepo of three ESM packages built on `@noble/ciphers`
and `@noble/hashes`.

### Added

- `@obsigil/core` — policy-free wire primitives: token grammar, strict
  b64url/hex codecs, deterministic AES-SIV / AES-GCM-SIV, and the single
  canonical CBOR serialization (spec §4–§7).
- `@obsigil/server` — the keyed backend: `mint`, `clauses` (verify) with
  uniform opaque failure, the diagnostic tier (`clausesUnchecked`,
  `mandatePlaintext`), reserved-field accessors, and hex-by-default keys
  (`generateKey` / `generateKeyBytes`; a hex string or raw bytes are both
  accepted wherever a key is taken).
- `@obsigil/client` — the keyless front end: `claims`, `manifest`,
  `mandate`, `manifestPlaintext`, `authorizationHeader`.

Wire-conformant against the shared, language-agnostic
`obsigil-test-vectors` (every positive and negative vector, both
algorithms and encodings), byte-compatible with the Rust reference.
