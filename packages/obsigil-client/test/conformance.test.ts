// Cross-implementation conformance against the language-agnostic
// obsigil-test-vectors (Conformance and test vectors, spec §13). The positives prove this TypeScript
// implementation (on @noble) reproduces, byte-for-byte, the tokens the
// Rust reference (on RustCrypto) generated — across AES-SIV, AES-GCM-SIV,
// HKDF, b64url, and hex.
//
// The vectors live in the sibling obsigil-test-vectors repo; point at a
// checkout with OBSIGIL_TEST_VECTORS, else the sibling path is used. If
// absent, the suite skips. `verify`-op negatives are the obsigil-server's
// responsibility — the client has no mandate key.
//
// Vector op -> API mapping (client side): `parse` -> parseToken,
// `open-manifest` -> claims (the keyless manifest read). `verify` ops are
// the server's.

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  decodeB64url,
  decodeHex,
  encodeB64url,
  encodeHex,
  open,
  parseToken,
  seal,
} from "@obsigil/core";
import type { Alg, Encoding } from "@obsigil/core";
import { MANIFEST_KEY, claims } from "../src/index";

const VECTORS =
  process.env.OBSIGIL_TEST_VECTORS ?? resolve(process.cwd(), "../obsigil-test-vectors");
const haveVectors = existsSync(resolve(VECTORS, "test-vectors.jsonl"));

// Fail loudly (rather than skip to a green result) when vectors are required
// but missing — CI sets OBSIGIL_REQUIRE_VECTORS so a mislocated corpus can't
// masquerade as a passing conformance run (mirrors the reference).
if (process.env.OBSIGIL_REQUIRE_VECTORS && !haveVectors) {
  throw new Error(`OBSIGIL_REQUIRE_VECTORS is set but conformance vectors were not found at ${VECTORS}`);
}

// The published test mandate key (see the vectors' README).
const MANDATE_TEST_KEY = decodeHex(
  "a341adc813cfa493412cda5900fa4ec83f20a6cdea4fe5c759f7ccdb7ffbec51" +
    "e01d2ce90c592909adb2ac1cad771790353f439ac86e9b113a17f7c57f0684b0",
)!;

function keyFor(role: string): Uint8Array {
  if (role === "manifest") return MANIFEST_KEY;
  if (role === "mandate") return MANDATE_TEST_KEY;
  return decodeHex(role.toLowerCase())!;
}

function decode(text: string, enc: Encoding): Uint8Array {
  const bytes = enc === "b64" ? decodeB64url(text) : decodeHex(text);
  if (bytes === null) throw new Error("decode failed");
  return bytes;
}

function encodeText(bytes: Uint8Array, enc: Encoding): string {
  return enc === "b64" ? encodeB64url(bytes) : encodeHex(bytes);
}

// biome-ignore lint/suspicious/noExplicitAny: vector lines are loose JSON
function lines(name: string): any[] {
  return readFileSync(resolve(VECTORS, name), "utf8")
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l));
}

describe.skipIf(!haveVectors)("conformance vs obsigil-test-vectors", () => {
  it("reproduces every positive bidirectionally (rs ⇄ ts byte-identical)", () => {
    const vectors = lines("test-vectors.jsonl");
    expect(vectors.length).toBeGreaterThan(0);
    for (const v of vectors) {
      const enc = v.encoding as Encoding;
      const sep = enc === "b64" ? "." : "~";
      let left = "";
      let right = "";
      for (const role of ["manifest", "mandate"] as const) {
        const half = v[role];
        if (!half) continue;
        const alg = half.alg as Alg;
        const key = keyFor(role);
        const octets = decodeHex(half.octets)!;
        const text = encodeText(seal(octets, key, alg), enc); // seal direction
        expect(open(decode(text, enc), key, alg)).toEqual(octets); // open direction
        if (role === "manifest") left = text + half.alg;
        else right = half.alg + text;
      }
      expect(left + sep + right).toBe(v.token);
    }
  });

  it("opens every manifest's canonical-CBOR claims", () => {
    for (const v of lines("test-vectors.jsonl")) {
      if (!v.manifest) continue;
      // The client opens code 0 (AES-SIV) and code 1 (AES-GCM-SIV) alike.
      const c = claims(v.token);
      expect(c).not.toBeNull();
      expect(c!.iss).toBe(v.manifest.fields.iss);
    }
  });

  it("rejects parse and open-manifest negatives (op -> parseToken / claims)", () => {
    const negatives = lines("negative-test-vectors.jsonl");
    // Prove the suite is iterating the extended negative corpus, not skipping.
    expect(negatives.length).toBe(57);
    let parsed = 0;
    let openManifest = 0;
    for (const v of negatives) {
      if (v.op === "parse") {
        // Includes the out-of-range algorithm-code char negative (op parse).
        expect(parseToken(v.token).ok).toBe(false);
        parsed++;
      } else if (v.op === "open-manifest") {
        // The wrong-half-reserved-key manifest yields no claims via `claims`.
        expect(claims(v.token)).toBeNull();
        openManifest++;
      }
    }
    expect(parsed).toBe(7);
    expect(openManifest).toBe(5);
  });
});
