// Cross-implementation conformance against obsigil-test-vectors (Conformance and test vectors, spec §13),
// from the server's side: reproduce each mandate half byte-for-byte (proving
// noble ⇄ RustCrypto agreement), verify each canonical-CBOR mandate, and
// reject every verify/parse negative — including the policy and crypto
// rejections the client could not test. Open-manifest negatives are the
// client's responsibility.
//
// Vector op -> API mapping (server side): `verify` -> clauses (the keyed
// verify), `parse` -> clauses too (a malformed token is rejected before any
// key use). `open-manifest` ops are the client's.

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  MANIFEST_KEY,
  decodeB64url,
  decodeHex,
  encodeB64url,
  encodeHalf,
  encodeHex,
  open,
  seal,
} from "@obsigil/core";
import type { Alg, Encoding, HalfFields } from "@obsigil/core";
import { describe, expect, it } from "vitest";
import { clauses } from "../src/index";
import { uuidToBytes } from "../src/uuid";

const RESERVED = new Set(["exp", "tid", "aud", "sub", "iss"]);

/** Rebuild a half's HalfFields from a vector's non-normative `fields` decode,
 *  exactly as mint does (tid string -> 16 bytes, reserved names by name,
 *  everything else into app). */
function halfFieldsFrom(fields: Record<string, unknown>): HalfFields {
  const app: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(fields)) if (!RESERVED.has(k)) app[k] = v;
  const out: HalfFields = { app };
  if (typeof fields.tid === "string") out.tid = uuidToBytes(fields.tid);
  if (fields.exp !== undefined) out.exp = fields.exp as number;
  if (fields.aud !== undefined) out.aud = fields.aud as string[];
  if (fields.sub !== undefined) out.sub = fields.sub as string;
  if (fields.iss !== undefined) out.iss = fields.iss as string;
  return out;
}

const VECTORS =
  process.env.OBSIGIL_TEST_VECTORS ?? resolve(process.cwd(), "../obsigil-test-vectors");
const haveVectors = existsSync(resolve(VECTORS, "test-vectors.jsonl"));

// Fail loudly (rather than skip to a green result) when vectors are required
// but missing — CI sets OBSIGIL_REQUIRE_VECTORS so a mislocated corpus can't
// masquerade as a passing conformance run (mirrors the reference).
if (process.env.OBSIGIL_REQUIRE_VECTORS && !haveVectors) {
  throw new Error(`OBSIGIL_REQUIRE_VECTORS is set but conformance vectors were not found at ${VECTORS}`);
}

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

describe.skipIf(!haveVectors)("server conformance vs obsigil-test-vectors", () => {
  it("encodeHalf reproduces every half's octets byte-for-byte from its fields", () => {
    let checked = 0;
    for (const v of lines("test-vectors.jsonl")) {
      for (const role of ["manifest", "mandate"] as const) {
        const half = v[role];
        if (!half) continue;
        const out = encodeHalf(halfFieldsFrom(half.fields));
        const got = [...out].map((b) => b.toString(16).padStart(2, "0")).join("");
        expect(got).toBe(half.octets); // canonical encoder is byte-identical
        checked++;
      }
    }
    expect(checked).toBeGreaterThan(0);
  });

  it("reproduces mandate halves and verifies the canonical-CBOR mandates", () => {
    for (const v of lines("test-vectors.jsonl")) {
      if (!v.mandate) continue;
      if (v.mandate.alg !== "0" && v.mandate.alg !== "1") continue;
      const enc = v.encoding as Encoding;
      const alg = v.mandate.alg as Alg;
      const octets = decodeHex(v.mandate.octets)!;
      const text = encodeText(seal(octets, MANDATE_TEST_KEY, alg), enc); // seal direction
      expect(open(decode(text, enc), MANDATE_TEST_KEY, alg)).toEqual(octets); // open direction

      // Verify the mandate; the 16-byte binary `tid` is normalized back to
      // its canonical string (the tid reserved field, spec §8.2).
      const aud = v.mandate.fields.aud as string[] | undefined;
      const c = clauses(v.token, { keys: MANDATE_TEST_KEY, now: 1000000000, audience: aud?.[0] });
      expect(c.exp).toBe(v.mandate.fields.exp);
      expect(c.tid).toBe(v.mandate.fields.tid);
    }
  });

  it("rejects every verify and parse negative (op -> clauses)", () => {
    const negatives = lines("negative-test-vectors.jsonl");
    // Prove the suite iterates the extended negative corpus, not skipping.
    expect(negatives.length).toBe(57);
    let checked = 0;
    let openManifest = 0;
    for (const v of negatives) {
      if (v.op === "open-manifest") {
        openManifest++; // the client's responsibility
        continue;
      }
      const keys = keyFor(v.key ?? "mandate");
      // A bounded verifier still rejects a vector pairing a large `leeway`
      // with a `now` far past `exp` (the limits-and-robustness rule of the Security Considerations, spec §16.10). The new negatives — a
      // disallowed CBOR map-key type (top-level and nested byte string),
      // invalid-UTF-8 text, and the out-of-range alg char — are rejected here.
      expect(() =>
        clauses(v.token, { keys, now: v.now, audience: v.audience, leewaySeconds: v.leeway }),
      ).toThrow();
      checked++;
    }
    expect(openManifest).toBe(5);
    expect(checked).toBe(52); // 57 negatives - 5 open-manifest
  });
});
