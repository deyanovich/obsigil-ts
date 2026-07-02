// Native verify-level tests for the canonical-CBOR model (the
// limits-and-robustness rule of the Security Considerations §16.10; Reserved fields §8):
// the resource bounds (decoded-size cap, leeway clamp) and the deterministic
// reserved/application key precedence — exercised without the cross-language
// vectors.

import { encodeCanonical, seal } from "@obsigil/core";
import { describe, expect, it } from "vitest";
import { clauses, mint } from "../src/index";
import { uuidToBytes } from "../src/uuid";

const KEY = new Uint8Array(64).fill(42);
const TID = "019ed29a-378d-72f0-b462-4929cd2bfcad";

/** Seal hand-built canonical-CBOR octets into a mandate-only token, so the
 *  verifier's own strict decode and reserved checks run on crafted input. */
function craftMandate(octets: Uint8Array): string {
  return ".0" + Buffer.from(seal(octets, KEY, "0")).toString("base64url");
}

describe("verify resource bounds (the limits-and-robustness rule of the Security Considerations, spec §16.10)", () => {
  it("rejects an oversize half under the default cap but admits it under a raised one", () => {
    const token = mint({ clauses: { blob: "x".repeat(100 * 1024) }, mandateKey: KEY, exp: 4000000000 });
    expect(() => clauses(token, { keys: KEY, now: 1000000000 })).toThrow();
    expect(() => clauses(token, { keys: KEY, now: 1000000000, maxDecodedBytes: 1 << 20 })).not.toThrow();
  });

  it("clamps an excessive leeway instead of resurrecting a long-expired exp", () => {
    const token = mint({ clauses: {}, mandateKey: KEY, exp: 1000 });
    expect(() => clauses(token, { keys: KEY, now: 2_000_000_000, leewaySeconds: 9_999_999_999 })).toThrow();
    // Within the 60 s cap, leeway applies (exp 1000 + 60 > now 1030).
    expect(() => clauses(token, { keys: KEY, now: 1030, leewaySeconds: 60 })).not.toThrow();
  });
});

describe("reserved/application key precedence (Reserved fields, spec §8)", () => {
  it("lets the reserved tid win deterministically over an application text key", () => {
    const octets = encodeCanonical(
      new Map<number | string, unknown>([
        [-1, uuidToBytes(TID)], // reserved tid, a valid UUIDv7
        [-2, 4000000000],
        ["tid", "not-a-uuid"], // application text key "tid"
      ]),
    );
    const token = craftMandate(octets);
    for (let i = 0; i < 50; i++) {
      const c = clauses(token, { keys: KEY, now: 1000000000 });
      expect(c.tid).toBe(TID); // the reserved field, normalized to a string
    }
  });
});
