import { MANIFEST_KEY, encodeHex } from "@obsigil/core";
import { describe, expect, it } from "vitest";
import { ObsigilError, clauses, generateKey, generateKeyBytes, mint } from "../src/index";

// Key format (spec §6.2): hex is the default key representation, raw bytes the
// alternative, and a malformed key is a configuration error — never the
// uniform token rejection.

const KEY_BYTES = new Uint8Array(64).fill(0x2a);
const KEY_HEX = encodeHex(KEY_BYTES); // 128 lowercase hex digits

describe("key format (§6.2)", () => {
  it("generateKey is 128 lowercase hex; generateKeyBytes is 64 bytes", () => {
    expect(generateKey()).toMatch(/^[0-9a-f]{128}$/);
    expect(generateKeyBytes().length).toBe(64);
  });

  it("a hex key and the same raw-byte key seal identically", () => {
    const tid = "019ed29a-378d-72f0-b462-4929cd2bfcad"; // pinned so the plaintext is fixed
    const tokHex = mint({ clauses: {}, mandateKey: KEY_HEX, exp: 4000000000, tid });
    const tokBytes = mint({ clauses: {}, mandateKey: KEY_BYTES, exp: 4000000000, tid });
    expect(tokHex).toBe(tokBytes);
  });

  it("a token minted under either form verifies under the other", () => {
    const tokHex = mint({ clauses: { role: "admin" }, mandateKey: KEY_HEX, exp: 4000000000 });
    expect(clauses(tokHex, { keys: KEY_BYTES, now: 1 }).role).toBe("admin");
    const tokBytes = mint({ clauses: { role: "admin" }, mandateKey: KEY_BYTES, exp: 4000000000 });
    expect(clauses(tokBytes, { keys: KEY_HEX, now: 1 }).role).toBe("admin");
  });

  it("uppercase hex is a config error, not the uniform ObsigilError", () => {
    expect(() => mint({ clauses: {}, mandateKey: KEY_HEX.toUpperCase(), exp: 1 })).toThrow(
      /128 lowercase hexadecimal/,
    );
    const tok = mint({ clauses: {}, mandateKey: KEY_HEX, exp: 4000000000 });
    let err: unknown;
    try {
      clauses(tok, { keys: KEY_HEX.toUpperCase(), now: 1 });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(Error);
    expect(err).not.toBeInstanceOf(ObsigilError);
  });

  it("rejects wrong-length and non-hex keys", () => {
    for (const bad of ["2a".repeat(10), "zz".repeat(64), "abc", "2a".repeat(65)]) {
      expect(() => mint({ clauses: {}, mandateKey: bad, exp: 1 })).toThrow();
    }
  });

  it("rejects the public manifest key as a mandate key", () => {
    expect(() => mint({ clauses: {}, mandateKey: encodeHex(MANIFEST_KEY), exp: 1 })).toThrow();
  });

  it("rejects an all-zero mandate key (bytes and hex), as a config error", () => {
    let err: unknown;
    try {
      mint({ clauses: {}, mandateKey: new Uint8Array(64), exp: 1 });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(Error);
    expect(err).not.toBeInstanceOf(ObsigilError);
    expect(() => mint({ clauses: {}, mandateKey: "00".repeat(64), exp: 1 })).toThrow();
  });

  it("rejects a non-integer exp at mint", () => {
    const key = "2a".repeat(64);
    expect(() => mint({ clauses: {}, mandateKey: key, exp: 1.5 })).toThrow(/exp/);
    expect(() => mint({ clauses: {}, mandateKey: key, exp: 4000000000 })).not.toThrow();
  });
});
