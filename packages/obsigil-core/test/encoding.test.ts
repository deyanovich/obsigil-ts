import { describe, expect, it } from "vitest";
import {
  decodeB64url,
  decodeHex,
  encodeB64url,
  encodeHex,
} from "../src/index";

describe("b64url (Token structure, spec §4)", () => {
  it("round-trips every length class", () => {
    for (let n = 0; n <= 8; n++) {
      const bytes = new Uint8Array(n);
      for (let i = 0; i < n; i++) bytes[i] = (i * 37 + 11) & 0xff;
      const text = encodeB64url(bytes);
      expect(text).not.toMatch(/[=.~]/); // no padding, no separators
      expect(decodeB64url(text)).toEqual(bytes);
    }
  });

  it("accepts canonical zero-trailing-bits forms", () => {
    expect(decodeB64url("AA")).toEqual(new Uint8Array([0])); // 2 chars -> 1 byte
    expect(decodeB64url("AAA")).toEqual(new Uint8Array([0, 0])); // 3 chars -> 2 bytes
  });

  it("rejects impossible 1-mod-4 length", () => {
    expect(decodeB64url("AAAAA")).toBeNull();
  });

  it("rejects `=` padding", () => {
    expect(decodeB64url("AA==")).toBeNull();
  });

  it("rejects non-zero trailing bits", () => {
    expect(decodeB64url("AB")).toBeNull(); // 2-char group, low 4 bits set
    expect(decodeB64url("AAB")).toBeNull(); // 3-char group, low 2 bits set
  });

  it("rejects out-of-alphabet and whitespace", () => {
    expect(decodeB64url("A*BC")).toBeNull();
    expect(decodeB64url("AA AA")).toBeNull();
  });
});

describe("hex (Token structure, spec §4)", () => {
  it("round-trips", () => {
    const bytes = new Uint8Array([0x00, 0x0f, 0xa9, 0xff, 0x10]);
    expect(encodeHex(bytes)).toBe("000fa9ff10");
    expect(decodeHex("000fa9ff10")).toEqual(bytes);
  });

  it("rejects odd length", () => {
    expect(decodeHex("abc")).toBeNull();
  });

  it("rejects uppercase (canonical is lowercase)", () => {
    expect(decodeHex("AB")).toBeNull();
  });

  it("rejects non-hex characters", () => {
    expect(decodeHex("zz")).toBeNull();
  });
});
