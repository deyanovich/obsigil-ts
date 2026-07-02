// Native tests for the canonical-CBOR codec and the half model (Serialization
// §7, Reserved fields §8), independent of the cross-language vectors: byte-identical canonical
// encoding, strict-decode rejection of every non-canonical form, the
// sign-split reserved namespace, reserved-field typing, and shortest-float
// interop.

import { describe, expect, it } from "vitest";
import {
  CborFloat,
  decodeHalf,
  decodeManifest,
  decodeStrict,
  encodeCanonical,
  encodeHalf,
} from "../src/index";

function bytes(hex: string): Uint8Array {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return b;
}
function hex(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

const TID = bytes("019ed29a378d72f0b4624929cd2bfcad");

describe("canonical encode is byte-identical to the reference octets", () => {
  it("a simple mandate (tid, exp)", () => {
    const out = encodeHalf({ tid: TID, exp: 4000000000, app: {} });
    expect(hex(out)).toBe("a22050019ed29a378d72f0b4624929cd2bfcad211aee6b2800");
  });

  it("a rich mandate (tid, exp, aud, sub, app role) — keys byte-sorted", () => {
    const out = encodeHalf({ tid: TID, exp: 4000000000, aud: ["api", "billing"], sub: "u42", app: { role: "admin" } });
    expect(hex(out)).toBe(
      "a52050019ed29a378d72f0b4624929cd2bfcad211aee6b28002282636170696762696c6c696e67236375343264726f6c656561646d696e",
    );
  });

  it("a float application clause as shortest float16 (1.5 -> f9 3e00)", () => {
    const out = encodeHalf({ tid: TID, exp: 4000000000, app: { score: 1.5 } });
    expect(hex(out)).toBe("a32050019ed29a378d72f0b4624929cd2bfcad211aee6b28006573636f7265f93e00");
  });

  it("a manifest (iss only)", () => {
    expect(hex(encodeHalf({ iss: "auth.example", app: {} }))).toBe("a1246c617574682e6578616d706c65");
  });
});

describe("decodeStrict rejects non-canonical CBOR", () => {
  it("a duplicate map key", () => {
    expect(() => decodeStrict(bytes("a2" + "2100" + "2100"))).toThrow();
  });
  it("keys out of canonical order (-2 before -1)", () => {
    // a2 21 00 (key -2) then 20 00 (key -1): -1 sorts before -2, so unsorted.
    expect(() => decodeStrict(bytes("a2" + "2100" + "2000"))).toThrow();
  });
  it("a non-shortest integer (0 in a 1-byte argument)", () => {
    expect(() => decodeStrict(bytes("1800"))).toThrow();
  });
  it("a non-shortest length header (1-byte text length 5)", () => {
    // 78 05 'hello' — text length 5 should be inline (0x65), not 0x78 05.
    expect(() => decodeStrict(bytes("780568656c6c6f"))).toThrow();
  });
  it("an indefinite-length map", () => {
    expect(() => decodeStrict(bytes("bf2100ff"))).toThrow();
  });
  it("trailing bytes after the value", () => {
    expect(() => decodeStrict(bytes("a000"))).toThrow();
  });
  it("a non-shortest float (f64 for an f16-representable 1.5)", () => {
    expect(() => decodeStrict(bytes("fb3ff8000000000000"))).toThrow();
  });
  it("a CBOR tag", () => {
    expect(() => decodeStrict(bytes("c000"))).toThrow();
  });
});

describe("decodeStrict accepts and distinguishes floats", () => {
  it("reads a shortest float16 as a CborFloat", () => {
    const v = decodeStrict(bytes("f93e00"));
    expect(v).toBeInstanceOf(CborFloat);
    expect((v as CborFloat).value).toBe(1.5);
  });
  it("round-trips a float at each shortest width (f16 / f32 / f64)", () => {
    expect(hex(encodeCanonical(new CborFloat(1.5)))).toBe("f93e00"); // f16
    const f32 = Math.fround(0.2);
    expect(hex(encodeCanonical(new CborFloat(f32)))).toBe("fa3e4ccccd"); // needs f32
    expect((decodeStrict(bytes("fa3e4ccccd")) as CborFloat).value).toBe(f32);
    expect(hex(encodeCanonical(0.1))).toBe("fb3fb999999999999a"); // needs f64
  });
  it("rejects a non-shortest float32 (f32 for an f16-representable 1.5)", () => {
    expect(() => decodeStrict(bytes("fa3fc00000"))).toThrow();
  });
});

describe("decodeStrict rejects NaN and unrepresentable integers", () => {
  it("a half-precision NaN (any payload)", () => {
    for (const h of ["f97e00", "f97c01", "f97d00", "f9fe00", "f97fff"]) {
      expect(() => decodeStrict(bytes(h))).toThrow();
    }
  });
  it("a float32 / float64 NaN", () => {
    expect(() => decodeStrict(bytes("fa7fc00000"))).toThrow();
    expect(() => decodeStrict(bytes("fb7ff8000000000000"))).toThrow();
  });
  it("an 8-byte integer beyond the JS safe-integer range", () => {
    // 1b 0020000000000001 = 2^53 + 1, not exactly representable as a double.
    expect(() => decodeStrict(bytes("1b0020000000000001"))).toThrow();
  });
  it("the encoder also refuses NaN and unsafe integers", () => {
    expect(() => encodeCanonical(new CborFloat(NaN))).toThrow();
    expect(() => encodeCanonical(2 ** 60)).toThrow();
  });
});

describe("decodeHalf classifies the sign-split namespace (Reserved fields, spec §8)", () => {
  it("accepts a shortest-float16 application clause and unwraps it", () => {
    const half = decodeHalf(encodeHalf({ tid: TID, exp: 4000000000, app: { score: 1.5 } }));
    expect(half).not.toBeNull();
    expect(half!.score).toBe(1.5); // unwrapped to a plain number
    expect(half!.exp).toBe(4000000000);
  });

  it("fails closed on an unrecognized negative key", () => {
    // a3 20 50<tid> 21 1aee6b2800 28 01  (key -9, value 1)
    const m = bytes("a32050019ed29a378d72f0b4624929cd2bfcad211aee6b28002801");
    expect(decodeHalf(m)).toBeNull();
  });

  it("rejects exp encoded as a CBOR float", () => {
    // key -2 -> float 4e9 instead of an integer
    const m = encodeCanonical(new Map<number | string, unknown>([[-1, TID], [-2, new CborFloat(4e9)]]));
    expect(decodeHalf(m)).toBeNull();
  });

  it("rejects a tid that is not a 16-byte byte string", () => {
    const m = encodeCanonical(new Map<number | string, unknown>([[-1, TID.slice(0, 8)], [-2, 4000000000]]));
    expect(decodeHalf(m)).toBeNull();
  });

  it("rejects an aud with a non-text element", () => {
    const m = encodeCanonical(new Map<number | string, unknown>([[-1, TID], [-2, 4000000000], [-3, [1]]]));
    expect(decodeHalf(m)).toBeNull();
  });

  it("rejects an empty aud array", () => {
    const m = encodeCanonical(new Map<number | string, unknown>([[-1, TID], [-2, 4000000000], [-3, []]]));
    expect(decodeHalf(m)).toBeNull();
  });

  it("lets the reserved field win over a same-named application key", () => {
    // reserved tid (-1) coexists with an application text key "tid".
    const m = encodeCanonical(
      new Map<number | string, unknown>([[-1, TID], [-2, 4000000000], ["tid", "not-a-uuid"]]),
    );
    const half = decodeHalf(m);
    expect(half).not.toBeNull();
    expect(half!.tid).toBeInstanceOf(Uint8Array); // the reserved 16-byte form, not the string
    expect(hex(half!.tid as Uint8Array)).toBe("019ed29a378d72f0b4624929cd2bfcad");
  });

  it("never lets an application text key named like a reserved field reach a reserved slot", () => {
    // The sign IS the namespace: an app text key "exp"/"tid" (no negative key)
    // is opaque data and must not satisfy or shadow the reserved field.
    const m = encodeCanonical(
      new Map<number | string, unknown>([["exp", 4000000000], ["tid", "019ed29a-378d-72f0-b462-4929cd2bfcad"]]),
    );
    const half = decodeHalf(m);
    expect(half).not.toBeNull();
    expect(half!.exp).toBeUndefined(); // not sourced from the app text key
    expect(half!.tid).toBeUndefined();
  });
});

describe("decodeManifest restricts the reserved namespace (the iss reserved field, spec §8.6)", () => {
  it("accepts a manifest with only iss (and an advisory exp)", () => {
    const m = encodeCanonical(new Map<number | string, unknown>([[-5, "auth.example"], [-2, 4100000000]]));
    const half = decodeManifest(m);
    expect(half).not.toBeNull();
    expect(half!.iss).toBe("auth.example");
    expect(half!.exp).toBe(4100000000);
  });

  it("rejects a manifest carrying a mandate-only reserved key (tid/aud/sub)", () => {
    for (const extra of [[-1, TID], [-3, ["api"]], [-4, "u42"]] as Array<[number, unknown]>) {
      const m = encodeCanonical(new Map<number | string, unknown>([[-5, "auth.example"], extra]));
      expect(decodeManifest(m)).toBeNull();
    }
  });

  it("does not accept an application text key 'iss' as the manifest issuer", () => {
    const m = encodeCanonical(new Map<number | string, unknown>([["iss", "auth.example"]]));
    const half = decodeManifest(m);
    expect(half).not.toBeNull();
    expect(half!.iss).toBeUndefined(); // only the reserved -5 key supplies iss
  });
});
