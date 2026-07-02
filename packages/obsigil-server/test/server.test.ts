import { MANIFEST_KEY, encodeCanonical, seal } from "@obsigil/core";
import { describe, expect, it } from "vitest";
import {
  ObsigilError,
  clauses,
  clausesUnchecked,
  generateKey,
  generateKeyBytes,
  generateUuidV7,
  isUuidV7,
  issuedAt,
  mandatePlaintext,
  mint,
  uuidV7Time,
} from "../src/index";
import type { Reason } from "../src/index";
import { uuidToBytes } from "../src/uuid";

const KEY = new Uint8Array(64).fill(42);

describe("mint / clauses", () => {
  it("round-trips a full token", () => {
    const token = mint({
      clauses: { role: "admin" },
      mandateKey: KEY,
      exp: 4000000000,
      aud: ["api"],
      sub: "u42",
      manifest: { iss: "auth.example", claims: { theme: "dark" } },
    });
    const c = clauses(token, { keys: KEY, audience: "api", now: 1000000000 });
    expect(c.role).toBe("admin");
    expect(c.sub).toBe("u42");
    expect(c.exp).toBe(4000000000);
    expect(isUuidV7(c.tid)).toBe(true);
  });

  it("round-trips a float application clause (shortest float16)", () => {
    const token = mint({ clauses: { role: "viewer", score: 1.5 }, mandateKey: KEY, exp: 4000000000 });
    const c = clauses(token, { keys: KEY, now: 1000000000 });
    expect(c.role).toBe("viewer");
    expect(c.score).toBe(1.5);
  });

  it("normalizes the binary tid back to a UUIDv7 string", () => {
    const token = mint({ clauses: { role: "admin" }, mandateKey: KEY, exp: 4000000000 });
    const c = clauses(token, { keys: KEY, now: 1000000000 });
    expect(c.role).toBe("admin");
    expect(isUuidV7(c.tid)).toBe(true); // 16-byte binary tid -> canonical string
  });

  it("verifies the forwarded mandate-only form", () => {
    const token = mint({ clauses: {}, mandateKey: KEY, exp: 4000000000 });
    expect(token.startsWith(".")).toBe(true); // no manifest half
    expect(() => clauses(token, { keys: KEY, now: 1000000000 })).not.toThrow();
  });

  it("trial-decrypts across candidate keys", () => {
    const token = mint({ clauses: {}, mandateKey: KEY, exp: 4000000000 });
    const wrong = new Uint8Array(64).fill(7);
    expect(() => clauses(token, { keys: [wrong, KEY], now: 1000000000 })).not.toThrow();
  });

  it("rejects uniformly with internal reasons", () => {
    const token = mint({ clauses: {}, mandateKey: KEY, exp: 4000000000, aud: ["api"] });
    const reasons: Reason[] = [];
    const onReject = (r: Reason) => reasons.push(r);
    expect(() => clauses(token, { keys: KEY, audience: "api", now: 5000000000, onReject })).toThrow(ObsigilError);
    expect(() => clauses(token, { keys: KEY, audience: "other", now: 1000000000, onReject })).toThrow(ObsigilError);
    expect(() => clauses(token, { keys: KEY, now: 1000000000, onReject })).toThrow(ObsigilError);
    expect(() => clauses(token, { keys: new Uint8Array(64).fill(7), now: 1000000000, onReject })).toThrow(ObsigilError);
    expect(() => clauses("garbage", { keys: KEY, now: 1000000000, onReject })).toThrow(ObsigilError);
    expect(reasons).toEqual(["expired", "audience-mismatch", "audience-mismatch", "auth-failed", "malformed"]);
  });

  it("rejects the manifest key as a mandate key", () => {
    expect(() => mint({ clauses: {}, mandateKey: MANIFEST_KEY, exp: 4000000000 })).toThrow();
    const token = mint({ clauses: {}, mandateKey: KEY, exp: 4000000000 });
    expect(() => clauses(token, { keys: MANIFEST_KEY, now: 1000000000 })).toThrow();
  });

  it("generates a valid UUIDv7 and reads its issue time", () => {
    const tid = generateUuidV7(1_700_000_000_000);
    expect(isUuidV7(tid)).toBe(true);
    expect(uuidV7Time(tid)).toBe(1_700_000_000);
    expect(generateKey()).toMatch(/^[0-9a-f]{128}$/); // 128 lowercase hex digits (§6.2)
    expect(generateKeyBytes().length).toBe(64);
  });

  it("issuedAt derives the issue time from the verified tid", () => {
    const tid = generateUuidV7(1_700_000_000_000);
    const token = mint({ clauses: {}, mandateKey: KEY, exp: 4000000000, tid });
    const c = clauses(token, { keys: KEY, now: 1000000000 });
    expect(issuedAt(c)).toBe(1_700_000_000);
  });
});

describe("diagnostic tier: clausesUnchecked / mandatePlaintext", () => {
  const TID = "019ed29a-378d-72f0-b462-4929cd2bfcad";

  /** Seal hand-built canonical octets into a mandate-only token. */
  function craft(octets: Uint8Array): string {
    return `.0${Buffer.from(seal(octets, KEY, "0")).toString("base64url")}`;
  }

  it("clausesUnchecked accepts a bare key and a key list", () => {
    const token = mint({ clauses: { role: "admin" }, mandateKey: KEY, exp: 4000000000 });
    expect(clausesUnchecked(token, KEY).role).toBe("admin");
    expect(clausesUnchecked(token, [new Uint8Array(64).fill(7), KEY]).role).toBe("admin");
    // A full policy is accepted too (only the keys are consumed).
    expect(clausesUnchecked(token, { keys: KEY }).role).toBe("admin");
  });

  it("clausesUnchecked skips policy value-checks but still authenticates + decodes", () => {
    // tid is a UUIDv4 (not v7) and exp is already past — the full `clauses`
    // rejects both value checks; `clausesUnchecked` skips them but still
    // requires tid and exp to be structurally present (accessors stay total).
    const v4 = "019ed29a-378d-42f0-b462-4929cd2bfcad"; // version nibble 4
    const octets = encodeCanonical(
      new Map<number | string, unknown>([[-1, uuidToBytes(v4)], [-2, 1000], ["role", "admin"]]),
    );
    const token = craft(octets);
    expect(() => clauses(token, { keys: KEY, now: 1000000000 })).toThrow();
    const c = clausesUnchecked(token, KEY);
    expect(c.role).toBe("admin");
    expect(c.tid).toBe(v4); // normalized to its string, version unverified
    expect(c.exp).toBe(1000); // present, but expiry unchecked
  });

  it("clausesUnchecked requires tid and exp present (accessor totality)", () => {
    // Missing exp / tid: even the unchecked tier fails, so the returned Clauses
    // type is never a lie (matches the reference).
    const noExp = encodeCanonical(new Map<number | string, unknown>([[-1, uuidToBytes(TID)]]));
    expect(() => clausesUnchecked(craft(noExp), KEY)).toThrow(ObsigilError);
    const noTid = encodeCanonical(new Map<number | string, unknown>([[-2, 4000000000]]));
    expect(() => clausesUnchecked(craft(noTid), KEY)).toThrow(ObsigilError);
  });

  it("clausesUnchecked still rejects a wrong key and non-canonical CBOR", () => {
    const token = mint({ clauses: {}, mandateKey: KEY, exp: 4000000000 });
    expect(() => clausesUnchecked(token, new Uint8Array(64).fill(9))).toThrow(ObsigilError);
    // Trailing bytes after the map: non-canonical, rejected even unchecked.
    const bad = new Uint8Array([...encodeCanonical(new Map([[-2, 4000000000]])), 0x00]);
    expect(() => clausesUnchecked(craft(bad), KEY)).toThrow(ObsigilError);
  });

  it("mandatePlaintext returns the raw canonical octets, or throws", () => {
    const octets = encodeCanonical(
      new Map<number | string, unknown>([[-1, uuidToBytes(TID)], [-2, 4000000000]]),
    );
    const token = craft(octets);
    expect(mandatePlaintext(token, KEY)).toEqual(octets);
    expect(() => mandatePlaintext(token, new Uint8Array(64).fill(9))).toThrow(ObsigilError);
    expect(() => mandatePlaintext("garbage", KEY)).toThrow(ObsigilError);
  });
});
