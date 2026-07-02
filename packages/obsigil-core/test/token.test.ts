import { describe, expect, it } from "vitest";
import { parseToken } from "../src/index";

describe("parseToken (Token structure, spec §4)", () => {
  it("parses a full b64 token", () => {
    const r = parseToken("abc0.0def");
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.token.encoding).toBe("b64");
    expect(r.token.separator).toBe(".");
    expect(r.token.manifest).toEqual({ algCode: "0", text: "abc" });
    expect(r.token.mandate).toEqual({ algCode: "0", text: "def" });
    expect(r.token.mandatePart).toBe("0def");
  });

  it("reads hex encoding from the `~` separator", () => {
    const r = parseToken("abc0~1def");
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.token.encoding).toBe("hex");
    expect(r.token.mandate).toEqual({ algCode: "1", text: "def" });
  });

  it("parses a manifest-only token", () => {
    const r = parseToken("abc0.");
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.token.manifest).toEqual({ algCode: "0", text: "abc" });
    expect(r.token.mandate).toBeNull();
    expect(r.token.mandatePart).toBe("");
  });

  it("parses a mandate-only (forwarded) token", () => {
    const r = parseToken(".0def");
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.token.manifest).toBeNull();
    expect(r.token.mandate).toEqual({ algCode: "0", text: "def" });
  });

  it.each([
    ["", "empty-token"],
    ["abc", "separator-count"],
    ["a.b.c", "separator-count"],
    [".", "both-absent"],
    ["0.", "degenerate-half"],
    [".0", "degenerate-half"],
    ["ab-.", "bad-alg-char"], // `-` is in the b64 alphabet but not an alg code
    ["abZ.", "bad-alg-char"], // uppercase is not a `0-9a-z` alg code
  ])("rejects %j with %s", (input, reason) => {
    const r = parseToken(input);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toBe(reason);
  });
});
