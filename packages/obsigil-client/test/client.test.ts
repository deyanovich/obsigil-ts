import { describe, expect, it } from "vitest";
import { encodeB64url, encodeHalf, encodeHex, seal } from "@obsigil/core";
import type { Alg, Encoding } from "@obsigil/core";
import {
  MANIFEST_KEY,
  authorizationHeader,
  claims,
  mandate,
  manifest,
  manifestPlaintext,
} from "../src/index";

/** Seal a manifest's canonical-CBOR map under the public manifest key and
 *  text-encode it — the manifest ciphertext as it appears in a token. */
function cborManifest(
  fields: { iss?: string; app?: Record<string, unknown> },
  alg: Alg,
  encoding: Encoding,
): string {
  const sealed = seal(encodeHalf(fields), MANIFEST_KEY, alg);
  return encoding === "b64" ? encodeB64url(sealed) : encodeHex(sealed);
}

/** Build a token from a manifest ciphertext and a raw (opaque) mandate. */
function assemble(opts: {
  manifest?: { text: string; alg: Alg };
  mandate?: { text: string; alg: string };
  encoding?: Encoding;
}): string {
  const sep = (opts.encoding ?? "b64") === "b64" ? "." : "~";
  const left = opts.manifest ? opts.manifest.text + opts.manifest.alg : "";
  const right = opts.mandate ? opts.mandate.alg + opts.mandate.text : "";
  return left + sep + right;
}

describe("claims (the published manifest key §5.2, the iss reserved field §8.6)", () => {
  it("opens a manifest sealed under AES-SIV (code 0)", () => {
    const text = cborManifest({ iss: "auth.example", app: { role: "viewer" } }, "0", "b64");
    const token = assemble({ manifest: { text, alg: "0" } });
    expect(claims(token)).toEqual({ iss: "auth.example", role: "viewer" });
  });

  it("opens a manifest sealed under AES-GCM-SIV (code 1, via HKDF)", () => {
    const text = cborManifest({ iss: "auth.example" }, "1", "b64");
    const token = assemble({ manifest: { text, alg: "1" } });
    expect(claims(token)).toEqual({ iss: "auth.example" });
  });

  it("opens a hex-encoded manifest", () => {
    const text = cborManifest({ iss: "auth.example" }, "0", "hex");
    const token = assemble({ manifest: { text, alg: "0" }, encoding: "hex" });
    expect(claims(token)).toEqual({ iss: "auth.example" });
  });

  it("opens the manifest of a full token, ignoring the mandate", () => {
    const text = cborManifest({ iss: "auth.example" }, "0", "b64");
    const token = assemble({
      manifest: { text, alg: "0" },
      mandate: { text: "opaqueMandateCiphertext", alg: "0" },
    });
    expect(claims(token)).toEqual({ iss: "auth.example" });
  });

  it("returns null for a manifest missing its required iss", () => {
    const text = cborManifest({ app: { role: "viewer" } }, "0", "b64");
    const token = assemble({ manifest: { text, alg: "0" } });
    expect(claims(token)).toBeNull();
  });

  it("returns null for a forged manifest carrying a mandate-only reserved key", () => {
    // A manifest with aud (-3) is not a valid manifest (the iss reserved field, spec §8.6): reject it
    // rather than display its iss.
    const sealed = seal(encodeHalf({ iss: "auth.example", aud: ["api"] }), MANIFEST_KEY, "0");
    const token = assemble({ manifest: { text: encodeB64url(sealed), alg: "0" } });
    expect(claims(token)).toBeNull();
  });

  it("does not accept an application text key 'iss' as the required issuer", () => {
    const sealed = seal(encodeHalf({ app: { iss: "auth.example" } }), MANIFEST_KEY, "0");
    const token = assemble({ manifest: { text: encodeB64url(sealed), alg: "0" } });
    expect(claims(token)).toBeNull();
  });

  it("returns null for a mandate-only token (no manifest)", () => {
    const token = assemble({ mandate: { text: "opaque", alg: "0" } });
    expect(claims(token)).toBeNull();
  });

  it("returns null when the manifest ciphertext is tampered", () => {
    const text = cborManifest({ iss: "auth.example" }, "0", "b64");
    // Flip one character of the ciphertext -> authentication must fail.
    const repl = text[5] === "A" ? "B" : "A";
    const bad = text.slice(0, 5) + repl + text.slice(6);
    const token = assemble({ manifest: { text: bad, alg: "0" } });
    expect(claims(token)).toBeNull();
  });

  it("returns null for a malformed token", () => {
    expect(claims("not a token")).toBeNull();
  });
});

describe("manifest / manifestPlaintext (Token structure §4, the iss reserved field §8.6)", () => {
  it("extracts the manifest as a standalone manifest-only token", () => {
    const text = cborManifest({ iss: "auth.example" }, "0", "b64");
    const token = assemble({
      manifest: { text, alg: "0" },
      mandate: { text: "MANDATE", alg: "0" },
    });
    // ciphertext + alg code + separator — the manifest half on its own.
    expect(manifest(token)).toBe(`${text}0.`);
    // The extracted manifest-only token still opens to the same claims.
    expect(claims(manifest(token)!)).toEqual({ iss: "auth.example" });
  });

  it("preserves the hex separator for the standalone manifest", () => {
    const text = cborManifest({ iss: "auth.example" }, "0", "hex");
    const token = assemble({ manifest: { text, alg: "0" }, encoding: "hex" });
    expect(manifest(token)).toBe(`${text}0~`);
  });

  it("returns null when there is no manifest half", () => {
    const token = assemble({ mandate: { text: "MANDATE", alg: "0" } });
    expect(manifest(token)).toBeNull();
    expect(manifest("no-separator")).toBeNull();
  });

  it("manifestPlaintext yields the raw canonical-CBOR octets", () => {
    const fields = { iss: "auth.example", app: { role: "viewer" } };
    const text = cborManifest(fields, "0", "b64");
    const token = assemble({ manifest: { text, alg: "0" } });
    expect(manifestPlaintext(token)).toEqual(encodeHalf(fields));
  });

  it("manifestPlaintext returns null for no manifest / auth failure", () => {
    expect(manifestPlaintext(assemble({ mandate: { text: "x", alg: "0" } }))).toBeNull();
    const text = cborManifest({ iss: "auth.example" }, "0", "b64");
    const repl = text[5] === "A" ? "B" : "A";
    const bad = text.slice(0, 5) + repl + text.slice(6);
    expect(manifestPlaintext(assemble({ manifest: { text: bad, alg: "0" } }))).toBeNull();
  });
});

describe("mandate / authorizationHeader (Audiences, spec §9)", () => {
  it("extracts the manifest-absent .0mandate form from a full token", () => {
    const text = cborManifest({ iss: "auth.example" }, "0", "b64");
    const token = assemble({
      manifest: { text, alg: "0" },
      mandate: { text: "MANDATE", alg: "0" },
    });
    expect(mandate(token)).toBe(".0MANDATE");
  });

  it("forwards a mandate whose algorithm the client cannot open", () => {
    // Code 1 (or any valid code) is forwarded verbatim — never decrypted.
    const token = assemble({ mandate: { text: "MANDATE", alg: "1" } });
    expect(mandate(token)).toBe(".1MANDATE");
  });

  it("preserves the hex separator", () => {
    const token = assemble({
      mandate: { text: "abcd", alg: "0" },
      encoding: "hex",
    });
    expect(mandate(token)).toBe("~0abcd");
  });

  it("returns null for a manifest-only token", () => {
    const text = cborManifest({ iss: "auth.example" }, "0", "b64");
    const token = assemble({ manifest: { text, alg: "0" } });
    expect(mandate(token)).toBeNull();
  });

  it("returns null for a malformed token", () => {
    expect(mandate("no-separator")).toBeNull();
    expect(mandate("two.sep.arators")).toBeNull();
  });

  it("builds an Authorization header value, default scheme Bearer", () => {
    const token = assemble({ mandate: { text: "MANDATE", alg: "0" } });
    expect(authorizationHeader(token)).toBe("Bearer .0MANDATE");
    expect(authorizationHeader(token, "DPoP")).toBe("DPoP .0MANDATE");
    expect(authorizationHeader(token, "")).toBe(".0MANDATE");
    expect(authorizationHeader(".")).toBeNull();
  });
});
