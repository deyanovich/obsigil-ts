// Token grammar: split a token into its halves and read each present
// half's algorithm code (Token structure, spec §4). This layer is purely structural — it
// does not decode the ciphertext text, decrypt, or check an algorithm
// code against the registry. Those happen later, so a code the parser
// accepts grammatically (any `0`-`9`/`a`-`z`) may still be unsupported.
//
//     token         = manifest-part SEP mandate-part
//     manifest-part = "" | ( manifest ALG )   ; ciphertext, then its code
//     mandate-part  = "" | ( ALG mandate )    ; code, then ciphertext
//     SEP           = "." | "~"               ; "." => b64, "~" => hex
//     ALG           = one char 0-9 / a-z
//
// Exactly one separator is present in a well-formed token. The encoding
// alphabets exclude both separator characters, so the split is
// unambiguous before any decoding.

import type { Encoding } from "./types.js";

/** A present half: its algorithm code char and its still-text ciphertext. */
export interface TokenHalf {
  /** The raw algorithm-code character, as it appears in the token. Not yet
   *  checked against the registry (the Algorithm registry, spec §6). */
  readonly algCode: string;
  /** The half's ciphertext, still in its text encoding (b64 or hex). */
  readonly text: string;
}

/** A structurally well-formed token. Either half may be absent. */
export interface ParsedToken {
  readonly encoding: Encoding;
  readonly separator: "." | "~";
  readonly manifest: TokenHalf | null;
  readonly mandate: TokenHalf | null;
  /** The post-separator part exactly as received (`ALG mandate`, or "" when
   *  the mandate is absent). The forwardable mandate-only token is
   *  `separator + mandatePart` (forwarding the mandate, Audiences, spec §9). */
  readonly mandatePart: string;
}

/** Why a token failed structural parsing. Diagnostic only — callers facing
 *  a bearer MUST collapse every cause into one uniform failure (the
 *  uniform-failure rule of the Security Considerations, spec §16.6). */
export type ParseError =
  | "empty-token"
  | "separator-count"
  | "degenerate-half"
  | "both-absent"
  | "bad-alg-char";

export type ParseResult =
  | { readonly ok: true; readonly token: ParsedToken }
  | { readonly ok: false; readonly reason: ParseError };

/** ALG = %x30-39 | %x61-7A : one char `0`-`9` or `a`-`z` (Token structure, spec §4). */
function isAlgChar(c: string): boolean {
  const code = c.charCodeAt(0);
  return (code >= 0x30 && code <= 0x39) || (code >= 0x61 && code <= 0x7a);
}

/** Parse a token into its halves. Rejects: empty input; zero, or more than
 *  one, separator; a separator outside {`.`, `~`} (impossible here, since
 *  those are the only chars counted); a present half that is a lone
 *  algorithm code with empty ciphertext; both halves absent (a bare
 *  separator); or a present half whose algorithm-code position holds a
 *  non-grammar character. */
export function parseToken(input: string): ParseResult {
  if (input.length === 0) return { ok: false, reason: "empty-token" };

  let sepIndex = -1;
  let sepChar = "";
  let sepCount = 0;
  for (let i = 0; i < input.length; i++) {
    const ch = input[i]!;
    if (ch === "." || ch === "~") {
      sepCount++;
      sepIndex = i;
      sepChar = ch;
    }
  }
  if (sepCount !== 1) return { ok: false, reason: "separator-count" };

  const encoding: Encoding = sepChar === "." ? "b64" : "hex";
  const before = input.slice(0, sepIndex);
  const after = input.slice(sepIndex + 1);

  // Manifest part: ciphertext then its algorithm code (the LAST char).
  let manifest: TokenHalf | null = null;
  if (before.length > 0) {
    if (before.length < 2) return { ok: false, reason: "degenerate-half" };
    const algCode = before[before.length - 1]!;
    if (!isAlgChar(algCode)) return { ok: false, reason: "bad-alg-char" };
    manifest = { algCode, text: before.slice(0, -1) };
  }

  // Mandate part: algorithm code (the FIRST char) then ciphertext.
  let mandate: TokenHalf | null = null;
  if (after.length > 0) {
    if (after.length < 2) return { ok: false, reason: "degenerate-half" };
    const algCode = after[0]!;
    if (!isAlgChar(algCode)) return { ok: false, reason: "bad-alg-char" };
    mandate = { algCode, text: after.slice(1) };
  }

  if (manifest === null && mandate === null) {
    return { ok: false, reason: "both-absent" };
  }

  return {
    ok: true,
    token: {
      encoding,
      separator: sepChar as "." | "~",
      manifest,
      mandate,
      mandatePart: after,
    },
  };
}
