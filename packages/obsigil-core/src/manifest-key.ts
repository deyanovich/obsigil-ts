// The public manifest key (the published manifest key, Construction, spec §5.2): a 64-byte master key pinned by the
// specification. Anyone can open AND forge a manifest with it — it is an
// encoding wrapper, not a security layer. Shared by the client (which opens
// manifests) and the server (which seals them); every conformant
// implementation MUST use this exact value.

import { decodeHex } from "./encoding.js";

const MANIFEST_KEY_HEX =
  "381284633d02ea5f35df8596b5cc4218310060468e8b465455a415174ea6e966" +
  "a9f48eec4ba446ddfc8b78587895356f45a75a1ab7419454dd9f7aa8a95dbdd5";

const decoded = decodeHex(MANIFEST_KEY_HEX);
if (decoded === null || decoded.length !== 64) {
  throw new Error("obsigil-core: baked-in manifest key is invalid");
}

/** The 64-byte public manifest master key (the published manifest key, Construction, spec §5.2). */
export const MANIFEST_KEY: Uint8Array = decoded;
