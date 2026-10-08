import { canonicalJson, hashOf, sha256Hex } from "../canonical.js";
import type { DocBody } from "./assemble.js";
import { renderMarkdown } from "./render.js";
import type { DocSealer } from "./seal.js";
import type { BlueprintRef } from "../types.js";

export const GENERATOR = "axis-compliance/1";

export interface DocMeta {
  document_id: string;
  tenant_id: string;
  blueprint: BlueprintRef & { content_hash: string | null };
  doc_version: number;
  generated_at: string;
  generated_by: string;
  generator: typeof GENERATOR;
  markdown_sha256: string;
}

export interface SealedDocument {
  body: DocBody;
  content_hash: string;
  meta: DocMeta;
  markdown: string;
  seal: { alg: DocSealer["alg"]; key_id: string; sig: string };
}

/** What the seal covers: the content hash of the JSON body and the metadata (which carries the hash of the Markdown). */
export const sealPayload = (content_hash: string, meta: DocMeta): string =>
  canonicalJson({ content_hash, meta });

export interface SealInput {
  body: DocBody;
  meta: Omit<DocMeta, "markdown_sha256" | "blueprint" | "generator">;
}

/** Builds and seals a document. Same inputs, same bytes. */
export function sealDocument(i: SealInput, sealer: DocSealer): SealedDocument {
  const content_hash = hashOf(i.body);
  const markdown = renderMarkdown(i.body, {
    document_id: i.meta.document_id,
    doc_version: i.meta.doc_version,
    generated_at: i.meta.generated_at,
    content_hash,
  });
  const meta: DocMeta = {
    ...i.meta,
    blueprint: i.body.blueprint,
    generator: GENERATOR,
    markdown_sha256: sha256Hex(markdown),
  };
  return {
    body: i.body,
    content_hash,
    meta,
    markdown,
    seal: { alg: sealer.alg, key_id: sealer.keyId, sig: sealer.sign(sealPayload(content_hash, meta)) },
  };
}

export type VerifyCheck = "content_hash" | "markdown" | "seal_key" | "seal_signature";

export interface Verification {
  ok: boolean;
  /** The checks that failed (empty when `ok`). */
  failed: VerifyCheck[];
}

/**
 * Recomputes everything a reader can recompute: the body hash, the Markdown (re-rendered from the body) and its hash, and the seal
 * under a trusted key. Any edit to the body, the Markdown, the metadata or the signature fails at least one check.
 */
export function verifyDocument(doc: SealedDocument, trusted: readonly DocSealer[]): Verification {
  const failed: VerifyCheck[] = [];
  let hash: string | null = null;
  try {
    hash = hashOf(doc.body);
  } catch {
    hash = null;
  }
  if (hash === null || hash !== doc.content_hash) failed.push("content_hash");
  let md: string | null = null;
  try {
    md = renderMarkdown(doc.body, {
      document_id: doc.meta.document_id,
      doc_version: doc.meta.doc_version,
      generated_at: doc.meta.generated_at,
      content_hash: doc.content_hash,
    });
  } catch {
    md = null;
  }
  if (md === null || md !== doc.markdown || sha256Hex(doc.markdown) !== doc.meta.markdown_sha256)
    failed.push("markdown");
  const key = trusted.find((k) => k.keyId === doc.seal.key_id && k.alg === doc.seal.alg);
  if (!key) failed.push("seal_key");
  else {
    let payload: string | null = null;
    try {
      payload = sealPayload(doc.content_hash, doc.meta);
    } catch {
      payload = null;
    }
    if (payload === null || !key.verify(payload, doc.seal.sig)) failed.push("seal_signature");
  }
  return { ok: failed.length === 0, failed };
}
