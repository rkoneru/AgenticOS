const MAX_REASON = 300;

/**
 * Audit reasons are written PHI-safe by the kernel (field names and limits, never values). This is defence in depth for text
 * that reaches an explanation: credential-shaped tokens are masked and the length is bounded.
 */
const SECRET_PATTERNS: readonly RegExp[] = [
  /\bsk-[A-Za-z0-9_-]{8,}/g,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi,
  /\baxk_[0-9a-f]{16}_[A-Za-z0-9_-]{20,}/g,
  /\baxr\.[A-Za-z0-9._-]{16,}/g,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
  /\b(?:password|secret|token|api[_-]?key)\s*[=:]\s*\S+/gi,
];

export function sanitizeText(text: string, max = MAX_REASON): string {
  let out = text.replace(/\p{Cc}+/gu, " ");
  for (const re of SECRET_PATTERNS) out = out.replace(re, "[redacted]");
  out = out.trim();
  return out.length > max ? `${out.slice(0, max - 1)}…` : out;
}
