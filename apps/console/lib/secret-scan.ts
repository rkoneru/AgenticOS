/** Scan built client assets for secrets (used by `scripts/scan-bundle.mjs` and tested in isolation). */

export interface Finding {
  file: string;
  rule: string;
  excerpt: string;
}

const PATTERNS: Array<{ rule: string; re: RegExp }> = [
  { rule: "axis-api-key", re: /axk_[0-9a-f]{16}_[A-Za-z0-9_-]{20,}/ },
  { rule: "axis-scim-token", re: /axs_[0-9a-f]{16}_[A-Za-z0-9_-]{20,}/ },
  { rule: "anthropic-key", re: /sk-ant-[A-Za-z0-9_-]{20,}/ },
  { rule: "openai-style-key", re: /sk-[A-Za-z0-9]{32,}/ },
  { rule: "aws-access-key", re: /AKIA[0-9A-Z]{16}/ },
  { rule: "private-key", re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { rule: "bearer-literal", re: /Bearer\s+[A-Za-z0-9._-]{30,}/ },
];

export function scanText(file: string, text: string, sentinels: readonly string[] = []): Finding[] {
  const out: Finding[] = [];
  for (const { rule, re } of PATTERNS) {
    const m = re.exec(text);
    if (m) out.push({ file, rule, excerpt: `${m[0].slice(0, 6)}...` });
  }
  for (const s of sentinels) {
    if (s.length >= 6 && text.includes(s))
      out.push({ file, rule: "sentinel", excerpt: `${s.slice(0, 3)}...` });
  }
  return out;
}
