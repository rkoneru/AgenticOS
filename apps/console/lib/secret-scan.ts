/** Scan built client assets for secrets (the patterns are shared with `scripts/scan-bundle.mjs`, the build gate). */
import { PATTERNS } from "./secret-patterns.mjs";

export interface Finding {
  file: string;
  rule: string;
  excerpt: string;
}

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
