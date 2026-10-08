import type { BlueprintRef } from "../types.js";
import { missing, sourced, type Limitation, type LimitationsSourcePort, type Sourced } from "./ports.js";

/**
 * Parses the "known limitations" table of docs/NEEDS.md style files: `| # | title | detail | evidence |` rows whose first cell is a
 * number. Rows marked RESOLVED are not limitations any more and are skipped. Deterministic; pure.
 */
export function parseNeeds(text: string): Limitation[] {
  const out: Limitation[] = [];
  for (const line of text.split("\n")) {
    if (!line.startsWith("|")) continue;
    const cells = line
      .split(/(?<!\\)\|/)
      .slice(1, -1)
      .map((c) => c.trim());
    if (cells.length < 3 || !/^\d+$/.test(cells[0] as string)) continue;
    const detail = cells[2] ?? "";
    if (/^RESOLVED\b/i.test(detail)) continue;
    out.push({
      id: `NEEDS-${cells[0]}`,
      title: cells[1] as string,
      detail: detail === "" ? null : detail.length > 240 ? `${detail.slice(0, 239)}…` : detail,
      evidence: cells[3] === undefined || cells[3] === "" ? null : cells[3],
    });
  }
  return out;
}

/** The platform's known limitations as the repository records them (docs/NEEDS.md), read through a function so tests need no disk. */
export class NeedsLimitations implements LimitationsSourcePort {
  constructor(private readonly readText: () => string | undefined) {}
  list(_tenantId: string, _bp: BlueprintRef): Promise<Sourced<Limitation[]>> {
    void _tenantId;
    void _bp;
    let text: string | undefined;
    try {
      text = this.readText();
    } catch {
      text = undefined;
    }
    if (text === undefined) return Promise.resolve(missing("docs/NEEDS.md is not available to this deployment"));
    const items = parseNeeds(text);
    return Promise.resolve(
      items.length === 0 ? missing("docs/NEEDS.md lists no limitations") : sourced(items),
    );
  }
}
