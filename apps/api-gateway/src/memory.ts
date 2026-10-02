import { PortConflict, type BlueprintStore, type BlueprintVersionDto, type Page } from "./ports.js";

const semverKey = (v: string): string =>
  v
    .split(/[.+-]/)
    .slice(0, 3)
    .map((n) => n.padStart(10, "0"))
    .join(".");

/** In-memory blueprint store (immutable versions, per tenant). The registry component (Phase 7 B) provides the durable one. */
export class MemoryBlueprintStore implements BlueprintStore {
  private readonly byTenant = new Map<string, Map<string, BlueprintVersionDto>>();

  async publish(tenantId: string, v: BlueprintVersionDto): Promise<BlueprintVersionDto> {
    const t = this.byTenant.get(tenantId) ?? new Map<string, BlueprintVersionDto>();
    const key = `${v.name}@${v.version}`;
    if (t.has(key))
      throw new PortConflict(`${key} already exists (published versions are immutable)`);
    t.set(key, structuredClone(v));
    this.byTenant.set(tenantId, t);
    return structuredClone(v);
  }

  async list(
    tenantId: string,
    q: { limit: number; after?: string },
  ): Promise<Page<BlueprintVersionDto>> {
    const all = [...(this.byTenant.get(tenantId)?.values() ?? [])]
      .map((v) => ({ key: `${v.name}|${semverKey(v.version)}|${v.version}`, v }))
      .sort((a, b) => (a.key < b.key ? -1 : 1))
      .filter((x) => q.after === undefined || x.key > q.after);
    const slice = all.slice(0, q.limit);
    return {
      items: slice.map((x) => structuredClone(x.v)),
      next: all.length > q.limit ? (slice[slice.length - 1] as { key: string }).key : undefined,
    };
  }

  async get(
    tenantId: string,
    name: string,
    version: string,
  ): Promise<BlueprintVersionDto | undefined> {
    const v = this.byTenant.get(tenantId)?.get(`${name}@${version}`);
    return v && structuredClone(v);
  }
}
