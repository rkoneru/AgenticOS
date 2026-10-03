import {
  compareVersionStrings,
  maxSatisfying,
  parseRange,
  forbidden,
  invalid,
  notFound,
} from "@axis/registry";
import { guarded, iso, mutate, requireRole, requireStaff, type Ctx } from "./ctx.js";
import { CATALOG, PLATFORM, tenantScope } from "./docstore.js";
import {
  MARKETPLACE_SERVICE,
  type InstallRecord,
  type ListingRecord,
  type PublisherRecord,
  type ReviewRecord,
  type StaffPrincipal,
  type TenantPrincipal,
} from "./types.js";

/** Control, line-separator, zero-width and bidi-control characters: none belongs in a title or a summary (terminals interpret them). */
const NOT_PLAIN_TEXT =
  // eslint-disable-next-line no-control-regex
  /[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u206f\ufeff]/;

export interface CatalogEntry {
  namespace: string;
  name: string;
  title: string;
  summary: string;
  categories: string[];
  latest: { version: string; contentHash: string; riskLevel: string; maxSeverity: string } | null;
  versions: string[];
}

const toEntry = (l: ListingRecord): CatalogEntry => {
  const live = l.approved.filter((a) => !l.blockedVersions.includes(a.version));
  const best = live
    .map((a) => a.version)
    .sort(compareVersionStrings)
    .at(-1);
  const a = live.find((x) => x.version === best);
  return {
    namespace: l.namespace,
    name: l.name,
    title: l.title,
    summary: l.summary,
    categories: l.categories,
    latest: a
      ? {
          version: a.version,
          contentHash: a.contentHash,
          riskLevel: a.riskLevel,
          maxSeverity: a.maxSeverity,
        }
      : null,
    versions: live.map((x) => x.version),
  };
};

export class ListingService {
  constructor(private readonly c: Ctx) {}

  async create(
    p: TenantPrincipal,
    input: {
      namespace: string;
      name: string;
      title: string;
      summary: string;
      categories?: string[];
    },
  ): Promise<ListingRecord> {
    requireRole(p, "publish");
    const pub = await this.c.docs.get<PublisherRecord>(
      tenantScope(p.tenantId),
      p.tenantId,
      "publishers",
      "self",
    );
    if (pub?.data.state !== "verified")
      throw forbidden("only verified publishers can create listings");
    for (const [k, v, max] of [
      ["title", input.title, 100],
      ["summary", input.summary, 500],
    ] as const)
      if (typeof v !== "string" || v.trim().length < 3 || v.length > max)
        throw invalid(`${k} must be 3-${max} characters`);
      else if (NOT_PLAIN_TEXT.test(v))
        throw invalid(`${k} must be plain text (no control or bidi characters)`);
    const cats = input.categories ?? [];
    if (
      !Array.isArray(cats) ||
      cats.length > 5 ||
      cats.some((x) => typeof x !== "string" || !/^[a-z][a-z0-9-]{1,30}$/.test(x))
    )
      throw invalid("categories: up to 5 lowercase slugs");
    const owned = (await this.c.registry.listNamespaces(p)).some(
      (n) => n.namespace === input.namespace,
    );
    if (!owned) throw forbidden("not your namespace");
    const versions = await this.c.registry.listVersions(
      { tenantId: p.tenantId },
      input.namespace,
      input.name,
    );
    if (versions.length === 0) throw notFound("no such blueprint in the registry");
    const approved = (
      await this.c.docs.find<ReviewRecord>(tenantScope(p.tenantId), "reviews", {
        state: "approved",
        namespace: input.namespace,
        name: input.name,
      })
    ).map((d) => d.data);
    const rec: ListingRecord = {
      namespace: input.namespace,
      name: input.name,
      publisherTenantId: p.tenantId,
      title: input.title.trim(),
      summary: input.summary.trim(),
      categories: cats,
      status: approved.length ? "listed" : "draft",
      approved: approved.map((r) => ({
        version: r.version,
        contentHash: r.approvedHash as string,
        riskLevel: r.riskLevel,
        maxSeverity: r.maxSeverity,
        approvedAt: r.decidedAt as string,
      })),
      blockedVersions: [],
      createdAt: iso(this.c.now()),
      takedownReason: null,
    };
    return mutate(
      this.c,
      p.tenantId,
      { type: "human", id: p.subject },
      "marketplace.listing.create",
      { listing: `${input.namespace}/${input.name}` },
      async () => {
        await guarded(
          () =>
            this.c.docs.insert(
              tenantScope(p.tenantId),
              p.tenantId,
              "listings",
              `${input.namespace}/${input.name}`,
              rec,
            ),
          "listing",
        );
        for (const a of approved)
          await this.c.registry.setVersionPublic(
            MARKETPLACE_SERVICE,
            input.namespace,
            input.name,
            a.version,
          );
        return rec;
      },
    );
  }

  /** Public catalog: NO tenant credential. Only listed listings, minus blocked versions. */
  async catalog(q: { text?: string; category?: string } = {}): Promise<CatalogEntry[]> {
    const rows = await this.c.docs.find<ListingRecord>(CATALOG, "listings", { status: "listed" });
    const text = q.text?.toLowerCase();
    return rows
      .map((d) => toEntry(d.data))
      .filter((e) => e.latest !== null)
      .filter((e) =>
        text
          ? `${e.namespace}/${e.name} ${e.title} ${e.summary}`.toLowerCase().includes(text)
          : true,
      )
      .filter((e) => (q.category ? e.categories.includes(q.category) : true));
  }

  async entry(namespace: string, name: string): Promise<CatalogEntry> {
    const rows = await this.c.docs.find<ListingRecord>(CATALOG, "listings", {
      status: "listed",
      namespace,
      name,
    });
    const l = rows[0];
    const e = l ? toEntry(l.data) : undefined;
    if (!e || e.latest === null) throw notFound("listing not found");
    return e;
  }

  /** The listing as the install flow sees it (status listed). Throws when delisted or unknown. */
  async listed(namespace: string, name: string): Promise<ListingRecord> {
    const rows = await this.c.docs.find<ListingRecord>(CATALOG, "listings", {
      status: "listed",
      namespace,
      name,
    });
    const l = rows[0];
    if (!l) throw notFound("listing not found or not available");
    return l.data;
  }

  /** Highest APPROVED, unblocked version satisfying `range` (exact version or a range), with the hash it was approved at. */
  async installable(
    namespace: string,
    name: string,
    range: string,
  ): Promise<{ version: string; contentHash: string; listing: ListingRecord }> {
    const l = await this.listed(namespace, name);
    const live = l.approved.filter((a) => !l.blockedVersions.includes(a.version));
    const best = maxSatisfying(
      live.map((a) => a.version),
      parseRange(range),
    );
    if (best === undefined) throw notFound("no approved version satisfies the range");
    return {
      version: best,
      contentHash: live.find((a) => a.version === best)!.contentHash,
      listing: l,
    };
  }

  // ------------------------------------------------------------------ moderation
  /**
   * Immediate delist + block: the listing (or one version) stops being installable the moment this returns; the registry versions are
   * yanked by the platform; existing installs are FLAGGED (still running, visible to their admin), never silently removed.
   */
  async takedown(
    m: StaffPrincipal,
    input: { namespace: string; name: string; version?: string; reason: string },
  ): Promise<{ flagged: number }> {
    requireStaff(m, "moderator");
    if (
      typeof input.reason !== "string" ||
      input.reason.trim().length < 10 ||
      input.reason.length > 500
    )
      throw invalid("a reason of 10-500 characters is required");
    const key = `${input.namespace}/${input.name}`;
    const found = await this.c.docs.find<ListingRecord>(PLATFORM, "listings", {
      namespace: input.namespace,
      name: input.name,
    });
    const cur = found[0];
    if (!cur) throw notFound("listing not found");
    const tenantId = cur.tenantId;
    if (input.version !== undefined && !cur.data.approved.some((a) => a.version === input.version))
      throw notFound("version is not listed");
    return mutate(
      this.c,
      tenantId,
      { type: "human", id: m.subject },
      "marketplace.moderation.takedown",
      { key, version: input.version ?? "*" },
      async () => {
        const next: ListingRecord =
          input.version === undefined
            ? { ...cur.data, status: "taken_down", takedownReason: input.reason }
            : {
                ...cur.data,
                blockedVersions: [...new Set([...cur.data.blockedVersions, input.version])],
                takedownReason: input.reason,
              };
        await guarded(
          () => this.c.docs.update(PLATFORM, tenantId, "listings", key, cur.rev, next),
          "listing",
        );
        await this.c.docs.insert(PLATFORM, tenantId, "takedowns", `td-${this.c.newId()}`, {
          namespace: input.namespace,
          name: input.name,
          version: input.version ?? null,
          reason: input.reason,
          by: m.subject,
          at: iso(this.c.now()),
        });
        const versions =
          input.version === undefined ? cur.data.approved.map((a) => a.version) : [input.version];
        for (const v of versions)
          await this.c.registry.platformYank(
            MARKETPLACE_SERVICE,
            input.namespace,
            input.name,
            v,
            `takedown: ${input.reason}`.slice(0, 500),
          );
        // flag existing installs, in every tenant
        const installs = await this.c.docs.find<InstallRecord>(PLATFORM, "installs", {
          namespace: input.namespace,
          name: input.name,
          state: "active",
        });
        let flagged = 0;
        for (const i of installs) {
          if (input.version !== undefined && i.data.version !== input.version) continue;
          await guarded(
            () =>
              this.c.docs.update(PLATFORM, i.tenantId, "installs", i.key, i.rev, {
                ...i.data,
                state: "flagged",
                flagReason: input.reason,
              }),
            "install",
          );
          await this.c.audit.record({
            tenantId: i.tenantId,
            actor: { type: "human", id: m.subject },
            action: "marketplace.install.flagged",
            decision: "ALLOW",
            reason: `target=${key}@${i.data.version} takedown`,
            inputs: { key, version: i.data.version },
          });
          flagged++;
        }
        return { flagged };
      },
    );
  }
}
