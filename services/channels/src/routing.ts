import {
  CHANNELS,
  ChannelError,
  type ChannelId,
  type RouteConfig,
  type RoutingTable,
} from "./types.js";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Normalise a provider key so lookups and configuration agree (case-insensitive for emails, trimmed). */
export function normalizeProviderKey(channel: ChannelId, key: string): string {
  const k = key.trim();
  return channel === "email" ? k.toLowerCase() : k;
}

/**
 * Static routing table. The tenant a message belongs to is read from this table by the provider identity ONLY; an
 * identity that is not configured, or is configured twice for different tenants, is refused at construction.
 */
export class StaticRoutingTable implements RoutingTable {
  private readonly byKey = new Map<string, RouteConfig>();

  constructor(routes: readonly RouteConfig[]) {
    for (const r of routes) {
      if (!CHANNELS.includes(r.channel))
        throw new ChannelError("INVALID", `unknown channel ${r.channel}`);
      if (!UUID_RE.test(r.tenant_id))
        throw new ChannelError("INVALID", "route tenant_id must be a UUID");
      if (r.provider_key.trim() === "")
        throw new ChannelError("INVALID", "route provider_key is empty");
      const k = `${r.channel}\u0000${normalizeProviderKey(r.channel, r.provider_key)}`;
      if (this.byKey.has(k))
        throw new ChannelError("CONFLICT", `duplicate route for ${r.channel}:${r.provider_key}`);
      this.byKey.set(k, r);
    }
  }

  lookup(channel: ChannelId, providerKey: string): RouteConfig | undefined {
    if (typeof providerKey !== "string" || providerKey === "" || providerKey.length > 512)
      return undefined;
    return this.byKey.get(`${channel}\u0000${normalizeProviderKey(channel, providerKey)}`);
  }

  candidates(channel: ChannelId): RouteConfig[] {
    return [...this.byKey.values()].filter((r) => r.channel === channel && r.enabled);
  }

  forTenant(tenant: string, channel: ChannelId): RouteConfig[] {
    return [...this.byKey.values()].filter(
      (r) => r.channel === channel && r.tenant_id === tenant && r.enabled,
    );
  }

  all(): RouteConfig[] {
    return [...this.byKey.values()];
  }
}
