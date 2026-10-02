import { RegistryError, type RegistryService, type TenantPrincipal } from "@axis/registry";
import {
  PortConflict,
  PortForbidden,
  PortInvalid,
  PortNotFound,
  PortUnavailable,
  type Principal,
  type RegistryKeyDto,
  type RegistryNamespaceDto,
  type RegistryPort,
  type RegistryVersionDto,
  type ResolvedBlueprintDto,
} from "../ports.js";

/** Translates the registry's refusals; `verification_failed` carries the failed check codes so a client can tell WHY a version does not verify. */
export function fromRegistryError(e: unknown): never {
  if (!(e instanceof RegistryError)) throw e;
  switch (e.code) {
    case "not_found":
      throw new PortNotFound(e.message);
    case "forbidden":
    case "unauthenticated":
      throw new PortForbidden(e.message);
    case "conflict":
      throw new PortConflict(e.message);
    case "invalid":
      throw new PortInvalid(e.message, [{ path: "/", message: e.message }]);
    case "verification_failed":
      throw new PortInvalid(
        e.message,
        (e.checks.length > 0 ? e.checks : ["verification_failed"]).map((c) => ({
          path: "/verification",
          keyword: c,
          message: `check failed: ${c}`,
        })),
      );
    default:
      throw new PortUnavailable(e.message);
  }
}

/** The tenant and the role come from the authenticated gateway principal and nothing else. */
export const registryPrincipal = (p: Principal): TenantPrincipal => ({
  kind: "tenant",
  tenantId: p.tenantId,
  subject: p.memberId,
  role: p.role,
});

type Version = Awaited<ReturnType<RegistryService["listVersions"]>>[number];
type Record_ = Version["record"];

const versionDto = (
  r: Record_,
  state?: { state: string; reason: string | null },
): RegistryVersionDto => ({
  namespace: r.namespace,
  name: r.name,
  version: r.version,
  content_hash: r.contentHash,
  risk_level: r.riskLevel,
  signature: { key_id: r.signature.keyId, signed_at: r.signature.signedAt, sig: r.signature.sig },
  published_at: r.publishedAt.toISOString(),
  published_by: r.publishedBy,
  ...(state ? { state: state.state as "active", state_reason: state.reason } : {}),
});

export class RegistryAdapter implements RegistryPort {
  constructor(private readonly reg: RegistryService) {}

  async listNamespaces(p: Principal): Promise<RegistryNamespaceDto[]> {
    try {
      return (await this.reg.listNamespaces(registryPrincipal(p))).map((n) => ({
        namespace: n.namespace,
        public: n.public,
        created_at: n.createdAt.toISOString(),
      }));
    } catch (e) {
      return fromRegistryError(e);
    }
  }

  async claim(p: Principal, namespace: string): Promise<RegistryNamespaceDto> {
    try {
      const n = await this.reg.claimNamespace(registryPrincipal(p), namespace);
      return { namespace: n.namespace, public: n.public, created_at: n.createdAt.toISOString() };
    } catch (e) {
      return fromRegistryError(e);
    }
  }

  private keyDto(k: Awaited<ReturnType<RegistryService["listKeys"]>>[number]): RegistryKeyDto {
    return {
      key_id: k.keyId,
      public_key: k.publicKey,
      valid_from: k.validFrom.toISOString(),
      valid_until: k.validUntil?.toISOString() ?? null,
      revoked_at: k.revokedAt?.toISOString() ?? null,
      revoke_reason: k.revokeReason,
    };
  }

  async listKeys(p: Principal, namespace: string): Promise<RegistryKeyDto[]> {
    try {
      return (await this.reg.listKeys(registryPrincipal(p), namespace)).map((k) => this.keyDto(k));
    } catch (e) {
      return fromRegistryError(e);
    }
  }

  async addKey(p: Principal, namespace: string, publicKey: string): Promise<RegistryKeyDto> {
    try {
      return this.keyDto(await this.reg.addKey(registryPrincipal(p), namespace, { publicKey }));
    } catch (e) {
      return fromRegistryError(e);
    }
  }

  async publish(
    p: Principal,
    namespace: string,
    input: Parameters<RegistryPort["publish"]>[2],
  ): Promise<RegistryVersionDto> {
    try {
      const r = await this.reg.publish(registryPrincipal(p), namespace, {
        abl: input.abl,
        signature: {
          keyId: input.signature.key_id,
          signedAt: input.signature.signed_at,
          sig: input.signature.sig,
        },
        provenance: input.provenance as never,
      });
      return versionDto(r);
    } catch (e) {
      return fromRegistryError(e);
    }
  }

  async listVersions(p: Principal, namespace: string, name: string): Promise<RegistryVersionDto[]> {
    try {
      return (await this.reg.listVersions({ tenantId: p.tenantId }, namespace, name)).map((r) =>
        versionDto(r.record, r.status),
      );
    } catch (e) {
      return fromRegistryError(e);
    }
  }

  async yank(
    p: Principal,
    namespace: string,
    name: string,
    version: string,
    reason: string,
  ): Promise<void> {
    try {
      await this.reg.yank(registryPrincipal(p), namespace, name, version, reason);
    } catch (e) {
      return fromRegistryError(e);
    }
  }

  async resolve(p: Principal, ref: string): Promise<ResolvedBlueprintDto> {
    try {
      const r = await this.reg.resolve({ tenantId: p.tenantId }, ref);
      return {
        ...versionDto(r.record, { state: r.state, reason: r.statusReason }),
        abl: r.abl,
        provenance: r.record.provenance,
        verification: {
          key_id: r.verification.keyId,
          builder: r.verification.builder,
          source_ref: r.verification.sourceRef,
          compiler_version: r.verification.compilerVersion,
        },
      };
    } catch (e) {
      return fromRegistryError(e);
    }
  }
}
