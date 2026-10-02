import { AdminAudit } from "./audit.js";
import { AdminService, type AuditReaderLike } from "./admin.js";
import { ApiKeyService } from "./apikeys.js";
import { Authorizer } from "./authz.js";
import { TokenSigner } from "./crypto.js";
import { DirectoryService } from "./directory.js";
import { DomainService, type DnsResolver } from "./domains.js";
import type { IdentityProvider } from "./idp.js";
import type { Kms } from "./kms.js";
import { ModelKeyService } from "./modelkeys.js";
import { PolicyPackService, type PackValidator } from "./policies.js";
import { Provisioner } from "./provisioning.js";
import { ScimHandler } from "./scim.js";
import { SessionService } from "./sessions.js";
import { SsoService } from "./sso.js";
import { RegionGuard } from "./tenancy.js";
import type { ControlPlaneStore } from "./types.js";
import type { AuditSink } from "@axis/contracts";
import type { HttpDeps } from "./http.js";

export interface WireConfig {
  store: ControlPlaneStore;
  auditSink: AuditSink;
  auditReader?: AuditReaderLike;
  authorizer: Authorizer;
  idp: IdentityProvider;
  kms: Kms;
  dns: DnsResolver;
  region: string;
  regions: readonly string[];
  /** >= 32 bytes each; distinct purposes. */
  secrets: { pepper: Uint8Array; cookieKey: Uint8Array; signingKeys: { kid: string; key: Uint8Array }[] };
  redirectUri: string;
  allowedReturnOrigins: readonly string[];
  validator?: PackValidator;
  defaultPacks?: unknown[];
  now?: () => Date;
  platformToken?: string;
  devToken?: string;
  runtimeAuth?: HttpDeps["runtimeAuth"];
  secureCookies?: boolean;
  accessTtlSec?: number;
  absoluteTtlSec?: number;
}

export interface ControlPlane {
  deps: HttpDeps;
  admin: AdminService;
  sessions: SessionService;
  apiKeys: ApiKeyService;
  modelKeys: ModelKeyService;
  policies: PolicyPackService;
  directories: DirectoryService;
  sso: SsoService;
  provisioner: Provisioner;
}

/** Composition root: builds every service from one configuration (used by `main.ts` and the tests). */
export function wireControlPlane(c: WireConfig): ControlPlane {
  const now = c.now;
  const audit = new AdminAudit(c.auditSink, now);
  const sessions = new SessionService({ store: c.store, signer: new TokenSigner(c.secrets.signingKeys), pepper: c.secrets.pepper, ...(now ? { now } : {}), ...(c.accessTtlSec ? { accessTtlSec: c.accessTtlSec } : {}), ...(c.absoluteTtlSec ? { absoluteTtlSec: c.absoluteTtlSec } : {}) });
  const apiKeys = new ApiKeyService({ store: c.store, pepper: c.secrets.pepper, ...(now ? { now } : {}) });
  const modelKeys = new ModelKeyService({ store: c.store, kms: c.kms, ...(now ? { now } : {}) });
  const policies = new PolicyPackService({ store: c.store, ...(c.validator ? { validator: c.validator } : {}), ...(now ? { now } : {}) });
  const directories = new DirectoryService({ store: c.store, sessions, audit, pepper: c.secrets.pepper, ...(now ? { now } : {}) });
  const domains = new DomainService({ store: c.store, dns: c.dns, ...(now ? { now } : {}) });
  const region = new RegionGuard(c.region, c.store);
  const admin = new AdminService({
    store: c.store, authorizer: c.authorizer, audit, sessions, apiKeys, modelKeys, policies, directories, domains, idp: c.idp, region,
    ...(c.auditReader ? { auditReader: c.auditReader } : {}), ...(now ? { now } : {}),
  });
  const sso = new SsoService({ store: c.store, idp: c.idp, sessions, audit, cookieKey: c.secrets.cookieKey, redirectUri: c.redirectUri, allowedReturnOrigins: c.allowedReturnOrigins, ...(now ? { now } : {}) });
  const provisioner = new Provisioner({ store: c.store, audit, region: c.region, regions: c.regions, ...(c.defaultPacks ? { defaultPacks: c.defaultPacks } : {}), ...(c.validator ? { validator: c.validator } : {}) });
  const deps: HttpDeps = {
    admin, sessions, apiKeys, sso, directories, scim: new ScimHandler(directories), idp: c.idp, provisioner, modelKeys, store: c.store,
    ...(c.platformToken ? { platformToken: c.platformToken } : {}), ...(c.devToken ? { devToken: c.devToken } : {}),
    ...(c.runtimeAuth ? { runtimeAuth: c.runtimeAuth } : {}), ...(c.secureCookies !== undefined ? { secureCookies: c.secureCookies } : {}),
  };
  return { deps, admin, sessions, apiKeys, modelKeys, policies, directories, sso, provisioner };
}
