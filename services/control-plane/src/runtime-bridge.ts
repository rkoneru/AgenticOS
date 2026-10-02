import type { ModelKeyService } from "./modelkeys.js";

/**
 * TS -> runtime path for BYO model keys (DEV / NON-PRODUCTION). The Python runtime's `SecretStore` (`models/secrets.py`) is
 * `get(tenant_id, provider, label) -> Secret`. `HttpSecretStoreContract` documents the HTTP exchange an `HttpSecretStore` client
 * implements, and `runtimeAuthFromTokens` builds the bearer -> tenant map the endpoint uses:
 *
 *   POST /internal/v1/model-keys/reveal            Authorization: Bearer <per-tenant runtime token>
 *   {"provider": "anthropic", "label": "default"}  ->  200 {"value": "<secret>"} | 404 | 401
 *
 * The tenant is the one the bearer token was issued for (never the body). Plaintext crosses the wire: loopback plus TLS termination
 * only. A production deployment replaces this with the runtime calling the KMS directly (NEEDS #704, #707).
 */
export const HttpSecretStoreContract = {
  path: "/internal/v1/model-keys/reveal",
  method: "POST",
} as const;

export function runtimeAuthFromTokens(tokens: Readonly<Record<string, string>>): (authorization: string | undefined) => string | undefined {
  const byToken = new Map(Object.entries(tokens).map(([tenant, token]) => [token, tenant]));
  return (authorization) => {
    const m = /^Bearer (\S+)$/.exec(authorization ?? "");
    return m ? byToken.get(m[1] as string) : undefined;
  };
}

export type { ModelKeyService };
