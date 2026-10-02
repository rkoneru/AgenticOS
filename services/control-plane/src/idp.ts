import { createHash, randomBytes } from "node:crypto";
import { b64u, safeEqual } from "./crypto.js";

/** What the IdP asserts about a user after a successful login. `emailVerified` is the IdP's statement, not ours. */
export interface IdpProfile {
  id: string;
  email: string;
  emailVerified: boolean;
  organizationId: string;
  connectionId?: string;
  connectionType: "saml" | "oidc";
  firstName?: string;
  lastName?: string;
  /** OIDC connections echo the nonce we sent; SAML connections do not (then the state cookie + PKCE protect the flow). */
  nonce?: string;
}

export interface AuthorizationUrlInput {
  organizationId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  nonce: string;
}

export interface ExchangeInput {
  code: string;
  codeVerifier: string;
  redirectUri: string;
}

export type DirectoryEvent =
  | { type: "user.created" | "user.updated"; directoryId: string; user: DirectoryUser }
  | { type: "user.deleted"; directoryId: string; externalId: string }
  | {
      type: "group.created" | "group.updated";
      directoryId: string;
      group: { externalId: string; name: string; memberExternalIds: string[] };
    }
  | { type: "group.deleted"; directoryId: string; externalId: string };

export interface DirectoryUser {
  externalId: string;
  userName: string;
  email: string;
  active: boolean;
  displayName?: string;
}

/**
 * WorkOS-shaped identity provider port. The real adapter (WorkOS SDK) is NEEDS #701; `FakeIdentityProvider` implements the same
 * contract for tests. Implementations must verify SAML/OIDC assertions and webhook signatures themselves; this service only
 * validates what it adds (state, nonce, PKCE binding, redirect URI, domain policy).
 */
export interface IdentityProvider {
  authorizationUrl(input: AuthorizationUrlInput): string;
  exchangeCode(input: ExchangeInput): Promise<IdpProfile>;
  /** Verifies the webhook signature over the raw body and returns the typed event. Throws on a bad signature. */
  parseDirectoryEvent(rawBody: string, signatureHeader: string | undefined): DirectoryEvent;
  adminPortalLink(input: {
    organizationId: string;
    intent: "sso" | "dsync";
    returnUrl: string;
  }): Promise<string>;
}

interface IssuedCode {
  profile: IdpProfile;
  redirectUri: string;
  challenge: string;
  used: boolean;
  nonce: string;
}

/** FAKE IdP: issues one-shot codes bound to a PKCE challenge, redirect URI and nonce, like a conforming OIDC provider. */
export class FakeIdentityProvider implements IdentityProvider {
  private readonly codes = new Map<string, IssuedCode>();
  private readonly pending = new Map<
    string,
    { redirectUri: string; challenge: string; nonce: string }
  >();
  readonly webhookSecret = "fake-idp-webhook-secret";
  lastPortal?: { organizationId: string; intent: string; returnUrl: string };

  constructor(private readonly base = "https://idp.fake.example") {}

  authorizationUrl(i: AuthorizationUrlInput): string {
    this.pending.set(i.state, {
      redirectUri: i.redirectUri,
      challenge: i.codeChallenge,
      nonce: i.nonce,
    });
    const u = new URL(`${this.base}/authorize`);
    u.searchParams.set("organization", i.organizationId);
    u.searchParams.set("redirect_uri", i.redirectUri);
    u.searchParams.set("state", i.state);
    u.searchParams.set("code_challenge", i.codeChallenge);
    u.searchParams.set("code_challenge_method", "S256");
    u.searchParams.set("nonce", i.nonce);
    return u.toString();
  }

  /** Test driver: the user authenticates at the IdP for the login started with `state`; returns the code the browser would carry back. */
  complete(
    state: string,
    profile: Omit<IdpProfile, "nonce">,
    opts: { omitNonce?: boolean; wrongNonce?: boolean } = {},
  ): string {
    const p = this.pending.get(state);
    if (!p) throw new Error("fake idp: unknown state");
    const code = b64u(randomBytes(16));
    const nonce = opts.omitNonce ? undefined : opts.wrongNonce ? "wrong" : p.nonce;
    this.codes.set(code, {
      profile: { ...profile, ...(nonce !== undefined ? { nonce } : {}) },
      redirectUri: p.redirectUri,
      challenge: p.challenge,
      used: false,
      nonce: p.nonce,
    });
    return code;
  }

  /** Test driver: a code the IdP issued with no matching authorization request (forged state / code injection). */
  issueRogue(profile: IdpProfile, redirectUri: string, verifier: string): string {
    const code = b64u(randomBytes(16));
    this.codes.set(code, {
      profile,
      redirectUri,
      challenge: pkceChallenge(verifier),
      used: false,
      nonce: profile.nonce ?? "",
    });
    return code;
  }

  exchangeCode(i: ExchangeInput): Promise<IdpProfile> {
    const c = this.codes.get(i.code);
    if (!c || c.used) return Promise.reject(new Error("invalid_grant"));
    c.used = true; // single use, even if the rest fails
    if (c.redirectUri !== i.redirectUri)
      return Promise.reject(new Error("invalid_grant: redirect_uri"));
    if (!safeEqual(Buffer.from(pkceChallenge(i.codeVerifier)), Buffer.from(c.challenge)))
      return Promise.reject(new Error("invalid_grant: pkce"));
    return Promise.resolve({ ...c.profile });
  }

  signWebhook(rawBody: string): string {
    return createHash("sha256").update(`${this.webhookSecret}.${rawBody}`).digest("hex");
  }

  parseDirectoryEvent(rawBody: string, signature: string | undefined): DirectoryEvent {
    if (!signature || !safeEqual(Buffer.from(this.signWebhook(rawBody)), Buffer.from(signature)))
      throw new Error("bad webhook signature");
    return JSON.parse(rawBody) as DirectoryEvent;
  }

  adminPortalLink(i: {
    organizationId: string;
    intent: "sso" | "dsync";
    returnUrl: string;
  }): Promise<string> {
    this.lastPortal = i;
    return Promise.resolve(
      `${this.base}/portal/${encodeURIComponent(i.organizationId)}/${i.intent}`,
    );
  }
}

export const pkceChallenge = (verifier: string): string =>
  b64u(createHash("sha256").update(verifier).digest());
