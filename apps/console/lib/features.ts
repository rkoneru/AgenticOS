/** Feature flags. `NEXT_PUBLIC_*` values are inlined at build time and are not secrets. */
export interface Features {
  marketplace: boolean;
  evals: boolean;
  devLogin: boolean;
}

export function parseFeatures(env: Record<string, string | undefined>): Features {
  const on = (v: string | undefined, dflt: boolean): boolean =>
    v === undefined ? dflt : v === "1" || v === "true";
  return {
    marketplace: on(env["NEXT_PUBLIC_FEATURE_MARKETPLACE"], true),
    evals: on(env["NEXT_PUBLIC_FEATURE_EVALS"], true),
    devLogin: on(env["NEXT_PUBLIC_DEV_LOGIN"], false),
  };
}

// Static references so Next inlines each variable.
export const features: Features = parseFeatures({
  NEXT_PUBLIC_FEATURE_MARKETPLACE: process.env["NEXT_PUBLIC_FEATURE_MARKETPLACE"],
  NEXT_PUBLIC_FEATURE_EVALS: process.env["NEXT_PUBLIC_FEATURE_EVALS"],
  NEXT_PUBLIC_DEV_LOGIN: process.env["NEXT_PUBLIC_DEV_LOGIN"],
});

export const ssoStartUrl: string = process.env["NEXT_PUBLIC_SSO_START_URL"] ?? "/auth/sso/start";
export const ssoDefaultOrg: string = process.env["NEXT_PUBLIC_SSO_ORG"] ?? "";
