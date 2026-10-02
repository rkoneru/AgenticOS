import type { NextConfig } from "next";

const config: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  transpilePackages: ["@axis/ui"],
  serverExternalPackages: ["@axis/abl", "ajv", "ajv-formats", "yaml"],
  // No rewrites: the BFF (`app/api/axis`) and the SSO route handler (`app/auth/sso`) read their upstream addresses at run time.
};

export default config;
