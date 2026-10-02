import type { NextConfig } from "next";

const api = process.env["AXIS_API_URL"] ?? "http://127.0.0.1:4010";

const config: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  transpilePackages: ["@axis/ui"],
  serverExternalPackages: ["@axis/abl", "ajv", "ajv-formats", "yaml"],
  // Only the SSO redirect flow is proxied by rewrite (the IdP callback lands on the console origin so the
  // control plane's cookies are set for it). Everything else goes through the CSRF-checking BFF route.
  async rewrites() {
    return [{ source: "/auth/sso/:path*", destination: `${api}/auth/sso/:path*` }];
  },
};

export default config;
