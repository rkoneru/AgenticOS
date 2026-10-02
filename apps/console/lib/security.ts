/** Security headers and CSP for every response (see `proxy.ts`). */

export function buildCsp(
  nonce: string,
  /** `formActionOrigins`: the IdP origin(s) the sign-in form may be redirected to (Chromium applies form-action to the redirect chain). */
  opts: { dev?: boolean; insecureHttp?: boolean; formActionOrigins?: readonly string[] } = {},
): string {
  const dev = opts.dev ?? false;
  const directives: Array<[string, string[]]> = [
    ["default-src", ["'self'"]],
    [
      "script-src",
      ["'self'", `'nonce-${nonce}'`, "'strict-dynamic'", ...(dev ? ["'unsafe-eval'"] : [])],
    ],
    ["style-src", dev ? ["'self'", "'unsafe-inline'"] : ["'self'", `'nonce-${nonce}'`]],
    ["img-src", ["'self'", "data:"]],
    ["font-src", ["'self'"]],
    ["connect-src", ["'self'"]],
    ["object-src", ["'none'"]],
    ["base-uri", ["'self'"]],
    ["form-action", ["'self'", ...(opts.formActionOrigins ?? [])]],
    ["frame-ancestors", ["'none'"]],
    ["frame-src", ["'none'"]],
    ["worker-src", ["'self'"]],
    ["manifest-src", ["'self'"]],
  ];
  const out = directives.map(([k, v]) => `${k} ${v.join(" ")}`);
  if (!dev && !opts.insecureHttp) out.push("upgrade-insecure-requests");
  return out.join("; ");
}

export function securityHeaders(
  csp: string,
  opts: { https?: boolean } = {},
): Record<string, string> {
  const h: Record<string, string> = {
    "content-security-policy": csp,
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
  };
  if (opts.https) h["strict-transport-security"] = "max-age=63072000; includeSubDomains";
  return h;
}

export function newNonce(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

const PUBLIC_PATHS = ["/login", "/auth/", "/_next/", "/favicon.ico"];

export function isPublicPath(pathname: string): boolean {
  return PUBLIC_PATHS.some(
    (p) => pathname === p || pathname.startsWith(p.endsWith("/") ? p : `${p}/`),
  );
}

/** Only same-site relative paths are honoured as a post-login target. */
export function safeReturnTo(v: string | null | undefined): string {
  if (!v || !v.startsWith("/") || v.startsWith("//") || v.startsWith("/\\") || hasControlChars(v))
    return "/";
  return v;
}

function hasControlChars(v: string): boolean {
  for (let i = 0; i < v.length; i++) if (v.charCodeAt(i) < 0x20) return true;
  return false;
}
