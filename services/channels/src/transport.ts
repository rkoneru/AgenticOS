import net from "node:net";
import { ChannelError, type EmailCall, type HttpCall } from "./types.js";

export interface HttpResponse {
  status: number;
  body: string;
}

/** The only way this service talks to a provider over HTTP. Tests inject a fake; production wraps `FetchTransport` in a guard. */
export interface HttpTransport {
  request(call: HttpCall, opts: { timeoutMs: number }): Promise<HttpResponse>;
}

/** Hands a composed RFC 5322 message to an SMTP relay or an email API. The real client is a NEEDS item (see approvals' SmtpClient). */
export interface EmailTransport {
  send(call: EmailCall): Promise<void>;
}

/** Real client: global fetch, no redirects (a redirecting provider is a failure, never followed). */
export class FetchTransport implements HttpTransport {
  constructor(private readonly fetchFn: typeof fetch = fetch) {}

  async request(call: HttpCall, opts: { timeoutMs: number }): Promise<HttpResponse> {
    const res = await this.fetchFn(call.url, {
      method: call.method,
      headers: call.headers,
      body: call.body,
      redirect: "error",
      signal: AbortSignal.timeout(opts.timeoutMs),
    });
    return { status: res.status, body: (await res.text()).slice(0, 4096) };
  }
}

export function hostAllowed(host: string, allow: readonly string[]): boolean {
  const h = host.toLowerCase();
  return allow.some((a) => {
    const p = a.toLowerCase();
    return p.startsWith("*.") ? h.endsWith(p.slice(1)) && h.length > p.length - 1 : h === p;
  });
}

/**
 * Egress guard: https only, no credentials in the URL, default port only, no IP literals, host must match the allowlist
 * (exact, or `*.suffix`). Redirects are never followed. An outbound target is built by an adapter from ROUTE CONFIG and fixed
 * provider hosts, never from message content; this guard is the second line if that ever regresses.
 */
export class GuardedHttpTransport implements HttpTransport {
  constructor(
    private readonly inner: HttpTransport,
    private readonly allowedHosts: readonly string[],
  ) {}

  async request(call: HttpCall, opts: { timeoutMs: number }): Promise<HttpResponse> {
    let u: URL;
    try {
      u = new URL(call.url);
    } catch {
      throw new ChannelError("TRANSPORT", "outbound URL is not valid");
    }
    if (u.protocol !== "https:") throw new ChannelError("TRANSPORT", "outbound URL must be https");
    if (u.username !== "" || u.password !== "")
      throw new ChannelError("TRANSPORT", "outbound URL must not carry credentials");
    if (u.port !== "")
      throw new ChannelError("TRANSPORT", "outbound URL must use the default port");
    const bare = u.hostname.replace(/^\[|\]$/g, "");
    if (net.isIP(bare) !== 0)
      throw new ChannelError("TRANSPORT", "outbound host must not be an IP literal");
    if (!hostAllowed(u.hostname, this.allowedHosts))
      throw new ChannelError("TRANSPORT", `outbound host ${u.hostname} is not allowlisted`);
    return this.inner.request(call, opts);
  }
}

export const PROVIDER_HOSTS = {
  slack: ["slack.com"],
  twilio: ["api.twilio.com"],
  meta: ["graph.facebook.com"],
  teams: ["*.trafficmanager.net", "*.botframework.com"],
} as const;
