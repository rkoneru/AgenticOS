import { clean, summaryLines, TITLES, type Notification, type Notifier } from "./notify.js";

export interface HttpTransport {
  /** POST JSON; must throw unless the server answered 2xx. */
  postJson(url: string, body: unknown, opts: { timeoutMs: number }): Promise<void>;
}

export interface EmailMessage {
  from: string;
  to: string[];
  subject: string;
  text: string;
}

export interface SmtpTransport {
  send(msg: EmailMessage): Promise<void>;
}

/** Per-tenant routing; return undefined to skip (tenant has not configured the channel). */
export type TargetResolver<T> = (tenantId: string) => T | undefined | Promise<T | undefined>;

export interface WebhookTarget {
  /** A secret. Never logged or placed in errors. */
  webhookUrl: string;
}

export interface WebhookOptions {
  transport: HttpTransport;
  target: TargetResolver<WebhookTarget>;
  consoleBaseUrl?: string;
  timeoutMs?: number;
  /** Host allowlist: exact host or ".suffix". Webhook URLs must be https and match (SSRF guard). */
  allowedHosts?: string[];
}

export function assertWebhookUrl(raw: string, allowed: string[]): void {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error("webhook url is not a valid URL");
  }
  if (u.protocol !== "https:") throw new Error("webhook url must be https");
  if (u.username || u.password) throw new Error("webhook url must not embed credentials");
  const host = u.hostname.toLowerCase();
  const ok = allowed.some((a) => (a.startsWith(".") ? host.endsWith(a) : host === a));
  if (!ok) throw new Error("webhook host is not allowed");
}

const mrkdwn = (s: string): string =>
  clean(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

export function buildSlackPayload(n: Notification, consoleBaseUrl?: string): unknown {
  const rows = summaryLines(n, consoleBaseUrl);
  return {
    text: `${TITLES[n.kind]}: ${mrkdwn(n.tool)} (${n.risk_level})`,
    blocks: [
      { type: "header", text: { type: "plain_text", text: TITLES[n.kind] } },
      {
        type: "section",
        fields: rows.map(([k, v]) => ({ type: "mrkdwn", text: `*${k}*\n${mrkdwn(v)}` })),
      },
    ],
  };
}

export function buildTeamsPayload(n: Notification, consoleBaseUrl?: string): unknown {
  const rows = summaryLines(n, consoleBaseUrl);
  return {
    type: "message",
    attachments: [
      {
        contentType: "application/vnd.microsoft.card.adaptive",
        content: {
          $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
          type: "AdaptiveCard",
          version: "1.4",
          body: [
            { type: "TextBlock", size: "Medium", weight: "Bolder", text: TITLES[n.kind] },
            { type: "FactSet", facts: rows.map(([title, value]) => ({ title, value })) },
          ],
        },
      },
    ],
  };
}

abstract class WebhookNotifier implements Notifier {
  abstract readonly channel: string;
  protected abstract readonly defaultHosts: string[];
  constructor(protected readonly opts: WebhookOptions) {}
  protected abstract build(n: Notification): unknown;

  async notify(n: Notification): Promise<void> {
    const target = await this.opts.target(n.tenant_id);
    if (!target) return;
    assertWebhookUrl(target.webhookUrl, this.opts.allowedHosts ?? this.defaultHosts);
    await this.opts.transport.postJson(target.webhookUrl, this.build(n), {
      timeoutMs: this.opts.timeoutMs ?? 5000,
    });
  }
}

export class SlackNotifier extends WebhookNotifier {
  readonly channel = "slack";
  protected readonly defaultHosts = ["hooks.slack.com"];
  protected build(n: Notification): unknown {
    return buildSlackPayload(n, this.opts.consoleBaseUrl);
  }
}

export class TeamsNotifier extends WebhookNotifier {
  readonly channel = "teams";
  protected readonly defaultHosts = [
    ".webhook.office.com",
    ".logic.azure.com",
    ".powerplatform.com",
  ];
  protected build(n: Notification): unknown {
    return buildTeamsPayload(n, this.opts.consoleBaseUrl);
  }
}

const ADDR_RE = /^[^\s@<>(),;:"\\]+@[^\s@<>(),;:"\\]+\.[^\s@<>(),;:"\\]+$/;

export function buildEmail(
  n: Notification,
  from: string,
  to: string[],
  consoleBaseUrl?: string,
): EmailMessage {
  for (const a of [from, ...to]) if (!ADDR_RE.test(a)) throw new Error("invalid email address");
  if (to.length === 0) throw new Error("no recipients");
  const rows = summaryLines(n, consoleBaseUrl);
  return {
    from,
    to,
    subject: clean(`[AXIS] ${TITLES[n.kind]}: ${n.tool} (${n.risk_level})`, 150),
    text: `${TITLES[n.kind]}\n\n${rows.map(([k, v]) => `${k}: ${v}`).join("\n")}\n`,
  };
}

export interface EmailTarget {
  to: string[];
}

export interface EmailOptions {
  transport: SmtpTransport;
  from: string;
  target: TargetResolver<EmailTarget>;
  consoleBaseUrl?: string;
}

export class EmailNotifier implements Notifier {
  readonly channel = "email";
  constructor(private readonly opts: EmailOptions) {}

  async notify(n: Notification): Promise<void> {
    const target = await this.opts.target(n.tenant_id);
    if (!target) return;
    await this.opts.transport.send(
      buildEmail(n, this.opts.from, target.to, this.opts.consoleBaseUrl),
    );
  }
}
