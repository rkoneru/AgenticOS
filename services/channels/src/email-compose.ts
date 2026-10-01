import { ChannelError } from "./types.js";

const LOCAL_RE = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}$/;
const LABEL_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

/** Strict address validation (no display names, no quoting, no comments, no IP literals). Returns the lower-cased address or undefined. */
export function validateAddress(a: unknown): string | undefined {
  if (typeof a !== "string" || a.length > 254) return undefined;
  const at = a.lastIndexOf("@");
  if (at < 1) return undefined;
  const local = a.slice(0, at);
  const domain = a.slice(at + 1).toLowerCase();
  if (!LOCAL_RE.test(local) || local.startsWith(".") || local.endsWith(".") || local.includes(".."))
    return undefined;
  const labels = domain.split(".");
  if (labels.length < 2 || !labels.every((l) => LABEL_RE.test(l))) return undefined;
  if (/^\d+$/.test(labels[labels.length - 1]!)) return undefined;
  return `${local}@${domain}`;
}

/** Extract the address of an RFC 5322 `Name <addr>` / bare `addr` header value. Only one address is accepted. */
export function extractAddress(v: unknown): string | undefined {
  if (typeof v !== "string" || v.length > 998 || /[\r\n\0]/.test(v)) return undefined;
  const m = /<([^<>]+)>\s*$/.exec(v.trim());
  return validateAddress(m ? m[1] : v.trim());
}

const SYSTEM_LOCALPARTS =
  /^(mailer-daemon|postmaster|noreply|no-reply|donotreply|do-not-reply|bounce[s]?|root)$/i;

/**
 * Mail we must never answer: automatic replies, bounces, lists, bulk. Answering these builds mail loops. `headers` keys are
 * lower-case. Anything that identifies the message as machine-generated suppresses the reply.
 */
export function suppressReason(headers: Record<string, string>, from: string): string | undefined {
  const get = (k: string): string => (headers[k] ?? "").toLowerCase();
  const auto = get("auto-submitted");
  if (auto !== "" && auto !== "no") return "auto-submitted";
  if (/^(bulk|junk|list|auto_reply)$/.test(get("precedence"))) return "precedence";
  if (headers["x-auto-response-suppress"] !== undefined) return "x-auto-response-suppress";
  if (headers["list-id"] !== undefined || headers["list-unsubscribe"] !== undefined) return "list";
  if (get("return-path") === "<>") return "null-return-path";
  if (get("content-type").startsWith("multipart/report")) return "delivery-report";
  const local = from.slice(0, from.lastIndexOf("@"));
  if (SYSTEM_LOCALPARTS.test(local)) return "system-sender";
  return undefined;
}

const noCtl = (s: string, what: string): string => {
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(s))
    throw new ChannelError("INVALID", `${what} must not contain control characters`);
  return s;
};

/** RFC 2047 encode a header value when it is not plain printable ASCII. */
function encodeHeader(v: string): string {
  return /^[\x20-\x7e]*$/.test(v) ? v : `=?UTF-8?B?${Buffer.from(v, "utf8").toString("base64")}?=`;
}

const MSGID_RE = /^<[A-Za-z0-9.!#$%&'*+/=?^_`{|}~@-]{1,200}>$/;
export const validMessageId = (v: unknown): v is string =>
  typeof v === "string" && MSGID_RE.test(v);

export interface ComposeInput {
  from: string;
  to: string;
  subject: string;
  text: string;
  messageId: string;
  inReplyTo?: string;
  date?: Date;
}

/**
 * Compose a plain-text RFC 5322 reply. Header injection safe: addresses are validated (no CR/LF possible), the subject is checked
 * for control characters BEFORE encoding, and every other header value is generated here. The reply carries `Auto-Submitted:
 * auto-replied` and `X-Auto-Response-Suppress` so well-behaved autoresponders do not answer it (loop prevention). The body is
 * normalised to CRLF; dot-stuffing is the SMTP transport's job.
 */
export function composeEmail(i: ComposeInput): { raw: string; from: string; to: string } {
  const from = validateAddress(i.from);
  const to = validateAddress(i.to);
  if (!from) throw new ChannelError("INVALID", "invalid from address");
  if (!to) throw new ChannelError("INVALID", "invalid recipient address");
  if (!validMessageId(i.messageId)) throw new ChannelError("INVALID", "invalid message id");
  const subject = encodeHeader(noCtl(i.subject, "subject").slice(0, 200));
  const headers = [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    `Date: ${(i.date ?? new Date()).toUTCString()}`,
    `Message-ID: ${i.messageId}`,
    "Auto-Submitted: auto-replied",
    "X-Auto-Response-Suppress: All",
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "Content-Transfer-Encoding: base64",
  ];
  if (i.inReplyTo !== undefined) {
    if (!validMessageId(i.inReplyTo)) throw new ChannelError("INVALID", "invalid In-Reply-To");
    headers.push(`In-Reply-To: ${i.inReplyTo}`, `References: ${i.inReplyTo}`);
  }
  const body = (
    Buffer.from(i.text.replace(/\r?\n/g, "\r\n"), "utf8")
      .toString("base64")
      .match(/.{1,76}/g) ?? []
  ).join("\r\n");
  return { raw: `${headers.join("\r\n")}\r\n\r\n${body}\r\n`, from, to };
}
