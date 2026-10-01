import net from "node:net";
import tls from "node:tls";
import type { EmailMessage, HttpTransport, SmtpTransport } from "./adapters.js";

/** Real HTTP client (global fetch). No redirects are followed: a webhook that redirects is treated as a failure. */
export class FetchHttpTransport implements HttpTransport {
  constructor(private readonly fetchFn: typeof fetch = fetch) {}

  async postJson(url: string, body: unknown, opts: { timeoutMs: number }): Promise<void> {
    const res = await this.fetchFn(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      redirect: "error",
      signal: AbortSignal.timeout(opts.timeoutMs),
    });
    if (!res.ok) throw new Error(`webhook responded with HTTP ${res.status}`);
  }
}

export interface SmtpOptions {
  host: string;
  port: number;
  /** Implicit TLS (smtps, usually 465). STARTTLS is not implemented: use implicit TLS or a trusted local relay. */
  secure: boolean;
  /** AUTH PLAIN credentials; only sent over `secure` connections. */
  auth?: { user: string; pass: string };
  timeoutMs?: number;
  /** Test seam: replaces net/tls connect. */
  connect?: (o: SmtpOptions) => net.Socket;
}

const noCrlf = (s: string): string => {
  if (/[\r\n]/.test(s)) throw new Error("CR/LF not allowed in SMTP envelope or headers");
  return s;
};

/** Minimal SMTP submission client (EHLO, AUTH PLAIN, MAIL, RCPT, DATA, QUIT). Rejects header injection. */
export class SmtpClient implements SmtpTransport {
  constructor(private readonly o: SmtpOptions) {
    if (o.auth && !o.secure) throw new Error("refusing to send SMTP credentials without TLS");
  }

  async send(msg: EmailMessage): Promise<void> {
    const { o } = this;
    const from = noCrlf(msg.from);
    const to = msg.to.map(noCrlf);
    const subject = noCrlf(msg.subject);
    const data =
      `From: ${from}\r\nTo: ${to.join(", ")}\r\nSubject: ${subject}\r\n` +
      `Content-Type: text/plain; charset=utf-8\r\nMIME-Version: 1.0\r\n\r\n` +
      msg.text
        .replace(/\r?\n/g, "\r\n")
        .replace(/^\./gm, "..")
        .replace(/(?<!\r\n)$/, "\r\n");

    return await new Promise<void>((resolve, reject) => {
      const sock = o.connect
        ? o.connect(o)
        : o.secure
          ? tls.connect({
              host: o.host,
              port: o.port,
              ...(net.isIP(o.host) ? {} : { servername: o.host }),
            })
          : net.connect({ host: o.host, port: o.port });
      let buf = "";
      let done = false;
      const finish = (err?: Error): void => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        sock.destroy();
        if (err) reject(err);
        else resolve();
      };
      const timer = setTimeout(() => finish(new Error("smtp timeout")), o.timeoutMs ?? 10_000);
      const steps: { send: string | null; expect: number }[] = [{ send: null, expect: 220 }];
      steps.push({ send: "EHLO axis.local\r\n", expect: 250 });
      if (o.auth) {
        const token = Buffer.from(`\0${o.auth.user}\0${o.auth.pass}`).toString("base64");
        steps.push({ send: `AUTH PLAIN ${token}\r\n`, expect: 235 });
      }
      steps.push({ send: `MAIL FROM:<${from}>\r\n`, expect: 250 });
      for (const r of to) steps.push({ send: `RCPT TO:<${r}>\r\n`, expect: 250 });
      steps.push({ send: "DATA\r\n", expect: 354 });
      steps.push({ send: `${data}.\r\n`, expect: 250 });
      steps.push({ send: "QUIT\r\n", expect: 221 });
      let i = 0;
      sock.setEncoding("utf8");
      sock.on("error", (e) => finish(e));
      sock.on("close", () => finish(new Error("smtp connection closed early")));
      sock.on("data", (chunk: string) => {
        buf += chunk;
        // A reply is complete at a line of the form "NNN " (space after the code, not "NNN-").
        for (;;) {
          const m = /^(\d{3}) .*\r?\n/m.exec(buf);
          if (!m) return;
          buf = buf.slice(m.index + m[0].length);
          const step = steps[i++];
          /* v8 ignore next */
          if (!step) return;
          if (Number(m[1]) !== step.expect)
            return finish(new Error(`smtp unexpected reply ${m[1]}`));
          if (i === steps.length) return finish();
          const next = steps[i];
          /* v8 ignore next */
          if (next?.send) sock.write(next.send);
        }
      });
    });
  }
}
