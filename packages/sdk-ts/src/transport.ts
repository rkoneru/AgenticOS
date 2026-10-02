import {
  AxisAbortError,
  AxisApiError,
  AxisConnectionError,
  AxisError,
  AxisTimeoutError,
  errorFromProblem,
  parseRetryAfter,
  type ProblemDetails,
  type ResponseMeta,
} from "./errors.js";
import type { OperationSpec } from "./generated/operations.js";
import { redactText, Secret } from "./redact.js";

export const SDK_VERSION = "0.1.0";

export interface RequestOptions {
  /** Abort the call (and any retries). */
  signal?: AbortSignal;
  /** Per-attempt timeout in milliseconds. */
  timeoutMs?: number;
  /** Override the client's retry budget for this call. */
  maxRetries?: number;
  /** Extra headers. Credential, tenant and host headers are refused. */
  headers?: Record<string, string>;
  /** Called once per finished call (success or failure) with request/trace ids. */
  onResponse?: (meta: ResponseMeta) => void;
}

export interface Transport {
  call<T>(op: OperationSpec, params: object, options?: RequestOptions): Promise<T>;
}

export type Validator = (op: OperationSpec, value: unknown) => void;

export interface TransportConfig {
  baseUrl: string;
  apiKey?: string | undefined;
  token?: string | undefined;
  fetch?: typeof fetch | undefined;
  timeoutMs?: number | undefined;
  maxRetries?: number | undefined;
  retryBaseMs?: number | undefined;
  retryMaxMs?: number | undefined;
  /** Allow http:// to a non-loopback host. Off by default: credentials never travel in clear text. */
  allowInsecure?: boolean | undefined;
  userAgent?: string | undefined;
  onResponse?: ((meta: ResponseMeta) => void) | undefined;
  /** Opt-in validators (off by default). Bring your own, for example Ajv over the OpenAPI schemas. */
  validateRequest?: Validator | undefined;
  validateResponse?: Validator | undefined;
  /** Injectable for tests. */
  sleep?: ((ms: number, signal?: AbortSignal) => Promise<void>) | undefined;
  random?: (() => number) | undefined;
}

const RETRY_STATUS = new Set([408, 429, 500, 502, 503, 504]);
const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);
const MAX_REDIRECTS = 5;
const FORBIDDEN_HEADERS =
  /^(authorization|x-axis-api-key|x-axis-tenant[a-z-]*|x-tenant[a-z-]*|host|cookie|proxy-authorization)$/i;
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

export function defaultSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new AxisAbortError("aborted"));
    const t = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(t);
      reject(new AxisAbortError("aborted"));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

/** Normalise and vet a base URL: https only (loopback may use http), no credentials, no query. */
export function normalizeBaseUrl(raw: string, allowInsecure = false): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new TypeError(`invalid base URL: ${redactText(raw)}`);
  }
  if (u.username || u.password) throw new TypeError("base URL must not embed credentials");
  if (u.search || u.hash) throw new TypeError("base URL must not carry a query or fragment");
  if (
    u.protocol !== "https:" &&
    !(u.protocol === "http:" && (allowInsecure || LOOPBACK.has(u.hostname)))
  ) {
    throw new TypeError(
      `base URL must be https (got ${u.protocol}//${u.host}); loopback hosts may use http`,
    );
  }
  if (!u.pathname.endsWith("/")) u.pathname += "/";
  return u;
}

export class HttpTransport implements Transport {
  readonly #base: URL;
  readonly #key: Secret | undefined;
  readonly #token: Secret | undefined;
  readonly #c: TransportConfig;
  readonly #fetch: typeof fetch;
  readonly #sleep: (ms: number, signal?: AbortSignal) => Promise<void>;
  readonly #random: () => number;

  constructor(config: TransportConfig) {
    this.#c = config;
    this.#base = normalizeBaseUrl(config.baseUrl, config.allowInsecure);
    this.#key = config.apiKey ? new Secret(config.apiKey) : undefined;
    this.#token = config.token ? new Secret(config.token) : undefined;
    this.#fetch = config.fetch ?? ((...a) => globalThis.fetch(...a));
    this.#sleep = config.sleep ?? defaultSleep;
    this.#random = config.random ?? Math.random;
  }

  get baseUrl(): string {
    return this.#base.href.replace(/\/$/, "");
  }

  toString(): string {
    return `HttpTransport(${this.baseUrl})`;
  }

  toJSON(): { baseUrl: string } {
    return { baseUrl: this.baseUrl };
  }

  #secrets(): string[] {
    return [this.#key?.reveal(), this.#token?.reveal()].filter((s): s is string => s !== undefined);
  }

  #scrub(text: string): string {
    return redactText(text, this.#secrets());
  }

  #url(op: OperationSpec, params: Record<string, unknown>): URL {
    let path = op.path;
    for (const name of op.pathParams) {
      const v = params[name];
      if (typeof v !== "string" || v === "")
        throw new TypeError(`${op.id}: missing path parameter "${name}"`);
      path = path.replace(`{${name}}`, encodeURIComponent(v));
    }
    const url = new URL(`.${path}`, this.#base); // "./policies:test": a bare "policies:test" would parse as a URL scheme;
    for (const name of op.queryParams) {
      const v = params[name];
      if (v !== undefined && v !== null) url.searchParams.set(name, String(v));
    }
    return url;
  }

  #headers(
    op: OperationSpec,
    key: string | undefined,
    hasBody: boolean,
    extra: Record<string, string> | undefined,
    sse: boolean,
  ): Headers {
    const h = new Headers();
    h.set("accept", sse ? "text/event-stream" : "application/json");
    h.set("user-agent", this.#c.userAgent ?? `axis-sdk-ts/${SDK_VERSION}`);
    if (hasBody) h.set("content-type", "application/json");
    if (this.#key) h.set("x-axis-api-key", this.#key.reveal());
    else if (this.#token) h.set("authorization", `Bearer ${this.#token.reveal()}`);
    if (key !== undefined) h.set("idempotency-key", key);
    for (const [k, v] of Object.entries(extra ?? {})) {
      if (FORBIDDEN_HEADERS.test(k))
        throw new TypeError(`header "${k}" may not be set per request`);
      h.set(k, v);
    }
    return h;
  }

  /** One HTTP exchange with manual, same-origin-only redirect handling. Credentials never leave the base origin. */
  async #send(url: URL, init: RequestInit, signal: AbortSignal): Promise<Response> {
    let current = url;
    let method = init.method ?? "GET";
    let body = init.body;
    const headers = new Headers(init.headers);
    for (let hop = 0; ; hop++) {
      const res = await this.#fetch(current.href, {
        method,
        headers,
        body: body ?? null,
        signal,
        redirect: "manual",
      });
      if (!REDIRECT_STATUS.has(res.status)) return res;
      const loc = res.headers.get("location");
      void res.body?.cancel().catch(() => undefined);
      if (!loc) return res;
      const next = new URL(loc, current);
      if (next.origin !== this.#base.origin) {
        throw new AxisConnectionError(
          `refusing to follow a redirect to another origin (${next.origin}); credentials are only sent to ${this.#base.origin}`,
        );
      }
      if (hop >= MAX_REDIRECTS) throw new AxisConnectionError("too many redirects");
      if (
        res.status === 303 ||
        ((res.status === 301 || res.status === 302) && method !== "GET" && method !== "HEAD")
      ) {
        method = "GET";
        body = null;
        headers.delete("content-type");
      }
      current = next;
    }
  }

  #backoff(attempt: number, retryAfterSeconds: number | undefined): number {
    const cap = this.#c.retryMaxMs ?? 8000;
    if (retryAfterSeconds !== undefined)
      return Math.min(retryAfterSeconds * 1000, Math.max(cap, 30_000));
    const ceiling = Math.min(cap, (this.#c.retryBaseMs ?? 500) * 2 ** attempt);
    return Math.floor(this.#random() * ceiling); // full jitter
  }

  /** Is this call safe to repeat? Idempotent verbs and keyed POSTs only; anything else is sent exactly once. */
  static retriable(op: OperationSpec, key: string | undefined): boolean {
    return op.idempotent === "always" || (op.idempotent === "with-key" && key !== undefined);
  }

  async call<T>(op: OperationSpec, params: object, options: RequestOptions = {}): Promise<T> {
    const res = await this.#exchange(op, params, options, false);
    return res as T;
  }

  /** Open a text/event-stream response (single attempt; the caller reconnects). */
  async openStream(
    op: OperationSpec,
    params: object,
    options: RequestOptions = {},
  ): Promise<Response> {
    return (await this.#exchange(op, params, options, true)) as Response;
  }

  async #exchange(
    op: OperationSpec,
    rawParams: object,
    options: RequestOptions,
    sse: boolean,
  ): Promise<unknown> {
    const params = rawParams as Record<string, unknown>;
    const started = Date.now();
    const url = this.#url(op, params);
    const hasBody = op.hasBody && params["body"] !== undefined;
    if (op.bodyRequired && !hasBody) throw new TypeError(`${op.id}: request body is required`);
    if (hasBody) this.#c.validateRequest?.(op, params["body"]);
    const supplied = params["idempotencyKey"];
    const key = op.idempotencyKey
      ? typeof supplied === "string"
        ? supplied
        : globalThis.crypto.randomUUID()
      : undefined;
    const retriable = HttpTransport.retriable(op, key);
    const maxRetries = sse ? 0 : retriable ? (options.maxRetries ?? this.#c.maxRetries ?? 2) : 0;
    const serialized = hasBody ? JSON.stringify(params["body"]) : undefined;
    const timeoutMs = options.timeoutMs ?? this.#c.timeoutMs ?? 30_000;

    const headers = this.#headers(op, key, hasBody, options.headers, sse);
    let attempt = 0;
    const report = (status: number, requestId: string | undefined, traceId: string | undefined) => {
      const meta: ResponseMeta = {
        operationId: op.id,
        status,
        requestId,
        traceId,
        attempts: attempt + 1,
        durationMs: Date.now() - started,
      };
      (options.onResponse ?? this.#c.onResponse)?.(meta);
    };

    for (; ; attempt++) {
      const timeoutSignal = AbortSignal.timeout(timeoutMs);
      const signal = options.signal
        ? AbortSignal.any([options.signal, timeoutSignal])
        : timeoutSignal;
      let res: Response;
      try {
        res = await this.#send(
          url,
          { method: op.method, headers, body: serialized ?? null },
          signal,
        );
      } catch (err) {
        if (options.signal?.aborted)
          throw new AxisAbortError("request aborted by caller", { cause: err });
        const failure = timeoutSignal.aborted
          ? new AxisTimeoutError(`${op.id}: timed out after ${timeoutMs} ms`, { cause: err })
          : err instanceof AxisError
            ? err
            : new AxisConnectionError(
                this.#scrub(`${op.id}: ${(err as Error)?.message ?? "network error"}`),
                { cause: err },
              );
        if (retriable && attempt < maxRetries && !(err instanceof AxisError)) {
          await this.#sleep(this.#backoff(attempt, undefined), options.signal);
          continue;
        }
        report(0, undefined, undefined);
        throw failure;
      }

      const requestId = res.headers.get("x-request-id") ?? undefined;
      const traceId =
        res.headers.get("x-trace-id") ??
        traceFromTraceparent(res.headers.get("traceparent")) ??
        undefined;

      if (res.ok) {
        report(res.status, requestId, traceId);
        if (sse) return res;
        return this.#parseSuccess(op, res);
      }

      const retryAfter = parseRetryAfter(res.headers.get("retry-after"));
      const problem = await readProblem(res);
      if (retriable && attempt < maxRetries && RETRY_STATUS.has(res.status)) {
        await this.#sleep(this.#backoff(attempt, retryAfter), options.signal);
        continue;
      }
      report(res.status, requestId, traceId);
      throw errorFromProblem(res.status, problem, {
        requestId,
        traceId: traceId ?? problem?.trace_id,
        retryAfterSeconds: retryAfter,
      });
    }
  }

  async #parseSuccess(op: OperationSpec, res: Response): Promise<unknown> {
    const text = await res.text();
    if (res.status === 204 || text === "") return undefined;
    let data: unknown;
    try {
      data = JSON.parse(text);
    } catch (err) {
      throw new AxisApiError(`${op.id}: response was not valid JSON`, {
        status: res.status,
        cause: err,
      });
    }
    this.#c.validateResponse?.(op, data);
    return data;
  }
}

function traceFromTraceparent(v: string | null): string | undefined {
  const m = v ? /^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$/.exec(v) : null;
  return m?.[1];
}

async function readProblem(res: Response): Promise<ProblemDetails | undefined> {
  try {
    const text = await res.text();
    const parsed: unknown = JSON.parse(text);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as ProblemDetails)
      : undefined;
  } catch {
    return undefined;
  }
}
