import net from "node:net";

/**
 * A small TCP fault-injection proxy (the in-repo equivalent of Toxiproxy). It sits between a client and one upstream and applies "toxics"
 * that can be switched on and off at run time while connections are open:
 *
 *  - ``down``       refuse new connections and reset existing ones (the upstream "crashed" / a network partition with RST)
 *  - ``blackhole``  accept bytes and drop them in both directions (a partition with no RST: clients only learn through timeouts)
 *  - ``latency``    delay every chunk by ``latencyMs`` (+ jitter) in each direction
 *  - ``slowClose``  deliver upstream->client data one byte at a time every ``trickleMs`` (slow-loris on responses)
 *  - ``resetAfter`` reset the connection once ``resetAfterBytes`` have been forwarded upstream->client (a cut mid-response)
 *  - ``limit``      bandwidth cap in bytes/second per direction
 */
export interface Toxics {
  down: boolean;
  blackhole: boolean;
  latencyMs: number;
  jitterMs: number;
  trickleMs: number;
  resetAfterBytes: number;
  bytesPerSec: number;
}

const NONE: Toxics = {
  down: false,
  blackhole: false,
  latencyMs: 0,
  jitterMs: 0,
  trickleMs: 0,
  resetAfterBytes: 0,
  bytesPerSec: 0,
};

export interface ProxyStats {
  accepted: number;
  refused: number;
  resets: number;
  bytesUp: number;
  bytesDown: number;
  open: number;
}

export class ChaosProxy {
  private server = net.createServer((c) => this.onClient(c));
  private pairs = new Set<{ client: net.Socket; upstream: net.Socket }>();
  private timers = new Set<NodeJS.Timeout>();
  private toxics: Toxics = { ...NONE };
  readonly stats: ProxyStats = {
    accepted: 0,
    refused: 0,
    resets: 0,
    bytesUp: 0,
    bytesDown: 0,
    open: 0,
  };
  port = 0;

  constructor(
    private readonly upstreamHost: string,
    private upstreamPort: number,
    private readonly rng: () => number = Math.random,
  ) {}

  async start(port = 0): Promise<number> {
    await new Promise<void>((resolve, reject) => {
      this.server.once("error", reject);
      this.server.listen(port, "127.0.0.1", resolve);
    });
    this.port = (this.server.address() as net.AddressInfo).port;
    return this.port;
  }

  /** Point the proxy at a different upstream port (e.g. after the upstream restarted elsewhere). */
  retarget(port: number): void {
    this.upstreamPort = port;
  }

  /** Apply toxics (merged over the current ones). ``down`` resets existing connections immediately. */
  set(t: Partial<Toxics>): void {
    this.toxics = { ...this.toxics, ...t };
    if (this.toxics.down) this.resetAll();
  }

  clear(): void {
    this.toxics = { ...NONE };
  }

  get current(): Readonly<Toxics> {
    return this.toxics;
  }

  resetAll(): void {
    for (const p of [...this.pairs]) {
      this.stats.resets++;
      p.client.resetAndDestroy();
      p.upstream.destroy();
    }
    this.pairs.clear();
    this.stats.open = 0;
  }

  async stop(): Promise<void> {
    this.resetAll();
    for (const t of this.timers) clearTimeout(t);
    this.timers.clear();
    await new Promise<void>((r) => this.server.close(() => r()));
  }

  private later(ms: number, fn: () => void): void {
    if (ms <= 0) return fn();
    const t = setTimeout(() => {
      this.timers.delete(t);
      fn();
    }, ms);
    this.timers.add(t);
  }

  private delay(): number {
    const { latencyMs, jitterMs } = this.toxics;
    return latencyMs + (jitterMs > 0 ? this.rng() * jitterMs : 0);
  }

  private onClient(client: net.Socket): void {
    if (this.toxics.down) {
      this.stats.refused++;
      client.resetAndDestroy();
      return;
    }
    this.stats.accepted++;
    const upstream = net.connect(this.upstreamPort, this.upstreamHost);
    const pair = { client, upstream };
    this.pairs.add(pair);
    this.stats.open = this.pairs.size;
    const drop = (): void => {
      this.pairs.delete(pair);
      this.stats.open = this.pairs.size;
      client.destroy();
      upstream.destroy();
    };
    client.on("error", drop);
    upstream.on("error", () => {
      if (!client.destroyed) {
        this.stats.resets++;
        client.resetAndDestroy();
      }
      drop();
    });
    client.on("close", drop);
    upstream.on("close", () => {
      if (!client.destroyed) client.end();
    });
    let down = 0;
    client.on("data", (b: Buffer) => {
      this.stats.bytesUp += b.length;
      if (this.toxics.blackhole) return;
      this.later(this.delay(), () => this.pace(b, (x) => upstream.write(x)));
    });
    upstream.on("data", (b: Buffer) => {
      if (this.toxics.blackhole) return;
      const cut = this.toxics.resetAfterBytes;
      if (cut > 0 && down + b.length >= cut) {
        const head = b.subarray(0, Math.max(0, cut - down));
        down += b.length;
        this.stats.bytesDown += head.length;
        if (head.length > 0) client.write(head);
        this.stats.resets++;
        client.resetAndDestroy();
        drop();
        return;
      }
      down += b.length;
      this.stats.bytesDown += b.length;
      this.later(this.delay(), () => {
        if (this.toxics.trickleMs > 0) this.trickle(b, client);
        else this.pace(b, (x) => client.write(x));
      });
    });
  }

  private pace(b: Buffer, write: (x: Buffer) => void): void {
    const bps = this.toxics.bytesPerSec;
    if (bps <= 0) return void write(b);
    const slice = Math.max(1, Math.floor(bps / 20)); // 50 ms ticks
    for (let i = 0, k = 0; i < b.length; i += slice, k++) {
      this.later(k * 50, () => write(b.subarray(i, i + slice)));
    }
  }

  private trickle(b: Buffer, client: net.Socket): void {
    for (let i = 0; i < b.length; i++) {
      this.later(i * this.toxics.trickleMs, () => {
        if (!client.destroyed) client.write(b.subarray(i, i + 1));
      });
    }
  }
}
