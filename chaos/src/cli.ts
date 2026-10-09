/**
 * Runs one ChaosProxy as a process with an HTTP control port, so the Python chaos suite can switch toxics on and off.
 *   tsx src/cli.ts --upstream 127.0.0.1:PORT [--listen PORT]
 * Prints one JSON line {"port":N,"control":M}. Control (loopback only): POST /toxics {…partial Toxics}, POST /clear, POST /reset, GET /stats.
 */
import http from "node:http";
import { ChaosProxy } from "./proxy.js";

const arg = (n: string): string | undefined => {
  const i = process.argv.indexOf(`--${n}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
};
const up = arg("upstream");
if (!up) throw new Error("--upstream host:port is required");
const [host, port] = up.split(":") as [string, string];
const proxy = new ChaosProxy(host, Number(port));
const listen = await proxy.start(Number(arg("listen") ?? 0));

const control = http.createServer((req, res) => {
  let body = "";
  req.on("data", (b: Buffer) => (body += b.toString()));
  req.on("end", () => {
    const reply = (o: unknown): void => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(o));
    };
    if (req.method === "POST" && req.url === "/toxics")
      proxy.set(JSON.parse(body || "{}") as object);
    else if (req.method === "POST" && req.url === "/clear") proxy.clear();
    else if (req.method === "POST" && req.url === "/reset") proxy.resetAll();
    else if (!(req.method === "GET" && req.url === "/stats")) {
      res.writeHead(404);
      return void res.end();
    }
    reply({ toxics: proxy.current, stats: proxy.stats });
  });
});
await new Promise<void>((r) => control.listen(0, "127.0.0.1", r));
console.log(
  JSON.stringify({ port: listen, control: (control.address() as { port: number }).port }),
);
for (const sig of ["SIGINT", "SIGTERM"] as const)
  process.on(sig, () => void proxy.stop().then(() => process.exit(0)));
