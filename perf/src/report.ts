import os from "node:os";
import type { LoadResult } from "./openload.js";

export type Verdict = "Met" | "Not met" | "Not measured";

export interface Check {
  /** NFR id, e.g. "gate.grpc.p99" */
  id: string;
  title: string;
  /** the target as written in the master prompt / docs/nfr.md */
  target: string;
  /** the measured value with its unit, or null when this run did not measure it */
  measured: number | null;
  unit: string;
  /** lower is better ("max") or higher is better ("min") */
  bound: "max" | "min";
  limit: number;
  verdict: Verdict;
  note?: string;
}

/** Verdict from evidence only: no measurement means "Not measured", never "Met". */
export function judge(measured: number | null, bound: "max" | "min", limit: number): Verdict {
  if (measured === null || Number.isNaN(measured)) return "Not measured";
  return (bound === "max" ? measured <= limit : measured >= limit) ? "Met" : "Not met";
}

export function check(c: Omit<Check, "verdict"> & { verdict?: Verdict }): Check {
  return { ...c, verdict: judge(c.measured, c.bound, c.limit) };
}

export interface Machine {
  platform: string;
  release: string;
  arch: string;
  cpuModel: string;
  cpus: number;
  memGiB: number;
  node: string;
  note: string;
}

export function machine(): Machine {
  const cpus = os.cpus();
  return {
    platform: os.platform(),
    release: os.release(),
    arch: os.arch(),
    cpuModel: cpus[0]?.model ?? "unknown",
    cpus: cpus.length,
    memGiB: Math.round((os.totalmem() / 2 ** 30) * 10) / 10,
    node: process.version,
    note: "load generator, gateway, kernel, run service, control plane and Postgres all share this one machine",
  };
}

export interface ScenarioReport {
  name: string;
  description: string;
  result: LoadResult;
}

export interface Report {
  generatedAt: string;
  profile: string;
  machine: Machine;
  scenarios: ScenarioReport[];
  extra: Record<string, unknown>;
  checks: Check[];
}

const ms = (us: number): string => (us / 1000).toFixed(us < 10_000 ? 3 : 1);

export function renderMarkdown(r: Report): string {
  const m = r.machine;
  const out: string[] = [
    `# Load test report (${r.profile})`,
    "",
    `Generated ${r.generatedAt}. **Machine:** ${m.cpus} x ${m.cpuModel}, ${m.memGiB} GiB RAM, ${m.platform} ${m.release} ${m.arch}, Node ${m.node}. ${m.note}.`,
    "",
    "Latencies are milliseconds from the INTENDED start of each request (open model, coordinated-omission aware); `svc p99` is from the actual send.",
    "",
    "| scenario | rate/s | ok | errors | achieved/s | p50 | p95 | p99 | p99.9 | max | svc p99 | gen lag max |",
    "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
  ];
  for (const s of r.scenarios) {
    const x = s.result;
    out.push(
      `| ${s.name} | ${x.rate} | ${x.ok} | ${x.errors} | ${x.achievedRate} | ${ms(x.latency.p50)} | ${ms(x.latency.p95)} | ${ms(x.latency.p99)} | ${ms(x.latency.p999)} | ${ms(x.latency.max)} | ${ms(x.service.p99)} | ${x.maxGeneratorLagMs} ms |`,
    );
  }
  const errs = r.scenarios.filter((s) => s.result.errors > 0);
  if (errs.length > 0) {
    out.push("", "## Errors", "");
    for (const s of errs) out.push(`- ${s.name}: ${JSON.stringify(s.result.errorsByLabel)}`);
  }
  out.push(
    "",
    "## NFR checks",
    "",
    "| id | target | measured | verdict | note |",
    "| --- | --- | ---: | --- | --- |",
  );
  for (const c of r.checks) {
    out.push(
      `| ${c.id} | ${c.target} | ${c.measured === null ? "-" : `${c.measured} ${c.unit}`} | **${c.verdict}** | ${c.note ?? ""} |`,
    );
  }
  if (Object.keys(r.extra).length > 0) {
    out.push("", "## Other measurements", "", "```json", JSON.stringify(r.extra, null, 2), "```");
  }
  return out.join("\n") + "\n";
}
