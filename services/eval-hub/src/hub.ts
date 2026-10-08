import { BaselineService } from "./baselines.js";
import { DatasetService, SuiteService } from "./catalog.js";
import { makeCtx, type CtxOptions } from "./context.js";
import { GateService, HubGatePort } from "./gate.js";
import { OnlineService } from "./online.js";
import { ReviewService } from "./reviews.js";
import { RunService } from "./runs.js";
import type { AttestationSink, HubSigningKey } from "./attest.js";

export interface HubOptions extends CtxOptions {
  /** Signs the attestation of every finished run (Ed25519). Without it no attestation is produced. */
  signing?: HubSigningKey;
  /** Receives each signed attestation (the registry). */
  sink?: AttestationSink;
}

export interface EvalHub {
  datasets: DatasetService;
  suites: SuiteService;
  runs: RunService;
  baselines: BaselineService;
  gate: GateService;
  /** The registry/marketplace-facing port (`new RegistryService({ evalGate: hub.gatePort })`). */
  gatePort: HubGatePort;
  reviews: ReviewService;
  online: OnlineService;
}

export function createEvalHub(o: HubOptions): EvalHub {
  const ctx = makeCtx(o);
  const runs = new RunService(ctx, {
    ...(o.signing ? { signing: o.signing } : {}),
    ...(o.sink ? { sink: o.sink } : {}),
  });
  const baselines = new BaselineService(ctx);
  const gate = new GateService(ctx, runs, baselines);
  return {
    datasets: new DatasetService(ctx),
    suites: new SuiteService(ctx),
    runs,
    baselines,
    gate,
    gatePort: new HubGatePort(gate, baselines),
    reviews: new ReviewService(ctx, runs),
    online: new OnlineService(ctx, runs),
  };
}
