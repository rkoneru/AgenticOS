import { ComplianceAudit } from "./audit.js";
import { DocumentService } from "./docgen/documents.js";
import type { SourcePorts } from "./docgen/ports.js";
import type { DocSealer } from "./docgen/seal.js";
import { makeCtx, type CtxOptions } from "./context.js";
import { AssessmentService } from "./records/assessments.js";
import { InventoryService } from "./records/inventory.js";

export interface ComplianceOptions extends CtxOptions {
  sources: SourcePorts;
  sealer: DocSealer;
  /** Retired seal keys whose documents still verify. */
  trustedSealers?: readonly DocSealer[];
}

export interface Compliance {
  systems: InventoryService;
  assessments: AssessmentService;
  documents: DocumentService;
}

export function createCompliance(o: ComplianceOptions): Compliance {
  const ctx = makeCtx(o);
  return {
    systems: new InventoryService(ctx),
    assessments: new AssessmentService(ctx),
    documents: new DocumentService(ctx, o.sources, o.sealer, o.trustedSealers ?? []),
  };
}

export { ComplianceAudit };
