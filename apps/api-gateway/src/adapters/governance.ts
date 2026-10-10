import { PortUnavailable, type GovernancePort } from "../ports.js";

/** Fail-closed stand-in for a gateway wired without the governance kit: every operation is a 503, never an empty success. */
export class UnavailableGovernance implements GovernancePort {
  private fail(): never {
    throw new PortUnavailable("the data-governance service is not configured on this gateway");
  }
  listDsarRequests = () => this.fail();
  createDsarRequest = () => this.fail();
  getDsarRequest = () => this.fail();
  verifyDsarRequest = () => this.fail();
  exportDsarRequest = () => this.fail();
  eraseDsarRequest = () => this.fail();
  restrictDsarRequest = () => this.fail();
  listHolds = () => this.fail();
  placeHold = () => this.fail();
  releaseHold = () => this.fail();
  getRetention = () => this.fail();
  setRetention = () => this.fail();
  listRetentionRuns = () => this.fail();
  runRetention = () => this.fail();
  getResidency = () => this.fail();
}
