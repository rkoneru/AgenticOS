// usage: node verify-chain-file.mjs <events.ndjson>  -> the reference verifier's verdict over an exported (possibly corrupted) copy
import { readFileSync } from "node:fs";
import { verifyChain } from "@axis/contracts";

const events = readFileSync(process.argv[2], "utf8")
  .split("\n")
  .filter(Boolean)
  .map((l) => JSON.parse(l));
// the export may start mid-chain: anchor on the first event's own prev_hash
console.log(
  JSON.stringify({ count: events.length, verdict: verifyChain(events.slice(1), events[0]) }),
);
