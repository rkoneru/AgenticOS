// usage: node yaml-to-json.mjs <file.yaml>  -> the document as JSON (policy packs are published to the control plane as JSON)
import { readFileSync } from "node:fs";
import { parse } from "yaml";

console.log(JSON.stringify(parse(readFileSync(process.argv[2], "utf8"))));
