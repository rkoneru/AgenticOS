#!/usr/bin/env node
import { runCheck } from "./matrix/run.js";

process.exitCode = runCheck(
  process.argv.slice(2),
  { out: (l) => console.log(l), err: (l) => console.error(l) },
  process.env["AXIS_REPO_ROOT"] ?? process.cwd(),
);
