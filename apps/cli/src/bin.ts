#!/usr/bin/env node
import { createInterface } from "node:readline";
import { run } from "./main.js";

/* v8 ignore start -- process entry point (spawn-tested in test/bin.test.ts) */
async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(Buffer.from(c as Uint8Array));
  return Buffer.concat(chunks).toString("utf8");
}

function readSecret(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    process.stderr.write(prompt);
    const rl = createInterface({ input: process.stdin, terminal: false });
    rl.once("line", (line) => {
      rl.close();
      resolve(line.trim());
    });
    rl.once("close", () => resolve(""));
  });
}

process.exitCode = await run(process.argv.slice(2), {
  stdout: (s) => void process.stdout.write(s),
  stderr: (s) => void process.stderr.write(s),
  env: process.env,
  readStdin,
  readSecret,
  isTTY: process.stdout.isTTY,
});
/* v8 ignore stop */
