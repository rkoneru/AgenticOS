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
    const stdin = process.stdin;
    if (!stdin.isTTY) {
      const rl = createInterface({ input: stdin, terminal: false });
      rl.once("line", (line) => {
        rl.close();
        resolve(line.trim());
      });
      rl.once("close", () => resolve(""));
      return;
    }
    // TTY: raw mode so the key is not echoed
    let buf = "";
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    const onData = (ch: string) => {
      for (const c of ch) {
        if (c === "\r" || c === "\n" || c === "\u0004") {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.off("data", onData);
          process.stderr.write("\n");
          resolve(buf.trim());
          return;
        }
        if (c === "\u0003") process.exit(130);
        buf = c === "\u007f" ? buf.slice(0, -1) : buf + c;
      }
    };
    stdin.on("data", onData);
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
