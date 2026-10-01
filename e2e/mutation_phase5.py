"""Mutation check for the Phase 5 wiring (run by hand: ``uv run python e2e/mutation_phase5.py``; needs PG like `make e2e-phase5`).

Each mutant breaks ONE safety property of the new wiring in the working tree, rebuilds the TS service if needed, runs the slice of
``test_phase5_channels.py`` that must notice, and requires a FAILURE of a real test (a stack that fails to start does not count).
Sources are restored afterwards. Exit code 0 only if every mutant was killed.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
E2E = "e2e/test_phase5_channels.py"


@dataclass(frozen=True)
class Mutant:
    name: str
    edits: tuple[tuple[str, str, str], ...]  # (file, old, new)
    tests: str  # pytest -k expression


MUTANTS = [
    Mutant(
        "outbound reply skips the gate (sent straight to the channels backend)",
        (
            (
                "runtime/src/axis_runtime/run.py",
                "        outcome = await self._act(MessageSend(name=REPLY_TOOL, args=args, channel=target.channel))\n",
                "        await self.ctx.backends.channels.send(target.channel, args)\n"
                '        self.ctx.reply = ReplyOutcome("sent")\n        return\n',
            ),
        ),
        "policy_deny or kill_switch or injection",
    ),
    Mutant(
        "the reply is not named channel.reply (policy no longer recognises it)",
        (
            (
                "runtime/src/axis_runtime/run.py",
                "MessageSend(name=REPLY_TOOL,",
                'MessageSend(name="reply",',
            ),
        ),
        "same_agent_answers",
    ),
    Mutant(
        "unverified inbound accepted (Slack signature not enforced)",
        (
            (
                "services/channels/src/adapters/slack.ts",
                '    if (sig === "bad") return reject("bad_signature", "signature does not verify", route);\n',
                "",
            ),
        ),
        "rejected or cross_tenant",
    ),
    Mutant(
        "replayed webhook accepted (idempotency claim skipped)",
        (
            (
                "services/channels/src/gateway.ts",
                "if (!(await this.d.idempotency.claim(idemKey, this.d.idempotencyTtlMs ?? 2 * DAY_MS))) {\n      await this.auditReplay",
                "if (false) {\n      await this.auditReplay",
            ),
        ),
        "replayed",
    ),
    Mutant(
        "tenant dropped from the inbox routing (one shared queue)",
        (
            (
                "services/channels/src/inbox.ts",
                "const q = this.queues.get(item.tenant_id) ?? [];",
                'const q = this.queues.get("shared") ?? [];',
            ),
            (
                "services/channels/src/inbox.ts",
                "this.queues.set(item.tenant_id, q);",
                'this.queues.set("shared", q);',
            ),
            (
                "services/channels/src/inbox.ts",
                "const q = this.queues.get(tenant);",
                'const q = this.queues.get("shared");',
            ),
        ),
        "cross_tenant",
    ),
    Mutant(
        "raw transcript stored in PHI mode (channels redaction off)",
        (
            (
                "services/channels/src/redact.ts",
                'if (phi || effective === "redacted_preview") t = redactPatterns(t);',
                "if (false) t = redactPatterns(t);",
            ),
        ),
        "phi_mode_redacts_the_transcript_before_persistence_on_a_channel",
    ),
    Mutant(
        "raw transcript persisted in PHI mode (voice)",
        (
            (
                "runtime/src/axis_runtime/voice/transcript.py",
                "        if not self.phi:\n            return text",
                "        if True:\n            return text",
            ),
        ),
        "voice_phi",
    ),
    Mutant(
        "voice transcript not mirrored into the audit chain",
        (
            (
                "runtime/src/axis_runtime/voice/transcript.py",
                "if self._audit is not None:  # first: no audit row, no transcript",
                "if False:",
            ),
        ),
        "voice_serves or one_agent_chat",
    ),
    Mutant(
        "conversation history not given to the agent (no continuity)",
        (
            (
                "runtime/src/axis_runtime/channel_runner.py",
                "history = await self._client.history(item.conversation_id)",
                "history = []",
            ),
        ),
        "linked_identity",
    ),
    Mutant(
        "outbound call country allowlist not enforced",
        (
            (
                "runtime/src/axis_runtime/voice/outbound.py",
                "        if not allowed:\n",
                "        if False:\n",
            ),
        ),
        "outbound",
    ),
    Mutant(
        "voice consent skipped when required",
        (
            (
                "runtime/src/axis_runtime/voice/session.py",
                "        if self._consent.mode is ConsentMode.NONE:",
                "        if True:",
            ),
        ),
        "consent_declined",
    ),
]


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)


def rebuild() -> None:
    out = run(["pnpm", "--filter", "@axis/channels", "build"])
    if out.returncode != 0:
        raise RuntimeError(f"build failed:\n{out.stdout}\n{out.stderr}")


def main() -> int:
    survived: list[str] = []
    for m in MUTANTS:
        originals: dict[str, str] = {}
        try:
            for rel, old, new in m.edits:
                path = ROOT / rel
                originals.setdefault(rel, path.read_text())
                text = path.read_text()
                if old not in text:
                    raise RuntimeError(f"{m.name}: pattern not found in {rel}")
                path.write_text(text.replace(old, new, 1))
            if any(rel.startswith("services/") for rel in originals):
                rebuild()
            out = run(
                [
                    "bash",
                    "infra/scripts/with-pg.sh",
                    "uv",
                    "run",
                    "pytest",
                    E2E,
                    "-p",
                    "no:cacheprovider",
                    "--no-cov",
                    "-q",
                    "-x",
                    "-k",
                    m.tests,
                ]
            )
            tail = (out.stdout + out.stderr).strip().splitlines()[-1]
            # killed = a test FAILED; an ERROR (the stack did not start) or no tests selected is not a kill
            killed = out.returncode != 0 and " failed" in tail and "error" not in tail
            print(f"{'KILLED  ' if killed else 'SURVIVED'} {m.name}  [{tail}]")
            if not killed:
                survived.append(m.name)
        finally:
            for rel, text in originals.items():
                (ROOT / rel).write_text(text)
            if any(rel.startswith("services/") for rel in originals):
                rebuild()
    print(f"\n{len(MUTANTS) - len(survived)}/{len(MUTANTS)} mutants killed")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
