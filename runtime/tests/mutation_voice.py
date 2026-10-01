"""Mutation check for the voice safety logic (run by hand: ``uv run python runtime/tests/mutation_voice.py``).

Each mutation breaks one safety property in a copy of the source; the voice tests MUST fail.  The
source is restored afterwards.  Exit code 0 only if every mutant was killed.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "runtime/src/axis_runtime/voice"
TESTS = [
    "runtime/tests/test_voice_session.py",
    "runtime/tests/test_voice_compliance.py",
    "runtime/tests/test_voice_outbound.py",
    "runtime/tests/test_voice_edges.py",
]
MUTANTS = [
    (
        "consent skipped when required",
        "session.py",
        "        if self._consent.mode is ConsentMode.NONE:",
        "        if True:",
    ),
    (
        "unplayed consent notice accepted",
        "session.py",
        "await self._after_consent_notice(completed and bool(turn.sentences))",
        "await self._after_consent_notice(True)",
    ),
    (
        "consent timeout does not refuse",
        "session.py",
        '                await self._consent_refused("timeout", "consent_timeout")',
        "                pass",
    ),
    (
        "barge-in does not cancel the turn",
        "session.py",
        "        await self._cancel_turn(turn, record=True)\n        now = self._clock.now_ms()\n        latency",
        "        now = self._clock.now_ms()\n        latency",
    ),
    (
        "barge-in never triggers",
        "session.py",
        "        return len(words) >= cfg.min_words",
        "        return False",
    ),
    (
        "playout not flushed on cancel",
        "session.py",
        "            discarded = await self._transport.clear_output()",
        "            discarded = 0",
    ),
    ("PHI transcripts stored raw", "transcript.py", "        if not self.phi:", "        if True:"),
    (
        "PHI names not learned",
        "transcript.py",
        "        self._names.extend(n for n in learn_names(text) if n not in self._names)",
        "        pass",
    ),
    (
        "audio before consent processed",
        "session.py",
        "        if not self._audio_enabled or self._phase is _Phase.CLOSING:",
        "        if self._phase is _Phase.CLOSING:",
    ),
    (
        "outbound call skips the gate",
        "outbound.py",
        "            outcome = await self._runner.run(action, pid=self._pid)",
        '            outcome = Completed({"call_id": "x"}, None)  # type: ignore[arg-type]',
    ),
    (
        "outbound call skips the pre-gate limiter",
        "outbound.py",
        "            reservation = self._limiter.check_and_reserve(self._tenant, to)",
        "            reservation = Reservation(self._tenant, to, {})",
    ),
    (
        "country allow list not enforced",
        "outbound.py",
        "        if not allowed:\n            raise CallRefusedError",
        "        if False:\n            raise CallRefusedError",
    ),
    (
        "DTMF digits persisted raw",
        "session.py",
        'if input_kind == "dtmf" and not self.config.dtmf.persist_digits:',
        "if False:",
    ),
]


def main() -> int:
    survived: list[str] = []
    for name, fname, old, new in MUTANTS:
        path = SRC / fname
        original = path.read_text()
        if old not in original:
            print(f"STALE   {name}: pattern not found in {fname}")
            survived.append(name)
            continue
        path.write_text(original.replace(old, new, 1))
        try:
            proc = subprocess.run(  # noqa: S603
                ["uv", "run", "pytest", *TESTS, "-x", "-q", "--no-cov", "-p", "no:cacheprovider"],  # noqa: S607
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
        finally:
            path.write_text(original)
        killed = proc.returncode != 0
        print(f"{'KILLED ' if killed else 'SURVIVED'} {name}")
        if not killed:
            survived.append(name)
    print(f"{len(MUTANTS) - len(survived)}/{len(MUTANTS)} mutants killed")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
