"""``make threatmodel-check``: the STRIDE threat models cite evidence that exists.

For every component in COMPONENTS there must be ``docs/security/stride-<component>.md`` with the required sections; its STRIDE table
must have at least one row for each of the six categories; every backticked repository path in the table (code path or test file,
optionally ``path:symbol`` or with ``*`` globs) must exist; every ``NEEDS #n`` must be a row of docs/NEEDS.md; every Test cell must
cite an existing test file or say ``none`` and then the residual cell must cite a NEEDS id. ``docs/security/README.md`` must index
every file. Exit 1 with one line per problem.
"""

from __future__ import annotations

import glob
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEC = ROOT / "docs" / "security"
COMPONENTS = [
    "risk-kernel",
    "audit",
    "control-plane",
    "api-gateway",
    "registry",
    "marketplace",
    "billing",
    "memory",
    "channels",
    "voice",
    "approvals",
    "eval-hub",
    "runtime",
    "sandbox",
    "browser",
    "mcp",
    "console",
    "cli-sdk",
]
SECTIONS = [
    "## Assets",
    "## Trust boundaries",
    "## Data flow",
    "## STRIDE",
    "## Prompt injection",
    "## Tool misuse",
]
CATEGORIES = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information disclosure",
    "Denial of service",
    "Elevation of privilege",
]
PATH_RE = re.compile(
    r"`([A-Za-z0-9_.@*/-]+/[A-Za-z0-9_.@*/-]+|[A-Za-z0-9_.-]+\.(?:py|ts|tsx|mjs|md|json|yaml|yml|sh|sql|proto))(?::[A-Za-z0-9_.:-]+)?`"
)
NEEDS_RE = re.compile(r"NEEDS\s+#(\d+)((?:\s*,\s*#?\d+)*)")


def needs_ids(root: Path = ROOT) -> set[int]:
    text = (root / "docs" / "NEEDS.md").read_text()
    return {int(m.group(1)) for m in re.finditer(r"^\|\s*(\d+)\s*\|", text, re.M)}


def path_exists(token: str, root: Path = ROOT) -> bool:
    if "*" in token:
        return bool(glob.glob(str(root / token), recursive=True))
    return (root / token).exists()


def table_rows(text: str) -> list[list[str]]:
    start = text.find("## STRIDE")
    if start < 0:
        return []
    block = text[start:]
    nxt = re.search(r"\n## (?!STRIDE)", block)
    block = block[: nxt.start()] if nxt else block
    rows = []
    for line in block.splitlines():
        if line.startswith("|") and not re.match(r"^\|[\s:|-]+\|$", line):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            rows.append(cells)
    return rows[1:] if rows else []  # drop the header row


def check_file(path: Path, ids: set[int], root: Path = ROOT) -> list[str]:
    name = path.name
    text = path.read_text()
    errs: list[str] = []
    for sec in SECTIONS:
        if sec not in text:
            errs.append(f"{name}: missing section '{sec}'")
    rows = table_rows(text)
    for cat in CATEGORIES:
        if not any(r and r[0].lower().startswith(cat.lower()) for r in rows):
            errs.append(f"{name}: STRIDE table has no {cat} row")
    for r in rows:
        if len(r) != 5:
            errs.append(
                f"{name}: STRIDE row needs 5 cells (category | threat | mitigation | test | residual): {r[:2]}"
            )
            continue
        _, threat, mitigation, test, residual = r
        if not PATH_RE.search(mitigation):
            errs.append(f"{name}: no code path in the mitigation of '{threat[:50]}'")
        tests = [m.group(1) for m in PATH_RE.finditer(test)]
        if not tests and test.strip().lower() != "none":
            errs.append(f"{name}: Test cell of '{threat[:50]}' cites no test file (or 'none')")
        if test.strip().lower() == "none" and not NEEDS_RE.search(residual):
            errs.append(f"{name}: '{threat[:50]}' has no test and no NEEDS reference")
    for m in PATH_RE.finditer(text):
        token = m.group(1)
        if not path_exists(token, root):
            errs.append(f"{name}: cited path does not exist: {token}")
    for m in NEEDS_RE.finditer(text):
        for n in [m.group(1), *re.findall(r"\d+", m.group(2) or "")]:
            if int(n) not in ids:
                errs.append(f"{name}: NEEDS #{n} is not a row of docs/NEEDS.md")
    return errs


def check(root: Path = ROOT, components: list[str] | None = None) -> list[str]:
    sec = root / "docs" / "security"
    ids = needs_ids(root)
    errs: list[str] = []
    for c in components or COMPONENTS:
        p = sec / f"stride-{c}.md"
        if not p.exists():
            errs.append(f"component '{c}' has no docs/security/stride-{c}.md")
            continue
        errs.extend(check_file(p, ids, root))
    readme = sec / "README.md"
    if not readme.exists():
        errs.append("docs/security/README.md (the index) is missing")
    else:
        body = readme.read_text()
        for c in components or COMPONENTS:
            if f"stride-{c}.md" not in body:
                errs.append(f"README.md does not index stride-{c}.md")
    return errs


def main() -> int:
    errs = check()
    for e in errs:
        print("FAIL", e, file=sys.stderr)
    if errs:
        print(f"threatmodel-check: {len(errs)} problem(s)", file=sys.stderr)
        return 1
    print(f"threatmodel-check: {len(COMPONENTS)} components, all citations exist")
    return 0


if __name__ == "__main__":
    sys.exit(main())
