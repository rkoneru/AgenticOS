"""Helpers of the Phase 9 hardening e2e (``test_phase9_hardening.py``): signed Slack webhooks, raw-database scans, table snapshots.

Everything here only READS the stack's database (as the table owner, past RLS) or builds a request a provider would send; the code
under test is always reached through its real surface (the channels webhook, the public gateway API, the services' own classes).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
import unicodedata
from pathlib import Path
from typing import Any

import httpx
import interfaces_stack as istack

ROOT = Path(__file__).resolve().parent.parent


# ---- the database, read as the owner ----------------------------------------------------------------------------------------


def q(stack: istack.Stack, sql: str) -> str:
    return istack.psql(stack.db_url, sql).strip()


def tenant_tables(stack: istack.Stack) -> list[str]:
    out = q(
        stack,
        "SELECT table_name FROM information_schema.columns WHERE table_schema='public' AND column_name='tenant_id' "
        "GROUP BY 1 ORDER BY 1",
    )
    return [t for t in out.splitlines() if t]


def dump_tenant(stack: istack.Stack, tenant_id: str, *, skip: tuple[str, ...] = ()) -> str:
    """Every row of every tenant table as text, sorted per table: the byte-exact state of one tenant's data."""
    parts: list[str] = []
    for table in tenant_tables(stack):
        if table in skip:
            continue
        rows = q(
            stack, f"SELECT t::text FROM {table} t WHERE tenant_id = '{tenant_id}' ORDER BY 1"
        )
        parts.extend(f"{table}: {r}" for r in rows.splitlines() if r)
    return "\n".join(parts)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def count(stack: istack.Stack, table: str, tenant_id: str, where: str = "true") -> int:
    return int(q(stack, f"SELECT count(*) FROM {table} WHERE tenant_id = '{tenant_id}' AND {where}"))


# ---- PHI canaries ------------------------------------------------------------------------------------------------------------

# (text written through an ingress, the core that must not be recoverable afterwards): the same set as the TypeScript harness
# (services/data-governance/src/phi-canary.ts) and runtime/tests/test_phi_canary.py.
CANARIES: list[tuple[str, str]] = [
    ("patient ssn 123-45-6789 on file", "123456789"),
    ("ssn 234 56 7890 given verbally", "234567890"),
    ("ssn １３５-７９-２４６８ typed", "135792468"),
    ("ssn 246-80-13​57 pasted", "246801357"),
    ("ssn 357.91.2468 scanned", "357912468"),
    ("social security number 468013579", "468013579"),
    ("chart MRN: 99887766 reviewed", "99887766"),
    ("contact zelda.canary@clinic-example.org today", "zelda.canary@clinic-example.org"),
    ("mail zelda+rx@clinic-example.org", "zelda+rx@clinic-example.org"),
    ("call (415) 555-0134 after noon", "4155550134"),
    ("call +1 415 555 0177", "4155550177"),
]


def leaks(text: str, core: str) -> bool:
    """Is the canary core still recognisable in ``text`` after NFKC, format characters removed and digit separators ignored?"""
    t = "".join(
        c for c in unicodedata.normalize("NFKC", text) if unicodedata.category(c) != "Cf"
    ).lower()
    if not core.isdigit():
        return core.lower() in t
    return re.search(r"[\s.\-‐-―−()]*".join(core), t) is not None


def leaked(text: str) -> list[str]:
    return [core for _t, core in CANARIES if leaks(text, core)]


# ---- Slack webhooks ----------------------------------------------------------------------------------------------------------


def slack_post(
    route: dict[str, Any], user: str, text: str, *, event_id: str | None = None
) -> httpx.Response:
    """A genuine, correctly signed Slack Events API delivery to the channels webhook of the stack."""
    now = int(time.time())
    body = json.dumps(
        {
            "type": "event_callback",
            "team_id": route["team_id"],
            "api_app_id": route["api_app_id"],
            "event_id": event_id or f"Ev{secrets.token_hex(5)}",
            "event_time": now,
            "event": {
                "type": "message",
                "user": user,
                "text": text,
                "channel": "C9E2E",
                "ts": f"{now}.{secrets.randbelow(10**6):06d}",
            },
        }
    ).encode()
    stamp = str(now)
    sig = (
        "v0="
        + hmac.new(
            route["signing_secret"].encode(), f"v0:{stamp}:".encode() + body, hashlib.sha256
        ).hexdigest()
    )
    return httpx.post(
        f"{route['url']}/v1/channels/slack/inbound",
        content=body,
        headers={
            "content-type": "application/json",
            "x-slack-request-timestamp": stamp,
            "x-slack-signature": sig,
        },
        timeout=60,
    )


def stderr_logs(stack: istack.Stack) -> str:
    """Everything the stack's processes wrote to their error logs (their only log stream)."""
    return "\n".join(p.read_text(errors="replace") for p in sorted(stack.work.glob("*.err")))
