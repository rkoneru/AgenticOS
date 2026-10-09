"""API-level privilege-escalation probes of the red-team campaign (Phase 9 / C): what a second tenant, a forged credential or a
narrow key can do against the REAL gateway. Each probe is a verdict in the same shape as an attack case of the corpus
(id ``rt-px-p..``, category ``privilege-escalation``), with a mechanical SAFE outcome stated in its ``expect``."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx


def _v(pid: str, technique: str, ok: bool, why: str) -> dict[str, Any]:
    return {
        "id": pid,
        "category": "privilege-escalation",
        "severity": "critical",
        "technique": technique,
        "goal": "cross-tenant",
        "known_open": None,
        "safe": ok,
        "reasons": [] if ok else [why],
        "evidence": {},
    }


def run_probes(
    gateway: str,
    *,
    key_a: str,
    key_b: str,
    narrow_a: str,
    tenant_a: str,
    tenant_b: str,
    run_id_a: str,
    suite_ref: str,
    dataset: tuple[str, int],
) -> list[dict[str, Any]]:
    ha, hb = {"x-axis-api-key": key_a}, {"x-axis-api-key": key_b}
    out: list[dict[str, Any]] = []

    def get(path: str, headers: dict[str, str], **kw: Any) -> httpx.Response:
        return httpx.get(f"{gateway}{path}", headers=headers, timeout=60, **kw)

    def probe(pid: str, technique: str, fn: Callable[[], tuple[bool, str]]) -> None:
        try:
            ok, why = fn()
        except Exception as exc:  # noqa: BLE001 - a probe that cannot run is a failure, never a pass
            ok, why = False, f"probe crashed: {type(exc).__name__}"
        out.append(_v(pid, technique, ok, why))

    refused = (400, 401, 403, 404, 422)
    probe(
        "rt-px-p01",
        "b-reads-a-eval-run",
        lambda: (
            (r := get(f"/evals/runs/{run_id_a}", hb)).status_code in refused
            and run_id_a not in r.text,
            "tenant B read tenant A's eval run",
        ),
    )
    probe(
        "rt-px-p02",
        "b-reads-a-dataset",
        lambda: (
            get(f"/evals/datasets/{dataset[0]}/versions/{dataset[1]}", hb).status_code in refused,
            "tenant B read tenant A's dataset",
        ),
    )
    probe(
        "rt-px-p03",
        "b-reads-a-suite",
        lambda: (
            get(f"/evals/suites/{suite_ref}", hb).status_code in refused,
            "tenant B read tenant A's suite",
        ),
    )

    def audit() -> tuple[bool, str]:
        r = get("/audit/events?limit=200", hb)
        seen = (
            {e["tenant_id"] for e in r.json().get("items", [])} if r.status_code == 200 else set()
        )
        return seen <= {tenant_b}, "tenant B's audit listing held another tenant's rows"

    probe("rt-px-p04", "b-reads-a-audit", audit)
    probe(
        "rt-px-p05",
        "tenant-in-query",
        lambda: (
            get("/runs", hb, params={"tenant_id": tenant_a}).status_code in (400, 422),
            "a tenant id in the query was honoured",
        ),
    )
    probe(
        "rt-px-p06",
        "tenant-in-header",
        lambda: (
            get("/runs", {**hb, "x-tenant-id": tenant_a}).status_code in (400, 422),
            "a tenant header was honoured",
        ),
    )

    def start_foreign() -> tuple[bool, str]:
        r = httpx.post(
            f"{gateway}/evals/runs",
            headers=hb,
            json={"suite": suite_ref, "blueprint": "nobody/redteam-agent@1.0.0"},
            timeout=60,
        )
        return r.status_code in refused, "tenant B queued a run of tenant A's suite"

    probe("rt-px-p07", "b-starts-a-suite", start_foreign)
    probe(
        "rt-px-p08",
        "forged-key",
        lambda: (
            get("/me", {"x-axis-api-key": "axk_" + "0" * 40}).status_code == 401,
            "a forged key was accepted",
        ),
    )
    probe(
        "rt-px-p09",
        "global-kill-switch-by-tenant",
        lambda: (
            httpx.put(
                f"{gateway}/kill-switches",
                headers=ha,
                json={"scope": "global", "engaged": True},
                timeout=60,
            ).status_code
            in refused,
            "a tenant key engaged a GLOBAL kill-switch",
        ),
    )

    def narrow_kill() -> tuple[bool, str]:
        r = httpx.put(
            f"{gateway}/kill-switches",
            headers={"x-axis-api-key": narrow_a},
            json={"scope": "tenant", "engaged": False, "reason": "narrow key release attempt"},
            timeout=60,
        )
        return r.status_code in (401, 403), "a read-only key changed a kill-switch"

    probe("rt-px-p10", "narrow-key-releases-kill-switch", narrow_kill)

    def b_agent_switch() -> tuple[bool, str]:
        put = httpx.put(
            f"{gateway}/kill-switches",
            headers=hb,
            json={
                "scope": "agent",
                "target": "redteam-agent",
                "engaged": True,
                "reason": "B drill",
            },
            timeout=60,
        )
        a_sees = get("/kill-switches", ha).json().get("items", [])
        httpx.put(
            f"{gateway}/kill-switches",
            headers=hb,
            json={"scope": "agent", "target": "redteam-agent", "engaged": False},
            timeout=60,
        )
        return (
            put.status_code == 200 and not a_sees,
            "tenant B's agent kill-switch is visible to or affects tenant A",
        )

    probe("rt-px-p11", "b-switch-leaks-to-a", b_agent_switch)
    return out
