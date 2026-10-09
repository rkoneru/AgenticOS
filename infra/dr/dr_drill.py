"""DR drill (Phase 9 D): populate a multi-tenant REAL stack, back it up two ways, DESTROY the database, restore into fresh Postgres clusters,
and verify what came back. Run with ``make dr-drill``. Writes infra/dr/results/dr-drill.{json,md}. Exit status 0 only when every positive
check passes AND every negative (tampered backup) is detected.

Backups
  logical   pg_dump (plain SQL) of the application database + pg_dumpall --globals-only (roles)
  physical  pg_basebackup + continuous WAL archiving (archive_timeout = 2 s in the drill; the design value is 60 s)
Restores
  A  logical  -> fresh cluster, exact point of the dump   (verify: chains, heads == pre-backup, checkpoints, RLS, row counts+hashes, seals, registry)
  B  physical -> fresh cluster, base backup + archived WAL replayed to the end of the archive (point-in-time recovery after a kill -9 + rm -rf)
  N1 a logical dump with ONE FLIPPED audit decision  -> must be detected (hash chain)
  N2 a logical dump with the audit TAIL removed       -> must be detected (signed checkpoint held outside the database)
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "e2e"))
sys.path.insert(0, str(HERE))
import interfaces_stack as istack  # noqa: E402
from pgcluster import BIN, Cluster, _run_as_pg  # noqa: E402

RESULTS = HERE / "results"


def yaml_json(path: str) -> Any:
    return json.loads(istack.sh(["node", "scripts/yaml-to-json.mjs", path], cwd=ROOT / "e2e"))


PACK = yaml_json("policies/phase7-interfaces/pack.yaml")
CLAIMS = yaml_json("agents/claims7.abl.yaml")
HELPER = yaml_json("agents/helper7.abl.yaml")
CLI = ["node", str(ROOT / "apps/cli/dist/bin.js")]


def dr_ops(cmd: str, args: dict[str, Any]) -> Any:
    out = istack.sh(["node", "scripts/dr-ops.mjs", cmd, json.dumps(args)], cwd=ROOT / "e2e")
    return json.loads(out.strip().splitlines()[-1])


class Tenant:
    def __init__(self, st: istack.Stack, slug: str) -> None:
        self.st = st
        t = st.provision(slug, pack=PACK)
        self.id: str = t["tenant_id"]
        self.key = st.api_key(t["tenant_id"], t["owner_member_id"])
        self.ref: str | None = None

    def api(self, method: str, path: str, **kw: Any) -> httpx.Response:
        return httpx.request(
            method,
            self.st.gateway + path,
            headers={"authorization": f"Bearer {self.key}"},
            timeout=60,
            **kw,
        )

    def run(self, prompt: str) -> str:
        r = self.api(
            "POST",
            "/runs",
            json={
                "blueprint": {"name": "claims-agent", "version": "1.0.0"},
                "input": {"prompt": prompt},
            },
        )
        assert r.status_code == 202, r.text
        rid = str(r.json()["id"])
        deadline = time.time() + 60
        while time.time() < deadline:
            g = self.api("GET", f"/runs/{rid}").json()
            if g["state"] == "terminated":
                return rid
            time.sleep(0.1)
        raise AssertionError("run did not terminate")

    def publish_to_registry(self, work: Path) -> None:
        env = {
            **os.environ,
            "AXIS_API_KEY": self.key,
            "AXIS_BASE_URL": self.st.gateway,
            "XDG_CONFIG_HOME": str(work / f"cfg-{self.id[:6]}"),
            "NO_COLOR": "1",
        }
        ns = f"dr-{secrets.token_hex(3)}"
        pem = work / f"{ns}.pem"

        def cli(*a: str) -> str:
            return subprocess.run(
                [*CLI, "--json", *a], env=env, capture_output=True, text=True, check=True
            ).stdout

        kg = json.loads(cli("registry", "keygen", "--out", str(pem)))
        cli("registry", "claim", ns)
        cli("registry", "add-key", ns, f"--public-key={kg['public_key']}")
        time.sleep(1.2)
        f = work / f"{ns}.json"
        f.write_text(json.dumps(HELPER))
        signed = json.loads(
            subprocess.run(
                [*CLI, "registry", "sign", str(f), "--namespace", ns, "--key", str(pem)],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            ).stdout
        )
        b = work / f"{ns}-bundle.json"
        b.write_text(json.dumps({"namespace": ns, **signed}))
        cli("registry", "publish", str(b))
        self.ref = f"{ns}/helper-agent@^1"


def pg_dump(cluster: Cluster, db: str, out: Path) -> None:
    with out.open("w") as f:
        subprocess.run([str(BIN / "pg_dump"), "-Fp", "-d", cluster.url(db)], stdout=f, check=True)


def restore_logical(globals_sql: Path, dump: Path, target: Cluster, db: str) -> float:
    t0 = time.time()
    clean = [
        ln for ln in globals_sql.read_text().splitlines() if not re.search(r"\bROLE postgres\b", ln)
    ]
    g = target.dir / "globals.sql"
    g.write_text("\n".join(clean) + "\n")
    target._chown(target.dir)
    target.psql_file("postgres", g)
    target.psql("postgres", f"CREATE DATABASE {db}")
    dump_copy = target.dir / "restore.sql"
    shutil.copy(dump, dump_copy)
    target._chown(target.dir)
    target.psql_file(db, dump_copy)
    return time.time() - t0


def main() -> int:  # noqa: C901, PLR0915 - one linear scenario, read top to bottom
    work = Path(tempfile.mkdtemp(prefix="axis-dr-"))
    work.chmod(0o755)  # the postgres OS user must traverse it
    archive = work / "wal-archive"
    src = Cluster(work, "src", archive_dir=archive)
    src.init()
    src.start()
    report: dict[str, Any] = {
        "started": datetime.now(UTC).isoformat(),
        "steps": {},
        "machine": os.uname().machine,
    }
    positives: list[dict[str, Any]] = []
    failures: list[str] = []
    clusters = [src]
    try:
        # ---- populate -----------------------------------------------------------------------------------------------------
        with (
            istack.boot(work / "stack", src.admin_url)
            if (work / "stack").mkdir() is None
            else None as st
        ):  # type: ignore[attr-defined]
            db_name = st.db_url.rsplit("/", 1)[1]
            tenants = [Tenant(st, f"dr{i}{secrets.token_hex(2)}") for i in range(3)]
            ids = [t.id for t in tenants]
            for t in tenants:
                assert t.api("POST", "/blueprints", json={"abl": CLAIMS}).status_code in (200, 201)
            for t in tenants:
                for i in range(3):
                    t.run(f"hello {i}")
                t.run("restricted 7")
                t.api(
                    "POST",
                    "/evals/datasets",
                    json={
                        "name": "dr-cases",
                        "cases": [
                            {
                                "id": "c1",
                                "input": "status of claim 1",
                                "expected": {"contains": ["claim"]},
                            }
                        ],
                    },
                )
            tenants[0].publish_to_registry(work)
            period = "2026-08"  # an ENDED month: only an ended period can be sealed
            periods: dict[str, str] = {}
            for t in tenants:
                st.ops("billing/seal-past-period", tenant_id=t.id, period=period)
                periods[t.id] = period
            anchor = (
                work / "anchor.json"
            )  # the tamper-evidence anchor: signed checkpoints + the public key, held OUTSIDE the database
            dr_ops("seed", {"db_url": st.db_url, "tenants": ids, "out": str(anchor)})
            manifest_path = work / "manifest.json"
            time.sleep(1.0)
            dr_ops("manifest", {"db_url": st.db_url, "tenants": ids, "out": str(manifest_path)})
            refs = {tenants[0].id: tenants[0].ref}

            # ---- backups --------------------------------------------------------------------------------------------------
            t0 = time.time()
            logical = work / "logical.sql"
            globals_sql = work / "globals.sql"
            pg_dump(src, db_name, logical)
            with globals_sql.open("w") as f:
                subprocess.run(
                    [
                        str(BIN / "pg_dumpall"),
                        "--globals-only",
                        "--no-role-passwords",
                        "-h",
                        "127.0.0.1",
                        "-p",
                        str(src.port),
                        "-U",
                        "postgres",
                    ],
                    stdout=f,
                    check=True,
                )
            report["steps"]["logical_backup_seconds"] = round(time.time() - t0, 2)
            t0 = time.time()
            base = work / "basebackup"
            _run_as_pg(
                [
                    str(BIN / "pg_basebackup"),
                    "-h",
                    "127.0.0.1",
                    "-p",
                    str(src.port),
                    "-U",
                    "postgres",
                    "-D",
                    str(base),
                    "-X",
                    "fetch",
                    "-c",
                    "fast",
                ]
            ) if False else None
            src._chown(work)
            _run_as_pg(
                [
                    str(BIN / "pg_basebackup"),
                    "-h",
                    "127.0.0.1",
                    "-p",
                    str(src.port),
                    "-U",
                    "postgres",
                    "-D",
                    str(base),
                    "-X",
                    "fetch",
                    "-c",
                    "fast",
                ]
            )
            report["steps"]["physical_backup_seconds"] = round(time.time() - t0, 2)
            report["steps"]["logical_dump_bytes"] = logical.stat().st_size
            report["steps"]["basebackup_bytes"] = sum(
                f.stat().st_size for f in base.rglob("*") if f.is_file()
            )

            # ---- writes AFTER the backup (they exist only in the WAL archive), then the disaster -------------------------------
            for t in tenants:
                for i in range(4):
                    t.run(f"hello post-backup {i}")
            crash_heads = {
                t: h
                for t, h in dr_ops("manifest", {"db_url": st.db_url, "tenants": ids})[
                    "heads"
                ].items()
            }
            ts_rows = src.psql(db_name, "SELECT max(ts) FROM audit_events")
            last_row_ts = (
                datetime.fromisoformat(ts_rows.replace(" ", "T")).astimezone(UTC)
                if "+" in ts_rows or "Z" in ts_rows
                else datetime.fromisoformat(ts_rows.replace(" ", "T") + "+00:00")
            )
            crash_at = datetime.now(UTC)
            report["steps"]["seconds_between_last_committed_audit_row_and_crash"] = round(
                (crash_at - last_row_ts).total_seconds(), 2
            )
            seal_key = st.seal_key
        # stack stopped (context exit). THE DISASTER: kill -9 the database server and delete its data directory.
        # (the stack's own shutdown wrote nothing more: its processes were only stopped)
        src.crash()
        report["steps"]["disaster"] = (
            "postmaster killed with SIGKILL and the data directory deleted"
        )

        def verify(c: Cluster, mode: str) -> dict[str, Any]:
            return dr_ops(
                "verify",
                {
                    "db_url": c.url(db_name),
                    "manifest": str(manifest_path),
                    "anchor": str(anchor),
                    "seal_key": seal_key,
                    "refs": refs,
                    "periods": periods,
                    "mode": mode,
                },
            )

        # ---- restore A: logical ---------------------------------------------------------------------------------------------
        a = Cluster(work, "restoreA")
        a.init()
        a.start()
        clusters.append(a)
        t_start = time.time()
        restore_logical(globals_sql, logical, a, db_name)
        va = verify(a, "exact")
        rto_logical = time.time() - t_start
        report["steps"]["restore_logical"] = {
            "rto_seconds": round(rto_logical, 2),
            "checks": va["checks"],
            "ok": va["ok"],
        }
        positives.append({"name": "logical restore verifies", "ok": va["ok"]})

        # ---- restore B: physical + WAL (PITR) ------------------------------------------------------------------------------
        b = Cluster(work, "restoreB")
        t_start = time.time()
        b.dir.mkdir(parents=True)
        shutil.copytree(base, b.data)
        b._chown(b.dir)
        (b.data / "recovery.signal").write_text("")
        with (b.data / "postgresql.conf").open("a") as f:
            f.write(
                f"\nport = {b.port}\nunix_socket_directories = '{b.dir}'\narchive_mode = off\nrestore_command = 'cp {archive}/%f %p'\nrecovery_target_action = 'promote'\n"
            )
        b._chown(b.dir)
        b.start()
        clusters.append(b)
        deadline = time.time() + 120
        while time.time() < deadline and b.psql("postgres", "SELECT pg_is_in_recovery()") != "f":
            time.sleep(0.2)
        vb = verify(b, "atleast")
        rto_physical = time.time() - t_start
        heads_after = dr_ops("manifest", {"db_url": b.url(db_name), "tenants": ids})["heads"]
        lost = {t: crash_heads[t]["seq"] - heads_after[t]["seq"] for t in ids}
        last_restored = b.psql(db_name, "SELECT max(ts) FROM audit_events")
        report["steps"]["restore_physical"] = {
            "rto_seconds": round(rto_physical, 2),
            "checks": vb["checks"],
            "ok": vb["ok"],
            "audit_events_lost_per_tenant": lost,
            "last_restored_audit_ts": last_restored,
            "last_committed_audit_ts_before_crash": ts_rows,
        }
        positives.append({"name": "physical restore verifies", "ok": vb["ok"]})
        # RPO = how much acknowledged data the restore did not bring back, as a time window
        lost_total = sum(lost.values())
        window = 0.0
        if lost_total:

            def epoch(x: str) -> float:
                return datetime.fromisoformat(x.replace(" ", "T")).timestamp()

            window = round(epoch(ts_rows) - epoch(last_restored), 2)
        report["steps"]["measured_rpo"] = {
            "lost_audit_events": lost_total,
            "window_seconds": window,
        }

        # ---- negatives: a tampered backup must be DETECTED ------------------------------------------------------------------
        n = Cluster(work, "restoreN")
        n.init()
        n.start()
        clusters.append(n)
        text = logical.read_text()
        m = re.search(
            r"^COPY public\.audit_events \((.*?)\) FROM stdin;\n(.*?)^\\\.\n", text, re.S | re.M
        )
        assert m, "no audit_events COPY block in the dump"
        cols = [c.strip() for c in m.group(1).split(",")]
        rows = m.group(2).splitlines()
        di, ti, si = cols.index("decision"), cols.index("tenant_id"), cols.index("seq")
        # N1: flip one decision in the middle of tenant 0's chain
        mine = [i for i, r in enumerate(rows) if r.split("\t")[ti] == ids[0]]
        victim = mine[len(mine) // 2]
        parts = rows[victim].split("\t")
        parts[di] = "ALLOW" if parts[di] != "ALLOW" else "DENY"
        flipped = list(rows)
        flipped[victim] = "\t".join(parts)
        d1 = work / "tampered-flip.sql"
        d1.write_text(text.replace(m.group(2), "\n".join(flipped) + "\n"))
        # N2: remove tenant 1's last audit row (the head the signed checkpoint pins)
        t1 = [i for i, r in enumerate(rows) if r.split("\t")[ti] == ids[1]]
        tail = max(t1, key=lambda i: int(rows[i].split("\t")[si]))
        d2 = work / "tampered-truncate.sql"
        d2.write_text(
            text.replace(m.group(2), "\n".join(r for i, r in enumerate(rows) if i != tail) + "\n")
        )
        negatives = []
        for label, dump, db, expect in (
            ("flipped decision", d1, "dr_tamper_flip", "audit chain verifies"),
            ("truncated tail", d2, "dr_tamper_trunc", "signed checkpoint"),
        ):
            restore_logical(
                globals_sql, dump, n, db
            ) if label == "flipped decision" else _restore_db_only(n, dump, db)
            v = dr_ops(
                "verify",
                {
                    "db_url": n.url(db),
                    "manifest": str(manifest_path),
                    "anchor": str(anchor),
                    "seal_key": seal_key,
                    "refs": refs,
                    "periods": periods,
                    "mode": "exact",
                },
            )
            failed = [c for c in v["checks"] if not c["ok"]]
            detected = any(expect in c["name"] for c in failed)
            negatives.append(
                {
                    "tamper": label,
                    "detected": detected,
                    "failed_checks": [c["name"] for c in failed][:6],
                }
            )
        report["steps"]["negatives"] = negatives
        report["measured"] = {
            "rpo_window_seconds": report["steps"]["measured_rpo"]["window_seconds"],
            "rto_logical_seconds": round(rto_logical, 2),
            "rto_physical_seconds": round(rto_physical, 2),
        }
        for p in positives:
            if not p["ok"]:
                failures.append(p["name"])
        for x in negatives:
            if not x["detected"]:
                failures.append(f"UNDETECTED tamper: {x['tamper']}")
        for stepname in ("restore_logical", "restore_physical"):
            for c in report["steps"][stepname]["checks"]:
                if not c["ok"]:
                    failures.append(f"{stepname}: {c['name']}: {c['detail']}")
    except BaseException as exc:
        failures.append(f"drill aborted: {type(exc).__name__}: {exc}")
        raise
    finally:
        for c in clusters:
            c.stop()
        report["failures"] = failures
        RESULTS.mkdir(exist_ok=True)
        (RESULTS / "dr-drill.json").write_text(json.dumps(report, indent=2, default=str))
        (RESULTS / "dr-drill.md").write_text(render(report))
        print(render(report))
        shutil.rmtree(work, ignore_errors=True)
    return 1 if failures else 0


def _restore_db_only(c: Cluster, dump: Path, db: str) -> None:
    c.psql("postgres", f"CREATE DATABASE {db}")
    cp = c.dir / "restore2.sql"
    shutil.copy(dump, cp)
    c._chown(c.dir)
    c.psql_file(db, cp)


def render(r: dict[str, Any]) -> str:
    s = r["steps"]
    lines = [
        "# DR drill result",
        "",
        f"Started {r['started']} on {r.get('machine')}. One small machine; clusters are local throwaways.",
        "",
    ]
    for k in (
        "logical_backup_seconds",
        "physical_backup_seconds",
        "logical_dump_bytes",
        "basebackup_bytes",
        "seconds_between_last_committed_audit_row_and_crash",
    ):
        if k in s:
            lines.append(f"- {k}: {s[k]}")
    if "measured" in r:
        lines += ["", "## Measured", "", json.dumps(r["measured"]), ""]
    for name in ("restore_logical", "restore_physical"):
        if name in s:
            lines += [f"## {name} (rto {s[name]['rto_seconds']} s, ok={s[name]['ok']})", ""]
            lines += [
                f"- {'PASS' if c['ok'] else 'FAIL'} {c['name']} {'' if c['ok'] else c['detail']}"
                for c in s[name]["checks"]
            ]
            lines.append("")
    if "negatives" in s:
        lines += ["## Tampered backups", ""] + [
            f"- {x['tamper']}: {'DETECTED' if x['detected'] else 'NOT DETECTED'} ({x['failed_checks']})"
            for x in s["negatives"]
        ]
    lines += ["", f"Failures: {r['failures'] or 'none'}"]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
