"""Throwaway PostgreSQL 16 clusters for the DR drill (initdb, start, kill -9, restore from a base backup + WAL archive)."""

from __future__ import annotations

import os
import shutil
import signal
import socket
import subprocess
import time
from pathlib import Path

BIN = Path(os.environ.get("PG_BIN", "/usr/lib/postgresql/16/bin"))


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _run_as_pg(args: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
    cmd = ["runuser", "-u", "postgres", "--", *args] if os.geteuid() == 0 else args
    r = subprocess.run(cmd, capture_output=True, text=True, check=False, **kw)  # type: ignore[call-overload]
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:3])} failed ({r.returncode}):\n{r.stdout}\n{r.stderr}")
    return r  # type: ignore[no-any-return]


class Cluster:
    def __init__(self, root: Path, name: str, *, archive_dir: Path | None = None) -> None:
        self.dir = root / name
        self.data = self.dir / "data"
        self.port = free_port()
        self.archive_dir = archive_dir
        self.log = self.dir / "log"

    @property
    def admin_url(self) -> str:
        return f"postgres://postgres@127.0.0.1:{self.port}/postgres"

    def url(self, db: str) -> str:
        return f"postgres://postgres@127.0.0.1:{self.port}/{db}"

    def _chown(self, p: Path) -> None:
        if os.geteuid() == 0:
            subprocess.run(["chown", "-R", "postgres:postgres", str(p)], check=True)

    def init(self) -> None:
        self.dir.mkdir(parents=True)
        self._chown(self.dir)
        _run_as_pg([str(BIN / "initdb"), "-D", str(self.data), "-U", "postgres", "--auth=trust"])
        conf = [
            "listen_addresses = '127.0.0.1'",
            f"port = {self.port}",
            f"unix_socket_directories = '{self.dir}'",
            "wal_level = replica",
            "max_wal_senders = 4",
            "fsync = on",
        ]
        if self.archive_dir is not None:
            self.archive_dir.mkdir(parents=True, exist_ok=True)
            self._chown(self.archive_dir)
            conf += [
                "archive_mode = on",
                f"archive_command = 'test ! -f {self.archive_dir}/%f && cp %p {self.archive_dir}/%f'",
                "archive_timeout = 2",  # the drill's WAL shipping cadence (the design target is 60 s, docs/runbooks/dr.md)
            ]
        with (self.data / "postgresql.conf").open("a") as f:
            f.write("\n" + "\n".join(conf) + "\n")

    def start(self) -> None:
        _run_as_pg([str(BIN / "pg_ctl"), "-D", str(self.data), "-w", "-l", str(self.log), "start"])

    def stop(self) -> None:
        if (self.data / "postmaster.pid").exists():
            subprocess.run(
                [
                    "runuser",
                    "-u",
                    "postgres",
                    "--",
                    str(BIN / "pg_ctl"),
                    "-D",
                    str(self.data),
                    "-m",
                    "immediate",
                    "stop",
                ]
                if os.geteuid() == 0
                else [str(BIN / "pg_ctl"), "-D", str(self.data), "-m", "immediate", "stop"],
                capture_output=True,
                check=False,
            )

    def crash(self) -> None:
        """kill -9 the postmaster (no shutdown checkpoint, no WAL flush beyond what was already fsynced), then DELETE the data directory."""
        pid = int((self.data / "postmaster.pid").read_text().splitlines()[0])
        os.kill(pid, signal.SIGKILL)
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                os.kill(pid, 0)
                time.sleep(0.1)
            except ProcessLookupError:
                break
        time.sleep(0.5)  # backends die with the postmaster
        shutil.rmtree(self.data)

    def psql(self, db: str, sql: str) -> str:
        r = _run_as_pg([str(BIN / "psql"), self.url(db), "-v", "ON_ERROR_STOP=1", "-tAc", sql])
        return r.stdout.strip()

    def psql_file(self, db: str, path: Path) -> None:
        _run_as_pg(
            [str(BIN / "psql"), self.url(db), "-v", "ON_ERROR_STOP=1", "-q", "-f", str(path)]
        )
