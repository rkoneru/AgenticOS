"""Locate (or fetch) the Temporal time-skipping test server binary for integration tests.

Order: $AXIS_TEMPORAL_TEST_SERVER, then a cached copy, then a download from the Temporal Java SDK GitHub
release (the SDK's default host, temporal.download, is blocked in some sandboxes).  Failure to obtain
the binary FAILS the tests; they are never skipped.
"""

from __future__ import annotations

import os
import platform
import stat
import tarfile
import tempfile
import urllib.request
from pathlib import Path

VERSION = "1.24.1"
_ARCH = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
_OS = {"Linux": "linux", "Darwin": "darwin"}


def _url() -> str:
    os_name = _OS.get(platform.system())
    arch = _ARCH.get(platform.machine().lower())
    if os_name is None or arch is None:
        raise RuntimeError(
            f"no test-server build for {platform.system()}/{platform.machine()}; "
            "set AXIS_TEMPORAL_TEST_SERVER to a temporal-test-server binary"
        )
    return (
        "https://github.com/temporalio/sdk-java/releases/download/"
        f"v{VERSION}/temporal-test-server_{VERSION}_{os_name}_{arch}.tar.gz"
    )


def ensure_test_server() -> Path:
    override = os.environ.get("AXIS_TEMPORAL_TEST_SERVER")
    if override:
        path = Path(override)
        if not path.is_file():
            raise RuntimeError(f"AXIS_TEMPORAL_TEST_SERVER={override} does not exist")
        return path
    cache_root = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "axis"
    target = cache_root / f"temporal-test-server-{VERSION}"
    if target.is_file():
        return target
    cache_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / "server.tar.gz"
        with urllib.request.urlopen(_url(), timeout=120) as resp, archive.open("wb") as out:  # noqa: S310
            out.write(resp.read())
        with tarfile.open(archive) as tar:
            member = next(
                m
                for m in tar.getmembers()
                if m.isfile() and m.name.endswith("temporal-test-server")
            )
            extracted = tar.extractfile(member)
            assert extracted is not None
            target.write_bytes(extracted.read())
    target.chmod(target.stat().st_mode | stat.S_IXUSR)
    return target
