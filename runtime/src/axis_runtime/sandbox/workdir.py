"""Per-run working directory: created private, handed to the sandbox user, wiped afterwards."""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
from dataclasses import dataclass

PREFIX = "axis-sbx-"


@dataclass(frozen=True)
class Workdir:
    root: str
    out: str
    base: str

    @classmethod
    def create(cls, base: str | None, owner: tuple[int, int] | None) -> Workdir:
        """``owner`` = (uid, gid) the sandbox runs as, or None when it runs as the caller."""
        parent = base or tempfile.gettempdir()
        root = tempfile.mkdtemp(prefix=PREFIX, dir=parent)  # mode 0700
        out = os.path.join(root, "out")
        os.mkdir(out, 0o700)
        if owner is not None:
            for p in (root, out):
                os.chown(p, owner[0], owner[1])
        return cls(root=root, out=out, base=parent)

    def write_code(self, name: str, data: bytes, owner: tuple[int, int] | None) -> str:
        path = os.path.join(self.root, name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        if owner is not None:
            os.chown(path, owner[0], owner[1])
        return path

    def wipe(self) -> None:
        """Remove the directory and everything the (untrusted) code left in it."""
        real = os.path.realpath(self.root)
        if not os.path.basename(real).startswith(PREFIX) or os.path.dirname(real) != (
            os.path.realpath(self.base)
        ):
            raise RuntimeError("refusing to wipe a directory that is not a sandbox workdir")
        shutil.rmtree(real, onerror=_force)
        if os.path.lexists(real):
            raise RuntimeError("sandbox workdir could not be wiped")


def _force(func: object, path: str, exc: object) -> None:
    """rmtree error hook: the code may have chmod'ed its own tree to 000."""
    try:
        parent = os.path.dirname(path)
        os.chmod(parent, stat.S_IRWXU)
        os.chmod(path, stat.S_IRWXU)
    except OSError:
        pass
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path, onerror=_force)
        else:
            os.unlink(path)
    except OSError:
        pass
