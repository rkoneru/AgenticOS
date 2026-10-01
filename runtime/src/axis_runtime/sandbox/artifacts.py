"""Artifact capture from the sandbox output directory, and disk-usage measurement.

The output directory is written by UNTRUSTED code, so everything here treats it as hostile:

* traversal is by file descriptor (``dir_fd``) with ``O_NOFOLLOW``, never by joining path strings,
  so a symlink (to a file OR a directory) is never followed and nothing outside the directory is
  ever opened;
* only regular files with a single link are read (no FIFOs/devices/sockets: opening a FIFO would
  block; no hard links to other files);
* count, per-file size, total size, depth and entry-count caps are enforced BEFORE reading and again
  while reading (a file that grew after ``fstat`` is skipped, not truncated silently).
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass

from axis_runtime.sandbox.types import Artifact, SandboxLimits, SkippedArtifact, sha256_hex

MAX_DEPTH = 6
MAX_ENTRIES = 2048  #: directory entries inspected per capture / usage scan (bounds a file flood)
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


@dataclass(frozen=True)
class Captured:
    artifacts: tuple[Artifact, ...]
    skipped: tuple[SkippedArtifact, ...]


def _safe_relative(rel: str) -> bool:
    parts = rel.split("/")
    return bool(rel) and not rel.startswith("/") and all(p not in ("", ".", "..") for p in parts)


class _Stop(Exception):
    """Entry limit reached: stop the walk (what was captured so far is returned)."""


def capture_artifacts(out_dir: str, limits: SandboxLimits) -> Captured:
    artifacts: list[Artifact] = []
    skipped: list[SkippedArtifact] = []
    try:
        root_fd = os.open(out_dir, _DIR_FLAGS)
    except OSError:
        return Captured((), ())
    total = 0
    inspected = 0

    def walk(dfd: int, prefix: str, depth: int) -> None:
        """Depth-first, so at most MAX_DEPTH + 1 directory descriptors are open at once: untrusted
        code can create thousands of directories, and holding one descriptor per pending directory
        would exhaust the runtime process's descriptors (for every other run too)."""
        nonlocal total, inspected
        try:
            names = sorted(os.listdir(dfd))
        except OSError:
            skipped.append(SkippedArtifact(prefix.rstrip("/") or ".", "unreadable_directory"))
            return
        children: list[str] = []
        for name in names:
            inspected += 1
            if inspected > MAX_ENTRIES:
                skipped.append(SkippedArtifact(prefix + name, "entry_limit"))
                raise _Stop
            rel = prefix + name
            if not _safe_relative(rel):
                skipped.append(SkippedArtifact(rel, "unsafe_path"))
                continue
            try:
                rel.encode("utf-8")
            except UnicodeEncodeError:
                skipped.append(SkippedArtifact(repr(rel), "bad_name"))
                continue
            try:
                st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            except OSError:
                skipped.append(SkippedArtifact(rel, "vanished"))
                continue
            if stat.S_ISLNK(st.st_mode):
                skipped.append(SkippedArtifact(rel, "symlink"))
            elif stat.S_ISDIR(st.st_mode):
                if depth + 1 > MAX_DEPTH:
                    skipped.append(SkippedArtifact(rel, "too_deep"))
                    continue
                children.append(name)
            elif not stat.S_ISREG(st.st_mode):
                skipped.append(SkippedArtifact(rel, "not_regular_file"))
            elif st.st_nlink != 1:
                skipped.append(SkippedArtifact(rel, "hard_link"))
            elif len(artifacts) >= limits.max_artifacts:
                skipped.append(SkippedArtifact(rel, "too_many_artifacts"))
            elif st.st_size > limits.max_artifact_bytes:
                skipped.append(SkippedArtifact(rel, "too_large"))
            elif total + st.st_size > limits.max_artifacts_total_bytes:
                skipped.append(SkippedArtifact(rel, "total_size_exceeded"))
            else:
                art = _read_one(dfd, name, rel, st, limits)
                if (
                    isinstance(art, Artifact)
                    and total + art.size > limits.max_artifacts_total_bytes
                ):
                    # the file grew between stat() and read(): the cap is on bytes actually read
                    skipped.append(SkippedArtifact(rel, "total_size_exceeded"))
                elif isinstance(art, Artifact):
                    total += art.size
                    artifacts.append(art)
                else:
                    skipped.append(art)
        for name in reversed(children):  # same order as the previous explicit stack
            try:
                child = os.open(name, _DIR_FLAGS, dir_fd=dfd)
            except OSError:
                skipped.append(SkippedArtifact(prefix + name, "unreadable_directory"))
                continue
            try:
                walk(child, prefix + name + "/", depth + 1)
            finally:
                os.close(child)

    try:
        walk(root_fd, "", 0)
    except _Stop:
        pass
    finally:
        os.close(root_fd)
    return Captured(tuple(artifacts), tuple(skipped))


def _read_one(
    dfd: int, name: str, rel: str, st: os.stat_result, limits: SandboxLimits
) -> Artifact | SkippedArtifact:
    try:
        fd = os.open(name, _FILE_FLAGS, dir_fd=dfd)
    except OSError:
        return SkippedArtifact(rel, "unreadable")
    try:
        st2 = os.fstat(fd)
        if (
            not stat.S_ISREG(st2.st_mode)
            or (st2.st_ino, st2.st_dev) != (st.st_ino, st.st_dev)
            or st2.st_nlink != 1
        ):
            return SkippedArtifact(rel, "changed_during_capture")
        data = b""
        while len(data) <= limits.max_artifact_bytes:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data += chunk
    except OSError:
        return SkippedArtifact(rel, "unreadable")
    finally:
        os.close(fd)
    if len(data) > limits.max_artifact_bytes:
        return SkippedArtifact(rel, "too_large")
    return Artifact(rel, len(data), sha256_hex(data), data)


def disk_usage(root: str) -> int:
    """Sum of regular-file sizes under ``root`` (symlinks not followed, scan bounded)."""
    total = 0
    seen = 0
    for base, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            seen += 1
            if seen > MAX_ENTRIES * 4:
                return total + (1 << 62)  # a flood of entries counts as "over any limit"
            try:
                st = os.lstat(os.path.join(base, name))
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode):
                total += st.st_size
    return total
