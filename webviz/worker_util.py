"""Cross-process plumbing shared by the leader-elected background workers
(enrich_worker, extension_worker, ooda_worker).

* Leader election: an exclusive, non-blocking fcntl flock on a tmpfs file.
* Status: JSON files written atomically (temp file, fsync, rename).
* Manual refresh: a trigger file whose mtime advances; the loop polls it
  while it sleeps, and the mtime also enforces a shared cooldown.
"""

from __future__ import annotations

import errno
import fcntl
import json
import logging
import os
import tempfile
import time
from pathlib import Path

logger = logging.getLogger(__name__)

TRIGGER_POLL_SEC = 1.0


def atomic_write_json(path: str, payload, *, prefix: str = ".worker.") -> None:
    """Write JSON atomically. Raises on failure: a status file that silently
    stops updating hides a dead worker."""
    parent = os.path.dirname(path) or "."
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError:
        pass  # mkstemp below raises with the real cause
    fd, tmp = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, separators=(",", ":"), default=str)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_json(path: str, default=None):
    """Parsed JSON at `path`, or `default` when missing or malformed."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return default


def try_acquire_lock(lock_path: str, name: str):
    """Open fd holding an exclusive flock on `lock_path`, or None when another
    process holds it (or the lock cannot be taken, which is logged)."""
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError as exc:
        logger.warning("%s: cannot open lock file %s: %s", name, lock_path, exc)
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(fd)
        if exc.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
            logger.warning("%s: lock acquisition failed: %s", name, exc)
        return None
    try:
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode("utf-8"))
    except OSError:
        pass
    return fd


def trigger_mtime(trigger_path: str) -> float:
    try:
        return os.path.getmtime(trigger_path)
    except OSError:
        return 0.0


def sleep_until(deadline: float, *, trigger_path: str, last_trigger: float,
                stop_event) -> float:
    """Sleep until `deadline`, a stop request, or a trigger newer than
    `last_trigger`. Returns the trigger mtime to compare against next time."""
    while not stop_event.is_set() and time.time() < deadline:
        mtime = trigger_mtime(trigger_path)
        if mtime > last_trigger:
            return mtime
        time.sleep(TRIGGER_POLL_SEC)
    return last_trigger


def fire_trigger(trigger_path: str, *, cooldown_sec: float, name: str) -> tuple[bool, float]:
    """Touch the trigger file unless the last touch is within `cooldown_sec`.

    The cooldown reads the file's own mtime, so every Gunicorn worker shares
    it. Returns (fired, retry_after_sec); retry_after_sec is 0 when fired.
    """
    now = time.time()
    last = trigger_mtime(trigger_path)
    if last > 0 and (now - last) < cooldown_sec:
        return False, max(1.0, cooldown_sec - (now - last))
    try:
        os.makedirs(os.path.dirname(trigger_path) or ".", exist_ok=True)
    except OSError:
        pass
    try:
        Path(trigger_path).touch()
    except OSError as exc:
        logger.error("%s: trigger touch failed: %s", name, exc)
        return False, 0.0
    return True, 0.0
