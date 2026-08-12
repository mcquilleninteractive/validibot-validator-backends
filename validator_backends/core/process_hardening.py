"""Small Linux process controls for secret-bearing validator parents.

Environment allowlisting on a child process prevents ordinary inheritance but
does not, by itself, stop a compromised same-UID child from inspecting an
ancestor through procfs. Linux's non-dumpable process attribute closes that
ptrace/procfs read path when the workload has no ``CAP_SYS_PTRACE``. The helper
fails closed on Linux because silently losing this boundary would expose
attempt capabilities to native parser children.
"""

from __future__ import annotations

import ctypes
import os
import sys


PR_GET_DUMPABLE = 3
PR_SET_DUMPABLE = 4
PR_SET_NO_NEW_PRIVS = 38


def protect_current_process_secrets() -> None:
    """Make a Linux process unavailable to same-UID ptrace/procfs readers."""
    if not sys.platform.startswith("linux"):
        return
    _prctl(PR_SET_DUMPABLE, 0)


def prevent_privilege_escalation() -> None:
    """Forbid a Linux parser child from gaining privilege across ``exec``."""
    if not sys.platform.startswith("linux"):
        return
    _prctl(PR_SET_NO_NEW_PRIVS, 1)


def current_process_dumpable() -> int | None:
    """Return the Linux dumpable state for tests and runtime diagnostics."""
    if not sys.platform.startswith("linux"):
        return None
    return _prctl(PR_GET_DUMPABLE, 0, returns_value=True)


def _prctl(option: int, argument: int, *, returns_value: bool = False) -> int:
    """Invoke ``prctl`` through libc and translate an errno into ``OSError``."""
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    prctl.restype = ctypes.c_int
    result = prctl(option, argument, 0, 0, 0)
    if result == -1:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))
    return result if returns_value else 0
