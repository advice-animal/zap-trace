from __future__ import annotations

import select
import subprocess
import sys
from typing import Generator

import pytest

try:
    import frida  # noqa: F401

    _FRIDA_AVAILABLE = True
except ImportError:
    _FRIDA_AVAILABLE = False

frida_mark = pytest.mark.skipif(not _FRIDA_AVAILABLE, reason="frida not installed")


def _allow_ptrace() -> None:
    """preexec_fn: allow any process to ptrace this child (Linux Yama workaround).

    With ptrace_scope=1, frida.attach() can only trace processes it spawned.
    PR_SET_PTRACER with PR_SET_PTRACER_ANY opts this specific child out of that
    restriction without requiring root or a global sysctl change.
    """
    import ctypes

    PR_SET_PTRACER = 0x59616D61  # "Yama" as a little-endian int
    PR_SET_PTRACER_ANY = -1
    try:
        ctypes.CDLL("libc.so.6").prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0)
    except Exception:
        pass


def _spawn(cmd: str) -> subprocess.Popen:
    kwargs: dict = {"stdin": subprocess.PIPE, "stdout": subprocess.PIPE}
    if sys.platform == "linux":
        kwargs["preexec_fn"] = _allow_ptrace
    return subprocess.Popen([sys.executable, "-c", cmd], **kwargs)


def _ready(proc: subprocess.Popen, timeout: float = 15.0) -> None:
    """Block until the child writes a line to stdout (readiness signal)."""
    assert proc.stdout is not None
    ready, _, _ = select.select([proc.stdout], [], [], timeout)
    if not ready:
        proc.kill()
        proc.wait()
        raise TimeoutError("child process did not signal ready")
    proc.stdout.readline()


def _teardown(proc: subprocess.Popen) -> None:
    assert proc.stdin is not None
    proc.stdin.close()
    try:
        proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


@pytest.fixture()
def idle_proc() -> Generator[subprocess.Popen, None, None]:
    """Spawn a Python process that blocks on stdin after signalling ready."""
    proc = _spawn("import sys; print(flush=True); sys.stdin.read()")
    _ready(proc)
    yield proc
    _teardown(proc)


@pytest.fixture()
def keke_proc() -> Generator[subprocess.Popen, None, None]:
    """Spawn a process with an active keke.TraceOutput that emits events continuously.

    A background thread emits a 'tick' kev at ~20 Hz while the process blocks
    on stdin, so the tap has events to receive regardless of attach timing.
    Child writes a blank line when ready; exits when stdin is closed.
    """
    script = "\n".join(
        [
            "import keke, sys, os, threading, time",
            "t = keke.TraceOutput(open(os.devnull, 'w'))",
            "t.__enter__()",
            "stop = threading.Event()",
            "def _emit():",
            "    while not stop.is_set():",
            "        with keke.kev('tick'): time.sleep(0.05)",
            "th = threading.Thread(target=_emit, daemon=True)",
            "th.start()",
            "print(flush=True)",
            "sys.stdin.readline()",
            "stop.set()",
            "th.join(timeout=1.0)",
            "t.__exit__(None, None, None)",
        ]
    )
    proc = _spawn(script)
    _ready(proc)
    yield proc
    _teardown(proc)
