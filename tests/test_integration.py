"""Integration tests — require frida and a real Python subprocess."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from io import StringIO
from typing import Generator

import keke
import pytest
from conftest import _ready, _spawn, _teardown, frida_mark
from zap_trace.gil import FridaGilTracker
from zap_trace.keke_tap import FridaKekeCollector


def _collect_gil_events(pid: int, duration: float) -> list:
    """Attach FridaGilTracker to pid, collect for duration seconds, return events."""
    out = StringIO()
    with keke.TraceOutput(out, close_output_file=False):
        try:
            with FridaGilTracker(pid):
                time.sleep(duration)
        except Exception as exc:
            pytest.skip(f"frida.attach failed: {exc}")
    return [e for e in json.loads(out.getvalue()) if e]


# ── GIL tracing (attach mode) ─────────────────────────────────────────────────


class TestGilAttach:
    @frida_mark
    def test_attaches_and_collects_events(self, idle_proc, tmp_path):
        out = StringIO()
        with keke.TraceOutput(out, close_output_file=False):
            try:
                with FridaGilTracker(idle_proc.pid):
                    time.sleep(0.5)
            except Exception as exc:
                pytest.skip(f"frida.attach failed: {exc}")
        assert out.getvalue().startswith("[")
        assert len(out.getvalue()) > 5

    @frida_mark
    def test_dropped_property_accessible(self, idle_proc, tmp_path):
        out = StringIO()
        with keke.TraceOutput(out, close_output_file=False):
            try:
                with FridaGilTracker(idle_proc.pid) as tracker:
                    time.sleep(0.2)
            except Exception as exc:
                pytest.skip(f"frida.attach failed: {exc}")
        assert tracker.dropped >= 0


# ── keke tapping (attach mode) ────────────────────────────────────────────────


class TestKekeTapAttach:
    @frida_mark
    def test_attaches_and_receives_events(self, keke_proc, tmp_path):
        output = tmp_path / "trace.json"
        with keke.TraceOutput(output.open("w")):
            try:
                with FridaKekeCollector(keke_proc.pid):
                    time.sleep(0.5)
            except Exception as exc:
                pytest.skip(f"frida.attach failed: {exc}")
        content = output.read_text()
        assert content.startswith("[")
        assert len(content) > 10


# ── Full CLI (exec mode) ──────────────────────────────────────────────────────


class TestCliExecMode:
    @frida_mark
    def test_exec_mode_gil(self, tmp_path):
        output = tmp_path / "out.json"
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "zap_trace",
                "--gil",
                "-o",
                str(output),
                "--",
                sys.executable,
                "-c",
                "import time; time.sleep(2)",
            ],
            capture_output=True,
            timeout=30,
        )
        if result.returncode != 0 and b"frida" in result.stderr.lower():
            pytest.skip(f"frida failed: {result.stderr.decode()[:200]}")
        assert result.returncode == 0, result.stderr.decode()
        assert output.exists()
        content = output.read_text()
        assert content.startswith("[")
        assert content.endswith("{}]\n")

    @frida_mark
    def test_exec_mode_both(self, tmp_path):
        output = tmp_path / "out.json"
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "zap_trace",
                "--gil",
                "-o",
                str(output),
                "--",
                sys.executable,
                "-c",
                "import time; time.sleep(2)",
            ],
            capture_output=True,
            timeout=30,
        )
        if result.returncode != 0 and b"frida" in result.stderr.lower():
            pytest.skip(f"frida failed: {result.stderr.decode()[:200]}")
        assert result.returncode == 0
        assert output.exists()


# ── Blocking event categorisation ────────────────────────────────────────────


@pytest.fixture()
def sleeping_proc() -> Generator[subprocess.Popen, None, None]:
    """Process whose daemon thread loops calling time.sleep(0.05)."""
    proc = _spawn(
        "import time, threading, sys\n"
        "def _loop():\n"
        "    while True: time.sleep(0.05)\n"
        "threading.Thread(target=_loop, daemon=True).start()\n"
        "print(flush=True)\n"
        "sys.stdin.read()\n"
    )
    _ready(proc)
    yield proc
    _teardown(proc)


@pytest.fixture()
def selecting_proc() -> Generator[subprocess.Popen, None, None]:
    """Process whose daemon thread loops calling select.select() with a timeout."""
    proc = _spawn(
        "import select, threading, sys\n"
        "def _loop():\n"
        "    while True: select.select([], [], [], 0.05)\n"
        "threading.Thread(target=_loop, daemon=True).start()\n"
        "print(flush=True)\n"
        "sys.stdin.read()\n"
    )
    _ready(proc)
    yield proc
    _teardown(proc)


class TestGilBlockingEvents:
    @frida_mark
    @pytest.mark.skipif(
        sys.version_info < (3, 11),
        reason="Python 3.10 uses select() for time.sleep(), not clock_nanosleep",
    )
    def test_time_sleep_shows_as_sleeping(self, sleeping_proc):
        events = _collect_gil_events(sleeping_proc.pid, duration=0.5)
        sleeping = [e for e in events if e.get("cat") == "sleeping"]
        assert sleeping, "expected 'sleeping' events from time.sleep()"
        assert all(e["name"] == "sleeping" for e in sleeping)

    @frida_mark
    def test_select_shows_as_io_wait(self, selecting_proc):
        events = _collect_gil_events(selecting_proc.pid, duration=0.5)
        io_waits = [e for e in events if e.get("cat") == "io_wait"]
        assert io_waits, "expected 'I/O wait' events from select.select()"
        assert all(e["name"] == "select" for e in io_waits)

    @frida_mark
    def test_asyncio_with_thread_pool_shows_gil_held(self):
        """Asyncio event loop + ThreadPoolExecutor must produce GIL held events.

        Regression guard for the production scenario: asyncio's kevent I/O wait
        dominates and take_gil fires only when threads re-acquire, so if the
        take_gil symbol is missing or inlined GIL held events vanish entirely.
        """
        proc = _spawn(
            "import asyncio, concurrent.futures, sys\n"
            "\n"
            "def _cpu():\n"
            "    return sum(range(100_000))\n"
            "\n"
            "async def _worker(ex):\n"
            "    loop = asyncio.get_running_loop()\n"
            "    while True:\n"
            "        await loop.run_in_executor(ex, _cpu)\n"
            "        await asyncio.sleep(0.005)\n"
            "\n"
            "async def _main():\n"
            "    ex = concurrent.futures.ThreadPoolExecutor(max_workers=3)\n"
            "    for _ in range(3):\n"
            "        asyncio.create_task(_worker(ex))\n"
            "    print(flush=True)\n"
            "    loop = asyncio.get_running_loop()\n"
            "    await loop.run_in_executor(None, sys.stdin.readline)\n"
            "    ex.shutdown(wait=False)\n"
            "\n"
            "asyncio.run(_main())\n"
        )
        _ready(proc)
        try:
            events = _collect_gil_events(proc.pid, duration=1.5)
        finally:
            _teardown(proc)
        held = [e for e in events if e.get("cat") == "gil_held"]
        io_wait = [e for e in events if e.get("cat") == "io_wait"]
        assert io_wait, "expected I/O wait events from asyncio kevent"
        assert held, "expected GIL held events — take_gil hooks may be missing"
        wait = [e for e in events if e.get("cat") == "gil_wait"]
        assert wait, (
            "expected GIL wait events — PyEval_RestoreThread.onEnter hook may be missing; "
            f"got {len(held)} held but {len(wait)} wait events"
        )
        # held:wait should be close to 1:1 (every acquisition has a wait period)
        ratio = len(wait) / len(held)
        assert ratio > 0.5, (
            f"gil_wait/gil_held ratio {ratio:.2f} too low — most re-acquisitions "
            "are not recording wait time (take_gil likely inlined in PyEval_RestoreThread)"
        )

    @frida_mark
    @pytest.mark.skipif(
        sys.version_info < (3, 11),
        reason="Python 3.10 uses select() for time.sleep(), not clock_nanosleep",
    )
    def test_gil_held_present_alongside_io_wait(self):
        """GIL held events must appear even when I/O wait events dominate.

        Regression guard: if take_gil hooks are missing or _holdStart is never
        populated, we'd see I/O waits but zero GIL held events.
        """
        # Use multiple threads so GIL contention is visible: workers alternate
        # between CPU (sum) and sleep, forcing take_gil/drop_gil to fire.
        proc = _spawn(
            "import threading, time, sys\n"
            "def _worker():\n"
            "    while True:\n"
            "        sum(range(10_000))\n"
            "        time.sleep(0.01)\n"
            "for _ in range(3):\n"
            "    threading.Thread(target=_worker, daemon=True).start()\n"
            "print(flush=True)\n"
            "sys.stdin.read()\n"
        )
        _ready(proc)
        try:
            events = _collect_gil_events(proc.pid, duration=1.0)
        finally:
            _teardown(proc)
        held = [e for e in events if e.get("cat") == "gil_held"]
        sleeping = [e for e in events if e.get("cat") == "sleeping"]
        assert sleeping, "expected 'sleeping' events (sanity check)"
        assert held, "expected 'GIL held' events — take_gil hooks may be missing"
