"""
keke_tap — tap a running process's keke TraceOutput via Frida.

Attaches to a Python process and injects code that opens a named FIFO and
registers it as a tap via ``keke.TRACER._add_tap()``.  The target's writer
thread then forwards every trace event to the FIFO as JSONL (one compact JSON
object per line); the controller reads these and merges them into its own
trace.

If keke is not installed in the target an informative error is raised.  If
keke is installed but no ``TraceOutput`` is active, a tap-only
``TraceOutput(None)`` is installed automatically so events still flow.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
from typing import Any, Optional

import keke

# ── Frida JS agent ────────────────────────────────────────────────────────────

_AGENT_JS = r"""
'use strict';

// Cached runner — built once in inject(), reused in cleanup() so
// Process.enumerateModules() / dl_iterate_phdr is only called once.
let _runPython = null;

function makePythonRunner() {
    // Single pass over the module list covers both the .so and .dylib cases.
    let findExport = null;
    for (const mod of Process.enumerateModules()) {
        if (mod.name.match(/^libpython3\.\d+.*\.so/)       // Linux dynamic
                || mod.path.match(/Python|libpython/)) {    // macOS framework/dylib
            findExport = (name) => mod.findExportByName(name);
            break;
        }
    }
    // Linux with statically-linked Python: symbols live in the executable.
    // Module.findGlobalExportByName() is the Frida 17+ API for this.
    if (findExport === null) {
        if (Module.findGlobalExportByName('PyGILState_Ensure') === null) {
            return null;
        }
        findExport = (name) => Module.findGlobalExportByName(name);
    }

    const ensure  = new NativeFunction(findExport('PyGILState_Ensure'),  'int',     []);
    const release = new NativeFunction(findExport('PyGILState_Release'), 'void',    ['int']);
    const runStr  = new NativeFunction(findExport('PyRun_SimpleString'), 'int',     ['pointer']);

    return function runPython(code) {
        const cstr  = Memory.allocUtf8String(code);
        const state = ensure();
        const ret   = runStr(cstr);
        release(state);
        return ret;
    };
}

rpc.exports = {
    inject: function(fifoPath) {
        _runPython = makePythonRunner();
        if (_runPython === null) {
            return {ok: false, error: 'libpython not found'};
        }
        const runPython = _runPython;

        // Two-step injection: first check keke is importable (gives a clean
        // error if not), then install the tap.  PyRun_SimpleString runs in
        // __main__ so variables set in step 1 are visible in step 2.
        //
        // If keke is present but TRACER is None, we install a NullTraceOutput
        // (TraceOutput(None)) so the tap receives events anyway.

        // Step 1: import keke
        const importRet = runPython('import keke as _keke_mod');
        if (importRet !== 0) {
            return {ok: false, error: 'keke is not installed in the target process'};
        }

        // Step 2: open FIFO tap; spin up NullTraceOutput if no active tracer
        const initCode = `
import builtins as _keke_b
_keke_fifo = _keke_b.open(${JSON.stringify(fifoPath)}, 'w')
_keke_null_tracer = None
if _keke_mod.TRACER is None:
    _keke_null_tracer = _keke_mod.TraceOutput(file=_keke_mod._NullIO())
    _keke_null_tracer.__enter__()
_keke_mod.TRACER._add_tap(_keke_fifo)
`;
        const ret = runPython(initCode);
        return ret === 0
            ? {ok: true}
            : {ok: false, error: 'tap registration failed in target process'};
    },

    cleanup: function() {
        if (_runPython === null) return {ok: false};
        const runPython = _runPython;
        // Close the FIFO so keke's writer thread sees a broken pipe and removes
        // the tap.  Also tear down any NullTraceOutput we installed.
        const ret = runPython(`\
if globals().get('_keke_null_tracer') is not None:
    try:
        _keke_null_tracer.__exit__(None, None, None)
    except Exception:
        pass
    _keke_null_tracer = None
if globals().get('_keke_fifo') is not None:
    try:
        _keke_fifo.close()
    except Exception:
        pass
    _keke_fifo = None
`);
        return {ok: ret === 0};
    },
};
"""


# ── Python controller ─────────────────────────────────────────────────────────


def _fifo_read_loop(
    read_fd: int,
    tracer: Optional[keke.TraceOutput],
    dropped_ref: list[int],
) -> None:
    """Read newline-delimited JSON events from the FIFO and feed into keke.

    Wire format: one compact JSON object per line (JSONL), written by
    keke's writer thread in the target process as text.
    """
    try:
        with os.fdopen(read_fd, "r", closefd=False) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                t = tracer if tracer is not None else keke.TRACER
                if t is not None:
                    t.put(keke.EVENT(event), False)
    except OSError:
        pass  # fd was closed from the controller side; clean exit


class FridaKekeCollector:
    """Stream keke trace events from a running process into this process's trace.

    Attaches to *pid* via Frida and injects code that opens a named FIFO and
    registers it with the target's ``keke.TRACER._add_tap()``.  The target's
    own writer thread then forwards every event to the FIFO as JSONL;
    the controller reads these and merges them into its own trace.

    .. note:: FIFO opening quirk (macOS)

        On macOS, opening a FIFO ``O_RDONLY|O_NONBLOCK`` (non-blocking so it
        returns immediately without a writer) and then stripping ``O_NONBLOCK``
        causes subsequent ``read()`` calls to return EOF immediately, because
        the kernel records that no writer was present at open time.  To prevent
        this, the controller also opens a write-side "keepalive" fd
        (``O_WRONLY|O_NONBLOCK``) immediately after the read fd, which keeps
        the pipe live until explicitly closed.  The keepalive fd is closed in
        ``__exit__`` after ``cleanup()`` has told the target to close its tap,
        so the reader thread sees EOF and exits cleanly.  On Linux the
        ``O_RDONLY|O_NONBLOCK``-then-strip pattern works without a keepalive,
        but the keepalive is harmless there too.

    Args:
        pid:       Target process PID.
        tracer:    Use this TraceOutput instead of ``keke.TRACER``.
        fifo_path: Path for the named pipe.  Defaults to a unique path in
                   ``$TMPDIR``.
    """

    def __init__(
        self,
        pid: int,
        tracer: Optional[keke.TraceOutput] = None,
        fifo_path: Optional[str] = None,
    ) -> None:
        self._pid = pid
        self._tracer = tracer
        if fifo_path is None:
            fifo_path = os.path.join(
                tempfile.gettempdir(),
                f"keke_tap_{os.getpid()}.fifo",
            )
        self._fifo_path = fifo_path
        self._dropped_ref: list[int] = [0]
        self._session: Optional[Any] = None
        self._script: Optional[Any] = None
        self._reader: Optional[threading.Thread] = None
        self._read_fd = -1
        self._write_keepalive_fd = -1
        self._exited = False

    def __enter__(self) -> "FridaKekeCollector":
        import fcntl  # noqa: PLC0415

        import frida  # noqa: PLC0415

        os.mkfifo(self._fifo_path)

        # Open read side non-blocking so it returns immediately without a writer.
        self._read_fd = os.open(self._fifo_path, os.O_RDONLY | os.O_NONBLOCK)
        # Open a write-side keepalive fd so the reader never sees spurious EOF.
        # On macOS, opening O_RDONLY|O_NONBLOCK and then stripping the flag
        # causes read() to return EOF immediately because no writer was present
        # at open time.  Keeping a live write reference prevents this; we close
        # it explicitly in __exit__ after cleanup() to signal EOF to the reader.
        self._write_keepalive_fd = os.open(self._fifo_path, os.O_WRONLY | os.O_NONBLOCK)
        # Strip O_NONBLOCK so the reader thread blocks normally on empty reads.
        flags = fcntl.fcntl(self._read_fd, fcntl.F_GETFL)
        fcntl.fcntl(self._read_fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)

        self._reader = threading.Thread(
            target=_fifo_read_loop,
            args=(self._read_fd, self._tracer, self._dropped_ref),
            name="keke_tap.reader",
            daemon=True,
        )
        self._reader.start()

        self._session = frida.attach(self._pid)
        self._script = self._session.create_script(_AGENT_JS)
        self._script.on("message", self._on_message)
        self._script.load()

        result = self._script.exports_sync.inject(self._fifo_path)
        if not result.get("ok"):
            err = result.get("error", "unknown error")
            raise RuntimeError(f"Frida injection failed: {err}")

        return self

    def _on_message(self, message: Any, data: object) -> None:
        if message["type"] == "error":
            print(f"[keke_tap] {message.get('description', message)}", file=sys.stderr)

    def disconnect(self) -> None:
        """Disconnect the tap.  Safe to call multiple times."""
        if not self._exited:
            self.__exit__(None, None, None)

    def __exit__(self, *_: object) -> None:
        if self._exited:
            return
        self._exited = True

        if self._script is not None:
            try:
                self._script.exports_sync.cleanup()
            except Exception:
                pass
            try:
                self._script.unload()
            except Exception:
                pass

        if self._session is not None:
            try:
                self._session.detach()
            except Exception:
                pass

        # Close the keepalive write fd after cleanup() has told the target to
        # close its tap.  With no writers remaining the reader thread sees EOF
        # and exits cleanly.
        if self._write_keepalive_fd >= 0:
            try:
                os.close(self._write_keepalive_fd)
            except OSError:
                pass
            self._write_keepalive_fd = -1

        if self._reader is not None:
            self._reader.join(timeout=3.0)

        if self._read_fd >= 0:
            try:
                os.close(self._read_fd)
            except OSError:
                pass
            self._read_fd = -1

        try:
            os.unlink(self._fifo_path)
        except OSError:
            pass

    @property
    def fifo_path(self) -> str:
        """The named pipe path used for this session."""
        return self._fifo_path
