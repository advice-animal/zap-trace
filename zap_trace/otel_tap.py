"""
otel_tap — tap a running process's OpenTelemetry spans via Frida.

Attaches to a Python process and injects a custom ``SpanProcessor`` that writes
completed spans to a named FIFO as keke-compatible JSONL.  The controller reads
these and merges them into its own keke trace.

If ``opentelemetry`` is not installed in the target an informative error is raised.
If OTel is installed but no ``SdkTracerProvider`` is active, a null-exporter
``SdkTracerProvider`` is installed automatically.

For the duration of the attach, the provider's sampler is replaced with
``ALWAYS_ON`` so that spans are not silently dropped before reaching the
processor.  The original sampler is restored when the last tap disconnects.

Multiple ``FridaOtelCollector`` instances can attach to the same PID
simultaneously; each adds its own processor and cleans up independently.
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

_AGENT_JS = r'''
'use strict';

let _runPython = null;

function makePythonRunner() {
    let findExport = null;
    for (const mod of Process.enumerateModules()) {
        if (mod.name.match(/^libpython3\.\d+.*\.so/)
                || mod.path.match(/Python|libpython/)) {
            findExport = (name) => mod.findExportByName(name);
            break;
        }
    }
    if (findExport === null) {
        if (Module.findGlobalExportByName('PyGILState_Ensure') === null) {
            return null;
        }
        findExport = (name) => Module.findGlobalExportByName(name);
    }

    const ensure  = new NativeFunction(findExport('PyGILState_Ensure'),  'int',  []);
    const release = new NativeFunction(findExport('PyGILState_Release'), 'void', ['int']);
    const runStr  = new NativeFunction(findExport('PyRun_SimpleString'), 'int',  ['pointer']);

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

        // Step 1: check opentelemetry is importable
        const importRet = runPython(
            'import opentelemetry.sdk.trace as _otel_sdk_mod; ' +
            'import opentelemetry.trace as _otel_trace_mod'
        );
        if (importRet !== 0) {
            return {ok: false, error: 'opentelemetry is not installed in the target process'};
        }

        // Step 2–6: define processor class, init registry, install provider if needed,
        //           force sampling, and register tap.
        const initCode = `
import builtins as _otel_b
import time as _otel_time

# Always recompute: converts OTel Unix-epoch nanoseconds to perf_counter-relative
# nanoseconds (the same time base keke uses).  Recomputing on every inject is safe
# because perf_counter and time have essentially the same rate; the value is stable.
_otel_epoch_to_perf_ns = _otel_time.perf_counter_ns() - _otel_time.time_ns()

# Step 2: define processor class once
try:
    _OtelFifoProcessor
except NameError:
    import json as _otel_json
    import os as _otel_os
    import threading as _otel_threading

    from opentelemetry.sdk.trace.export import SpanExportResult as _OtelSER

    class _OtelNullExporter:
        def export(self, spans):
            return _OtelSER.SUCCESS
        def shutdown(self):
            pass
        def force_flush(self, timeout_millis=30000):
            return True

    class _OtelFifoProcessor:
        """SpanProcessor that writes completed spans to a FIFO as keke JSONL."""
        def __init__(self, fifo_path):
            self._f = _otel_b.open(fifo_path, 'w')
            self._active = True

        def on_start(self, span, parent_context=None):
            pass

        def _on_ending(self, span):
            pass

        def on_end(self, span):
            if not self._active:
                return
            ctx = span.get_span_context()
            pid = _otel_os.getpid()
            tid = _otel_threading.get_native_id()
            start_us = (span.start_time + _otel_epoch_to_perf_ns) / 1000.0
            dur_us   = (span.end_time - span.start_time) / 1000.0
            event = {
                'ph':   'X',
                'name': span.name,
                'ts':   start_us,
                'dur':  dur_us,
                'pid':  pid,
                'tid':  tid,
                'args': dict(span.attributes or {}, **{
                    'trace_id': format(ctx.trace_id, '032x'),
                    'span_id':  format(ctx.span_id,  '016x'),
                }),
            }
            try:
                self._f.write(_otel_json.dumps(event, separators=(',', ':')) + '\\n')
                self._f.flush()
            except OSError:
                self._active = False

        def deactivate(self):
            self._active = False
            try:
                self._f.close()
            except OSError:
                pass

        def shutdown(self):
            self.deactivate()

        def force_flush(self, timeout_millis=30000):
            return True

# Step 3: init registry once; reset session-level state whenever no taps are
# active.  Resetting here (not just on NameError) ensures a clean slate after
# each session even if a previous cleanup left stale values.
try:
    _otel_tap_registry
except NameError:
    _otel_tap_registry = {}

if not _otel_tap_registry:
    _otel_null_provider    = None
    _otel_orig_provider    = None
    _otel_original_sampler = None

# Step 4: get provider; install null provider if target has none
_otel_provider = _otel_trace_mod.get_tracer_provider()
if not isinstance(_otel_provider, _otel_sdk_mod.TracerProvider):
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor as _OtelSSP
    _otel_orig_provider = _otel_provider
    _otel_null_provider = _otel_sdk_mod.TracerProvider()
    _otel_null_provider.add_span_processor(_OtelSSP(_OtelNullExporter()))
    _otel_trace_mod.set_tracer_provider(_otel_null_provider)
    _otel_provider = _otel_null_provider

# Step 5: force sampling on (save original only once)
if _otel_original_sampler is None:
    from opentelemetry.sdk.trace.sampling import ALWAYS_ON as _ALWAYS_ON
    _otel_original_sampler = _otel_provider.sampler
    _otel_provider.sampler = _ALWAYS_ON

# Step 6: register the tap
_otel_proc = _OtelFifoProcessor(${JSON.stringify(fifoPath)})
_otel_provider.add_span_processor(_otel_proc)
_otel_tap_registry[${JSON.stringify(fifoPath)}] = _otel_proc
`;
        const ret = runPython(initCode);
        return ret === 0
            ? {ok: true}
            : {ok: false, error: 'tap registration failed in target process'};
    },

    cleanup: function(fifoPath) {
        if (_runPython === null) return {ok: false};
        const runPython = _runPython;
        const code = `
if globals().get('_otel_tap_registry') and ${JSON.stringify(fifoPath)} in _otel_tap_registry:
    _otel_tap_registry[${JSON.stringify(fifoPath)}].deactivate()
    del _otel_tap_registry[${JSON.stringify(fifoPath)}]

# When last tap leaves: restore sampler only.
# We intentionally do NOT call set_tracer_provider to restore the original
# proxy provider.  ProxyTracer instances in the target cache a real tracer
# that points to our null_provider.  If we replaced the global provider and
# a second attach then installed a new null_provider2, those cached tracers
# would still delegate to null_provider1 — now with its sampler restored to
# the original (possibly restrictive) value — and all spans would be dropped.
# Leaving null_provider1 as the global means a second attach finds it via
# get_tracer_provider(), resets its sampler to ALWAYS_ON, and adds a fresh
# processor: the cached tracers keep working and spans flow correctly.
if not _otel_tap_registry:
    _otel_provider = _otel_trace_mod.get_tracer_provider()
    if _otel_original_sampler is not None:
        _otel_provider.sampler = _otel_original_sampler
        _otel_original_sampler = None
    _otel_null_provider = None
    _otel_orig_provider = None
`;
        const ret = runPython(code);
        return {ok: ret === 0};
    },
};
'''


# ── Python controller ─────────────────────────────────────────────────────────


def _otel_read_loop(
    read_fd: int,
    tracer: Optional[keke.TraceOutput],
    dropped_ref: list[int],
) -> None:
    """Read keke-compatible JSONL spans from the FIFO and feed into keke.

    Wire format: one compact JSON object per line produced by ``_OtelFifoProcessor``
    in the target process.
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


class FridaOtelCollector:
    """Stream OpenTelemetry spans from a running process into this process's trace.

    Attaches to *pid* via Frida and injects a custom ``SpanProcessor`` that writes
    completed spans to a named FIFO as keke-compatible JSONL.  The controller reads
    these and merges them into its own keke trace.

    The target's OTel sampler is replaced with ``ALWAYS_ON`` for the duration of
    the attach and restored when the tap is removed.  Multiple instances can attach
    to the same PID simultaneously.

    .. note:: FIFO keepalive (macOS)

        Same keepalive-fd trick as ``FridaKekeCollector``: a write-side fd is held
        open until ``__exit__`` so the reader thread never sees spurious EOF.

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
                f"otel_tap_{os.getpid()}.fifo",
            )
        self._fifo_path = fifo_path
        self._dropped_ref: list[int] = [0]
        self._session: Optional[Any] = None
        self._script: Optional[Any] = None
        self._reader: Optional[threading.Thread] = None
        self._read_fd = -1
        self._write_keepalive_fd = -1
        self._exited = False

    def __enter__(self) -> "FridaOtelCollector":
        import fcntl  # noqa: PLC0415

        import frida  # noqa: PLC0415

        os.mkfifo(self._fifo_path)

        self._read_fd = os.open(self._fifo_path, os.O_RDONLY | os.O_NONBLOCK)
        self._write_keepalive_fd = os.open(self._fifo_path, os.O_WRONLY | os.O_NONBLOCK)
        flags = fcntl.fcntl(self._read_fd, fcntl.F_GETFL)
        fcntl.fcntl(self._read_fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)

        self._reader = threading.Thread(
            target=_otel_read_loop,
            args=(self._read_fd, self._tracer, self._dropped_ref),
            name="otel_tap.reader",
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
            print(f"[otel_tap] {message.get('description', message)}", file=sys.stderr)

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
                self._script.exports_sync.cleanup(self._fifo_path)
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
