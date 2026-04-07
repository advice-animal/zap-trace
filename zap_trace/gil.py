from __future__ import annotations

import json
import struct
import sys
import threading
import time
from typing import Any, Optional

import keke

# Wire format: timestamp_us (end), duration_us, tid, kind, 3x pad
_FMT = "=QQIBxxx"
_SIZE = struct.calcsize(_FMT)
assert _SIZE == 24

# kind 3: sleeping (nanosleep/clock_nanosleep)
# kind 4-8: I/O multiplexers — named by syscall family, same cat/cname
_IO_CNAME = "thread_state_unknown"
_NAME = {
    0: "GIL wait",
    1: "GIL held",
    3: "sleeping",
    4: "select",
    5: "poll",
    6: "kevent",
    7: "epoll_wait",
    8: "pselect",
}
_CAT = {
    0: "gil_wait",
    1: "gil_held",
    3: "sleeping",
    4: "io_wait",
    5: "io_wait",
    6: "io_wait",
    7: "io_wait",
    8: "io_wait",
}
_CNAME = {
    0: "bad",
    1: "thread_state_running",
    3: "thread_state_iowait",
    4: _IO_CNAME,
    5: _IO_CNAME,
    6: _IO_CNAME,
    7: _IO_CNAME,
    8: _IO_CNAME,
}

# Virtual GIL tid = real_native_tid | _GIL_TID_BIT.
# Must match GIL_TID_BIT in the JS agent.
_GIL_TID_BIT = 1 << 31

# ── embedded JS agent ────────────────────────────────────────────────────────

_AGENT_JS = r"""
'use strict';

const MIN_WAIT_US = {min_wait_us};
const BATCH = 512;
const ESZ   = 24;   // =QQIBxxx: 8+8+4+1+3

let _buf    = new ArrayBuffer(BATCH * ESZ);
let _view   = new DataView(_buf);
let _n      = 0;
let _dropped = 0;
let _holdStart = {};   // osTid -> {t, ptid, vtid} when take_gil returned
let _ioActive  = {};   // vtid -> true while inside a blocking I/O call
let _seenTids  = {};   // vtid -> true (for thread_name metadata)
let _flushTimer = null;

// High-resolution monotonic microseconds via native clock.
// Process.hrtime() was removed in Frida 16+; use platform clock directly.
const _nowUs = (function() {
    if (Process.platform === 'darwin') {
        const _mach_abs = new NativeFunction(
            Module.findGlobalExportByName('mach_absolute_time'), 'uint64', []);
        const _info = Memory.alloc(8);
        new NativeFunction(
            Module.findGlobalExportByName('mach_timebase_info'), 'int', ['pointer'])(_info);
        const _numer = _info.readU32();
        const _denom = _info.add(4).readU32();
        return function() {
            return Number(_mach_abs()) * _numer / _denom / 1000;
        };
    } else {
        const _cgt = new NativeFunction(
            Module.findGlobalExportByName('clock_gettime'), 'int', ['int', 'pointer']);
        const _ts  = Memory.alloc(16);
        return function() {
            _cgt(1 /* CLOCK_MONOTONIC */, _ts);
            return Number(_ts.readU64()) * 1e6 + Number(_ts.add(8).readU64()) / 1e3;
        };
    }
})();
function nowUs() { return _nowUs(); }

// Python-compatible thread ID matching threading.get_native_id().
//
// CPython's PyThread_get_thread_native_id() wraps the platform call:
//   macOS: pthread_threadid_np(NULL, &out)  → uint64
//   Linux: syscall(SYS_gettid)              → same as Frida's this.threadId
//
// We try the Python export first (clean, forward-compatible), then fall back
// to calling the platform function directly.
//
// NOTE: pthread_self() returns the opaque pthread_t *pointer* (~2 GB on arm64),
// which is NOT the same as get_native_id() (~6 million).  Don't use it here.
const _pythonNativeTid = (function() {
    const _ptn = findExport('PyThread_get_thread_native_id');
    if (_ptn) {
        const fn = new NativeFunction(_ptn, 'ulong', []);
        return function() { return fn(); };
    }
    if (Process.platform === 'darwin') {
        const _threadid_np = new NativeFunction(
            Module.findGlobalExportByName('pthread_threadid_np'),
            'int', ['pointer', 'pointer']);
        return function() {
            const buf = Memory.alloc(8);
            _threadid_np(ptr(0), buf);
            return Number(buf.readU64());
        };
    }
    // Linux: gettid() is the same as Frida's this.threadId, but we need it
    // callable outside an interceptor context too.
    const _gtid = findExport('gettid');
    if (_gtid) {
        const fn = new NativeFunction(_gtid, 'int', []);
        return function() { return fn(); };
    }
    // Final fallback: syscall(SYS_gettid). SYS_gettid = 186 on x86-64, 178 on arm64.
    const SYS_gettid = Process.arch === 'arm64' ? 178 : 186;
    const _sc = new NativeFunction(findExport('syscall'), 'long', ['long']);
    return function() { return Number(_sc(SYS_gettid)); };
})();
function pythonTid() { return _pythonNativeTid(); }

// GIL events use a *virtual* tid = native_tid | GIL_TID_BIT so they appear
// on a separate row from keke events for the same thread.  The Python side
// emits a thread_sort_index for this virtual tid that places it just above
// the real thread row.
// Bit 31 is clear in all valid get_native_id() values on both macOS
// (pthread_threadid_np values are small monotonic integers) and Linux
// (gettid() max = PID_MAX, default 4M on 64-bit, well below 2^31).
// Using bit 31 avoids the collision risk of lower bits.
const GIL_TID_BIT = 1 << 31;   // 2 147 483 648 — top bit of uint32

// Write a safe-integer microsecond value as little-endian uint64
function writeU64LE(offset, v) {
    const lo = v % 4294967296;
    const hi = Math.floor(v / 4294967296);
    _view.setUint32(offset, lo, true);
    _view.setUint32(offset + 4, hi, true);
}

function flush() {
    if (_n === 0) return;
    const slice = _buf.slice(0, _n * ESZ);
    send({type: 'events', dropped: _dropped}, slice);
    _dropped = 0;
    _n = 0;
}

// ts_end_us = absolute end timestamp; dur_us = duration; kind: 0=wait 1=held
function emit(ts_end_us, dur_us, tid, kind) {
    if (_n >= BATCH) { _dropped++; return; }
    const off = _n * ESZ;
    writeU64LE(off,      Math.round(ts_end_us));
    writeU64LE(off + 8,  Math.round(dur_us));
    _view.setUint32(off + 16, tid, true);
    _view.setUint8 (off + 20, kind);
    // bytes 21-23 are zero padding (Python struct ignores them)
    _n++;
    if (_n >= BATCH) flush();
}

// Accept a canonical symbol name: prefix, or prefix.llvm.NNNNN (digits only after)
function isCanonical(name, prefix) {
    if (!name.startsWith(prefix)) return false;
    const rest = name.slice(prefix.length);
    if (rest === '') return true;
    if (!rest.startsWith('.llvm.')) return false;
    return /^\d+$/.test(rest.slice(6));
}

// Locate a global export by name.
// Module.findGlobalExportByName (Frida 16+) scans .dynsym directly and works
// on BOLT-optimised binaries where .gnu.hash is stale.  Fall back to a
// per-module search for older Frida.
function findExport(name) {
    if (typeof Module.findGlobalExportByName === 'function') {
        const p = Module.findGlobalExportByName(name);
        if (p && !p.isNull()) return p;
    }
    // Fallback: search each loaded module directly.
    // Use findExportByName (returns null) not getExportByName (throws) —
    // the latter was removed from module instances in Frida 17.
    for (const mod of Process.enumerateModules()) {
        const p = mod.findExportByName(name);
        if (p && !p.isNull()) return p;
    }
    return null;
}

function findBySymbol(prefix) {
    const addrs = [];
    for (const mod of Process.enumerateModules()) {
        if (!mod.path.match(/python/i)) continue;
        try {
            for (const sym of mod.enumerateSymbols()) {
                // Accept 'function' and 'section' — BOLT-optimised binaries
                // emit take_gil/drop_gil as type 'section' rather than 'function'.
                if ((sym.type === 'function' || sym.type === 'section') &&
                        isCanonical(sym.name, prefix)) {
                    addrs.push(sym.address);
                }
            }
        } catch(_) {}
    }
    return addrs;
}

// Emit a GIL-held event and clear the pending hold for this thread.
// Called from both drop_gil and PyEval_SaveThread hooks.  Using delete
// makes this idempotent: on non-BOLT binaries PyEval_SaveThread calls
// drop_gil internally, so whichever fires second sees no pending entry
// and is a no-op.
// _holdStart[osTid] = {t: nowUs, ptid: native_tid, vtid: native_tid | GIL_TID_BIT}
function emitHeld(osTid) {
    const entry = _holdStart[osTid];
    if (entry !== undefined) {
        const now = nowUs();
        emit(now, now - entry.t, entry.vtid, 1);  // GIL held
        delete _holdStart[osTid];
    }
}

// Query the target's threading.enumerate() via the Python C API and return
// a JSON string mapping native_id (int) → thread name, or null on any error.
// Uses a temporary __main__._zap_tnames attribute to pass the result back.
function queryThreadNames() {
    const _ensure  = findExport('PyGILState_Ensure');
    const _release = findExport('PyGILState_Release');
    const _runStr  = findExport('PyRun_SimpleString');
    const _addMod  = findExport('PyImport_AddModule');
    const _getAttr = findExport('PyObject_GetAttrString');
    const _asUtf8  = findExport('PyUnicode_AsUTF8');
    const _decRef  = findExport('Py_DecRef');
    const _errClr  = findExport('PyErr_Clear');
    if (!_ensure || !_release || !_runStr || !_addMod || !_getAttr || !_asUtf8 || !_decRef) {
        return null;
    }
    const ensure  = new NativeFunction(_ensure,  'int',     []);
    const release = new NativeFunction(_release, 'void',    ['int']);
    const runStr  = new NativeFunction(_runStr,  'int',     ['pointer']);
    const addMod  = new NativeFunction(_addMod,  'pointer', ['pointer']);
    const getAttr = new NativeFunction(_getAttr, 'pointer', ['pointer', 'pointer']);
    const asUtf8  = new NativeFunction(_asUtf8,  'pointer', ['pointer']);
    const decRef  = new NativeFunction(_decRef,  'void',    ['pointer']);
    const errClr  = new NativeFunction(_errClr,  'void',    []);

    const state = ensure();
    runStr(Memory.allocUtf8String(
        'import json as _zt_j, threading as _zt_t\n' +
        '__import__("__main__")._zap_tnames = _zt_j.dumps(\n' +
        '    {t.native_id: t.name for t in _zt_t.enumerate()}\n' +
        ')\n'
    ));
    const mainMod = addMod(Memory.allocUtf8String('__main__'));
    let result = null;
    if (mainMod && !mainMod.isNull()) {
        const pyStr = getAttr(mainMod, Memory.allocUtf8String('_zap_tnames'));
        if (pyStr && !pyStr.isNull()) {
            const cStr = asUtf8(pyStr);
            if (cStr && !cStr.isNull()) {
                result = cStr.readUtf8String();
            }
            decRef(pyStr);
        } else {
            errClr();
        }
    }
    runStr(Memory.allocUtf8String(
        'try:\n    del __import__("__main__")._zap_tnames\nexcept AttributeError:\n    pass\n'
    ));
    release(state);
    return result;
}

function attachGilHooks(takeAddrs, dropAddrs) {
    for (const addr of takeAddrs) {
        Interceptor.attach(addr, {
            onEnter: function() {
                this._t0 = nowUs();
            },
            onLeave: function() {
                const now    = nowUs();
                const osTid  = this.threadId;
                const ptid   = pythonTid();
                const vtid   = (ptid | GIL_TID_BIT) >>> 0;  // virtual GIL row tid
                const waitDur = now - this._t0;
                if (waitDur >= MIN_WAIT_US) {
                    emit(now, waitDur, vtid, 0);   // GIL wait
                }
                _holdStart[osTid] = {t: now, ptid: ptid, vtid: vtid};
            }
        });
    }
    for (const addr of dropAddrs) {
        Interceptor.attach(addr, {
            onEnter: function() { emitHeld(this.threadId); }
        });
    }
}

// On BOLT-optimised macOS binaries, drop_gil is inlined into PyEval_SaveThread
// for the I/O-release path, so the drop_gil symbol only fires for the eval-loop
// preemption path.  Hook PyEval_SaveThread as well to cover the I/O path.
// The emitHeld() delete makes this safe on non-BOLT binaries too.
function attachSaveThreadHook() {
    const addr = findExport('PyEval_SaveThread');
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function() { emitHeld(this.threadId); }
    });
}

// On BOLT-optimised binaries, take_gil is inlined into PyEval_RestoreThread,
// so the take_gil symbol only fires on new-thread startup, not on every
// re-acquisition.  Always hook PyEval_RestoreThread as well:
//   onEnter: record the wait start time
//   onLeave: if take_gil symbol didn't already fire (i.e. it was inlined),
//            emit a gil_wait event and set _holdStart
// When take_gil IS NOT inlined, it fires first and sets _holdStart; the
// onLeave check (_holdStart already set) suppresses the duplicate emit.
function attachRestoreThreadHook() {
    const addr = findExport('PyEval_RestoreThread');
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function() {
            this._t0 = nowUs();
        },
        onLeave: function() {
            const now   = nowUs();
            const osTid = this.threadId;
            const ptid  = pythonTid();
            const vtid  = (ptid | GIL_TID_BIT) >>> 0;
            // If take_gil symbol already fired (not inlined), _holdStart is
            // already set — skip the wait emit to avoid double-counting.
            if (!_holdStart[osTid]) {
                const waitDur = now - this._t0;
                if (waitDur >= MIN_WAIT_US) {
                    emit(now, waitDur, vtid, 0);  // gil_wait
                }
            }
            _holdStart[osTid] = {t: now, ptid: ptid, vtid: vtid};
        }
    });
}

// Hook blocking sleep and I/O calls to emit events on the GIL row.
// kind=3 sleeping; kind=4 select; kind=5 poll; kind=6 kevent; kind=7 epoll; kind=8 pselect
function attachBlockingHooks() {
    // [symbol, kind] pairs — variants of the same syscall share a kind.
    const hooks = [
        ['nanosleep',     3], ['clock_nanosleep', 3],
    ].concat(Process.platform === 'darwin' ? [
        ['select',                         4],
        ['select$DARWIN_EXTSN',            4],
        ['select$NOCANCEL',                4],
        ['select$DARWIN_EXTSN$NOCANCEL',   4],
        ['poll',                           5],
        ['kevent',                         6],
        ['kevent64',                       6],
        ['pselect',                        8],
        ['pselect$DARWIN_EXTSN',           8],
    ] : [
        ['select',       4], ['pselect64', 8],
        ['poll',         5], ['ppoll',     5],
        ['epoll_wait',   7], ['epoll_pwait', 7],
    ]);
    for (const [name, kind] of hooks) {
        const addr = findExport(name);
        if (!addr) continue;
        Interceptor.attach(addr, {
            onEnter: function() {
                const vtid = (pythonTid() | GIL_TID_BIT) >>> 0;
                // Suppress nested calls: kevent() may call kevent64() internally,
                // and BOLT may produce multiple symbols for the same function.
                // Only the outermost call for a given vtid emits an event.
                if (_ioActive[vtid]) { this._vtid = null; return; }
                _ioActive[vtid] = true;
                this._t0   = nowUs();
                this._vtid = vtid;
            },
            onLeave: function() {
                if (this._vtid === null) return;
                delete _ioActive[this._vtid];
                const dur = nowUs() - this._t0;
                if (dur > 0) emit(nowUs(), dur, this._vtid, kind);
            }
        });
    }
}

(function main() {
    let takeAddrs = findBySymbol('take_gil');
    let dropAddrs = findBySymbol('drop_gil');

    // Stripped binary fallback: use exported CPython API.
    // findExport() uses Module.findGlobalExportByName where available, which
    // works on BOLT-optimised binaries where the .gnu.hash table is stale.
    if (takeAddrs.length === 0) {
        const a = findExport('PyEval_RestoreThread');
        if (a) takeAddrs = [a];
    }
    if (dropAddrs.length === 0) {
        const a = findExport('PyEval_SaveThread');
        if (a) dropAddrs = [a];
    }

    if (takeAddrs.length === 0 || dropAddrs.length === 0) {
        send({type: 'error', message:
            'GIL symbols not found (take=' + takeAddrs.length +
            ', drop=' + dropAddrs.length + ')'});
        return;
    }

    attachGilHooks(takeAddrs, dropAddrs);
    attachSaveThreadHook();
    attachRestoreThreadHook();
    attachBlockingHooks();
    send({type: 'ready', take: takeAddrs.length, drop: dropAddrs.length});
    _flushTimer = setInterval(flush, 50);
})();

rpc.exports = {
    getThreadNames: function() { return queryThreadNames(); },
    stop: function() {
        if (_flushTimer !== null) { clearInterval(_flushTimer); _flushTimer = null; }
        // Detach all hooks first so the target doesn't execute into a torn-down
        // trampoline after we unload the script / detach the session.
        Interceptor.detachAll();
        // Emit truncated held events for threads still holding the GIL at detach time.
        const now = nowUs();
        for (const osTid in _holdStart) {
            const entry = _holdStart[osTid];
            emit(now, now - entry.t, entry.vtid, 1);
        }
        flush();
        send({type: 'done', dropped: _dropped});
    },
};
"""


# ── Python wrapper ───────────────────────────────────────────────────────────


class FridaGilTracker:
    """Attach to a running process and record GIL contention into a keke trace.

    Events:
      green (thread_state_running) — GIL held
      red   (bad)                  — blocked waiting to acquire
      gray  (sleeping)

    GC coloring is not supported in attach mode (requires in-process hooks).

    Requires frida >= 16
    """

    def __init__(
        self,
        pid: int,
        tracer: Optional[keke.TraceOutput] = None,
        min_wait_us: int = 0,
    ) -> None:
        self._pid = pid
        self._tracer = tracer
        self._min_wait_us = min_wait_us
        self._dropped = 0
        self._done = threading.Event()
        self._session: Optional[Any] = None
        self._script: Optional[Any] = None
        self._seen_tids: set[int] = set()
        self._thread_names: dict[int, str] = {}  # native_id -> Python thread name

    def __enter__(self) -> "FridaGilTracker":
        import frida  # noqa: PLC0415

        # The target process may not have finished initialising (e.g. in exec
        # mode, Popen() returns before the child has loaded the Python runtime).
        # Retry attach with linear back-off up to ~5 s before giving up.
        last_exc: Exception = RuntimeError("no attempts made")
        for attempt in range(10):
            try:
                self._session = frida.attach(self._pid)
                break
            except Exception as exc:
                last_exc = exc
                if attempt == 0:
                    print(
                        f"[zap-trace] waiting for pid {self._pid} to be ready…",
                        file=sys.stderr,
                    )
                time.sleep(0.1 * (attempt + 1))
        else:
            raise last_exc

        js = _AGENT_JS.replace("{min_wait_us}", str(self._min_wait_us))
        self._script = self._session.create_script(js)
        self._script.on("message", self._on_message)
        self._script.load()
        names_json = self._script.exports_sync.get_thread_names()
        if names_json:
            self._thread_names = {
                int(k): v for k, v in json.loads(names_json).items()
            }
        return self

    def _on_message(self, message: Any, data: Optional[bytes]) -> None:
        if message["type"] != "send":
            return
        payload = message["payload"]
        kind = payload.get("type")
        if kind == "events":
            self._dropped += payload.get("dropped", 0)
            if data:
                self._ingest(data)
        elif kind == "done":
            self._dropped += payload.get("dropped", 0)
            self._done.set()
        elif kind == "ready":
            pass  # could log take/drop counts
        elif kind == "error":
            print(f"[frida_gil] {payload['message']}", file=sys.stderr)

    def _ingest(self, data: bytes) -> None:
        t = self._tracer if self._tracer is not None else keke.TRACER
        if t is None:
            return
        pid = self._pid  # target's PID, not the controller's
        n = len(data) // _SIZE
        for timestamp, duration_us, tid, event_kind in struct.iter_unpack(
            _FMT, data[: n * _SIZE]
        ):
            if event_kind not in _NAME:
                continue
            # tid from the wire is native_id | _GIL_TID_BIT (internal protocol).
            # For the JSON output use native_id - 1 as the track TID.
            # Perfetto ignores thread_sort_index from legacy JSON and orders tracks
            # by TID value instead; using native_id - 1 places the GIL row
            # immediately above the keke row (native_id) for the same thread.
            # sort_index is set to the same value so Chrome trace viewer agrees.
            real_native_id = tid & ~_GIL_TID_BIT
            json_tid = real_native_id - 1
            if tid not in self._seen_tids:
                self._seen_tids.add(tid)
                py_name = self._thread_names.get(real_native_id)
                label = f"Thread: {py_name}" if py_name else f"GIL: {py_name}"
                for name, args in (
                    ("thread_name", {"name": label}),
                    ("thread_sort_index", {"sort_index": json_tid}),
                ):
                    t.queue.put(
                        keke.EVENT(
                            {
                                "pid": pid,
                                "tid": json_tid,
                                "ts": 0,
                                "ph": "M",
                                "cat": "__metadata",
                                "name": name,
                                "args": args,
                            }
                        )
                    )
            t.put(
                keke.EVENT(
                    {
                        "pid": pid,
                        "name": _NAME[event_kind],
                        "cat": _CAT[event_kind],
                        "cname": _CNAME[event_kind],
                        "ph": "X",
                        "ts": timestamp - duration_us,
                        "dur": duration_us,
                        "tid": json_tid,
                    }
                ),
                False,
            )

    def __exit__(self, *_: object) -> None:
        if self._script is not None:
            try:
                self._script.exports_sync.stop()
                self._done.wait(timeout=3.0)
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

    @property
    def dropped(self) -> int:
        """Events lost because the JS-side batch buffer was full."""
        return self._dropped
