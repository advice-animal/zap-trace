# Frida symbol hunting: lessons from GIL tracing

## What we're hooking and why it's hard

GIL tracing needs to intercept two internal CPython functions:

- `take_gil(tstate)` — called by a thread to acquire the GIL (blocks until available)
- `drop_gil(ceval, tstate, final)` — called to release the GIL (eval-loop preemption path)

These are `static` functions in `Python/ceval_gil.c`.  They are not in `.dynsym` (the
dynamic symbol table), so the usual `Module.findExportByName` / `Module.getExportByName`
approaches don't find them.  What works depends on how the binary was compiled.

---

## Timing API

`Process.hrtime()` was removed in Frida 16.  Use native clock functions instead:

```javascript
const _nowUs = (function() {
    if (Process.platform === 'darwin') {
        // mach_absolute_time() + mach_timebase_info for nanoseconds → microseconds
        const _mach_abs = new NativeFunction(
            Module.findGlobalExportByName('mach_absolute_time'), 'uint64', []);
        const _info = Memory.alloc(8);
        new NativeFunction(
            Module.findGlobalExportByName('mach_timebase_info'), 'int', ['pointer'])(_info);
        const numer = _info.readU32(), denom = _info.add(4).readU32();
        return () => Number(_mach_abs()) * numer / denom / 1000;
    } else {
        // Linux: clock_gettime(CLOCK_MONOTONIC)
        const _cgt = new NativeFunction(
            Module.findGlobalExportByName('clock_gettime'), 'int', ['int', 'pointer']);
        const _ts = Memory.alloc(16);
        return () => {
            _cgt(1, _ts);
            return Number(_ts.readU64()) * 1e6 + Number(_ts.add(8).readU64()) / 1e3;
        };
    }
})();
```

---

## macOS: BOLT-optimised binaries (uv Python)

Python distributed by uv (and Homebrew's `python3`) is BOLT-optimised.  BOLT is a
post-link binary optimizer that reorders code for cache locality.  This breaks two things:

### `.gnu.hash` is stale → `Module.findExportByName(null, name)` fails

BOLT rewrites function addresses but may not update the `.gnu.hash` table used by
`Module.findExportByName`.  **Fix**: use `Module.findGlobalExportByName(name)` (Frida 16+),
which reads `.dynsym` directly:

```javascript
function findExport(name) {
    if (typeof Module.findGlobalExportByName === 'function') {
        const p = Module.findGlobalExportByName(name);
        if (p && !p.isNull()) return p;
    }
    // Fall back to per-module scan (older Frida)
    for (const mod of Process.enumerateModules()) {
        try {
            const p = mod.getExportByName(name);
            if (p && !p.isNull()) return p;
        } catch(_) {}
    }
    return null;
}
```

### `take_gil`/`drop_gil` appear as type `'section'` not `'function'`

BOLT reorganises functions into new text sections.  The resulting symbol table entries
have `STT_SECTION` (type `'section'`) rather than `STT_FUNC` (type `'function'`).
`enumerateSymbols()` still returns them, but the type check `sym.type === 'function'`
misses them.

**Additionally**, BOLT appends `.llvm.<hash>` to symbol names to make them unique after
reordering.  These are valid canonical names, not aliases.

**Fix**: accept both `'function'` and `'section'` type symbols, and match both bare names
and `.llvm.<digits>` suffixes:

```javascript
function isCanonical(name, prefix) {
    if (!name.startsWith(prefix)) return false;
    const rest = name.slice(prefix.length);
    if (rest === '') return true;
    if (!rest.startsWith('.llvm.')) return false;
    return /^[0-9]+$/.test(rest.slice(6));
}

function findBySymbol(prefix) {
    for (const mod of Process.enumerateModules()) {
        if (!mod.path.match(/python/i)) continue;
        try {
            for (const sym of mod.enumerateSymbols()) {
                if ((sym.type === 'function' || sym.type === 'section')
                        && isCanonical(sym.name, prefix)) {
                    // sym.address is the hook target
                }
            }
        } catch(_) {}
    }
}
```

### `drop_gil` is inlined into `PyEval_SaveThread` on the I/O path

Even with the above fixes, `drop_gil` may only fire for the **eval-loop preemption path**
(threads yielding voluntarily every ~5ms).  The **I/O release path** (`PyEval_SaveThread`
→ `_PyEval_ReleaseLock` → `drop_gil`) uses an inlined copy of `drop_gil` that BOLT puts
in a different section, far from the `drop_gil.llvm.NNN` symbol.

Symptom: `take_gil` fires ~200×/s; `drop_gil` fires 0×/s against an I/O-bound process.
`PyEval_SaveThread` fires ~200×/s.

**Fix**: hook **both** `drop_gil` (eval breaker path) and `PyEval_SaveThread` (I/O path).
Make the "pending hold" deletion idempotent so non-BOLT binaries (where
`PyEval_SaveThread` calls through to `drop_gil`) don't double-count:

```javascript
// _holdStart[osTid] = {t: acquireTime, ptid: pythonTid}
function emitHeld(osTid) {
    const entry = _holdStart[osTid];
    if (entry !== undefined) {
        const now = nowUs();
        emit(now, now - entry.t, entry.ptid, 1);
        delete _holdStart[osTid];   // idempotent: second caller is a no-op
    }
}
// Attach emitHeld to both drop_gil symbol AND PyEval_SaveThread
```

### Thread ID mapping

`this.threadId` inside a Frida interceptor returns the **Mach port ID** on macOS (a small
integer, e.g. 4611).  Python's `threading.get_ident()` returns the **pthread address** (a
large pointer, e.g. `0x7fa5b2c3d0a0 ≈ 1.4×10¹⁴`).  These are different namespaces.

If GIL events use `this.threadId` as `tid`, they land on separate trace rows from keke
events for the same OS thread.

**Fix**: call `pthread_self()` from inside the interceptor to get the Python-compatible ID:

```javascript
const _pthread_self = new NativeFunction(
    Module.findGlobalExportByName('pthread_self'), 'pointer', []);
function pythonTid() {
    const s = _pthread_self().toString();
    return s.startsWith('0x') ? parseInt(s, 16) : parseInt(s, 10);
}
```

Store `{t: now, ptid: pythonTid()}` in `_holdStart` and use `ptid` when emitting events.

---

## Linux: stripped system Python

On stripped system Python (e.g. `python3` on Ubuntu), `take_gil`/`drop_gil` are absent
entirely from the symbol table.  `PyEval_RestoreThread` and `PyEval_SaveThread` are
present in `.dynsym` (they are part of the public C API).

Fallback (already in the agent):
```javascript
if (takeAddrs.length === 0) {
    const a = findExport('PyEval_RestoreThread');
    if (a) takeAddrs = [a];
}
if (dropAddrs.length === 0) {
    const a = findExport('PyEval_SaveThread');
    if (a) dropAddrs = [a];
}
```

On Linux with debug symbols (`python3-dbg` or a source build), `take_gil`/`drop_gil` are
present as `STT_FUNC` symbols and `findBySymbol` finds them directly.

---

## Debugging checklist

```javascript
// 1. What GIL-related symbols exist, and what are their types?
for (const mod of Process.enumerateModules()) {
    if (!mod.path.match(/python/i)) continue;
    for (const sym of mod.enumerateSymbols()) {
        if (sym.name && sym.name.includes('gil'))
            console.log(sym.type, sym.name, sym.address);
    }
}

// 2. Are PyEval_* present in dynsym?
console.log('SaveThread:', Module.findGlobalExportByName('PyEval_SaveThread'));
console.log('RestoreThread:', Module.findGlobalExportByName('PyEval_RestoreThread'));

// 3. Are hooks actually firing?
let n = 0;
Interceptor.attach(addr, { onEnter: function() { n++; } });
setInterval(() => { console.log('count/s:', n); n = 0; }, 1000);

// 4. If take fires but drop doesn't, check inlining:
//    Hook PyEval_SaveThread separately and count it.
//    If SaveThread fires but drop_gil doesn't, drop_gil is inlined.
```
