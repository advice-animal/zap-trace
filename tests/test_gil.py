"""Unit tests for FridaGilTracker (frida mocked)."""

from __future__ import annotations

import json
import struct
from io import StringIO
from unittest.mock import MagicMock, patch

import keke
import pytest
from zap_trace.gil import _FMT, _GIL_TID_BIT, FridaGilTracker


def _make_event(ts: int, dur: int, tid: int, kind: int) -> bytes:
    """Pack a single binary event as the JS agent would produce it."""
    return struct.pack(_FMT, ts, dur, tid, kind)


def _make_frida_session():
    script = MagicMock()
    script.exports_sync.stop = MagicMock()
    script.exports_sync.get_thread_names = MagicMock(return_value="{}")
    session = MagicMock()
    session.create_script = MagicMock(return_value=script)
    return session, script


class TestFridaGilTrackerEnterExit:
    def test_enter_attaches_and_loads(self):
        session, script = _make_frida_session()
        mock_frida = MagicMock()
        mock_frida.attach.return_value = session

        with patch.dict("sys.modules", {"frida": mock_frida}):
            tracker = FridaGilTracker(pid=1234)
            tracker.__enter__()

        mock_frida.attach.assert_called_once_with(1234)
        session.create_script.assert_called_once()
        script.on.assert_called_once_with("message", tracker._on_message)
        script.load.assert_called_once()
        tracker.__exit__(None, None, None)

    def test_exit_stops_and_detaches(self):
        session, script = _make_frida_session()
        mock_frida = MagicMock()
        mock_frida.attach.return_value = session

        with patch.dict("sys.modules", {"frida": mock_frida}):
            tracker = FridaGilTracker(pid=1)
            tracker.__enter__()
            # Simulate "done" event so _done is set
            tracker._done.set()
            tracker.__exit__(None, None, None)

        script.exports_sync.stop.assert_called_once()
        script.unload.assert_called_once()
        session.detach.assert_called_once()

    def test_exit_suppresses_frida_errors(self):
        session, script = _make_frida_session()
        script.exports_sync.stop.side_effect = RuntimeError("frida gone")
        session.detach.side_effect = RuntimeError("already gone")
        mock_frida = MagicMock()
        mock_frida.attach.return_value = session

        with patch.dict("sys.modules", {"frida": mock_frida}):
            tracker = FridaGilTracker(pid=1)
            tracker.__enter__()
            tracker.__exit__(None, None, None)  # must not raise

    def test_context_manager_returns_self(self):
        session, script = _make_frida_session()
        mock_frida = MagicMock()
        mock_frida.attach.return_value = session

        with patch.dict("sys.modules", {"frida": mock_frida}):
            tracker = FridaGilTracker(pid=42)
            result = tracker.__enter__()
            assert result is tracker
            tracker.__exit__(None, None, None)


class TestIngest:
    def _make_tracker_with_tracer(self):
        """Return a tracker and a real keke.TraceOutput (StringIO-backed)."""
        out = StringIO()
        tracer = keke.TraceOutput(out, close_output_file=False)
        tracer.__enter__()
        tracker = FridaGilTracker(pid=0, tracer=tracer)
        return tracker, tracer, out

    def teardown_method(self):
        import keke as _keke

        if _keke.TRACER is not None:
            try:
                _keke.TRACER.__exit__(None, None, None)
            except Exception:
                pass

    def test_ingest_wait_event(self):
        tracker, tracer, _ = self._make_tracker_with_tracer()
        data = _make_event(ts=2000, dur=500, tid=10, kind=0)
        tracker._ingest(data)
        tracer.__exit__(None, None, None)

    def test_ingest_held_event(self):
        tracker, tracer, _ = self._make_tracker_with_tracer()
        data = _make_event(ts=3000, dur=1000, tid=20, kind=1)
        tracker._ingest(data)
        tracer.__exit__(None, None, None)

    def test_ingest_sleeping_event(self):
        tracker, tracer, _ = self._make_tracker_with_tracer()
        data = _make_event(ts=4000, dur=200, tid=30, kind=3)
        tracker._ingest(data)
        tracer.__exit__(None, None, None)

    def test_ingest_unknown_kind_skipped(self):
        tracker, tracer, _ = self._make_tracker_with_tracer()
        data = _make_event(ts=5000, dur=100, tid=1, kind=99)
        tracker._ingest(data)
        # No events put beyond thread metadata
        tracer.__exit__(None, None, None)

    def test_thread_name_emitted_once(self):
        tracker, tracer, _ = self._make_tracker_with_tracer()
        data = _make_event(ts=1000, dur=100, tid=7, kind=1)
        tracker._ingest(data)
        tracker._ingest(data)  # same tid again
        assert tracker._seen_tids == {7}
        tracer.__exit__(None, None, None)

    def test_ingest_multiple_events(self):
        tracker, tracer, _ = self._make_tracker_with_tracer()
        data = b"".join(
            _make_event(ts=1000 + i * 100, dur=50, tid=1, kind=1) for i in range(5)
        )
        tracker._ingest(data)
        tracer.__exit__(None, None, None)

    def test_ingest_truncated_data_ignored(self):
        tracker, tracer, _ = self._make_tracker_with_tracer()
        # Partial event (not a multiple of _SIZE)
        data = _make_event(ts=1000, dur=100, tid=1, kind=0)[:10]
        tracker._ingest(data)  # must not raise
        tracer.__exit__(None, None, None)

    def test_ingest_no_tracer_is_noop(self):
        tracker = FridaGilTracker(pid=0, tracer=None)
        # No keke.TRACER active — _ingest should silently do nothing
        data = _make_event(ts=1000, dur=100, tid=1, kind=0)
        tracker._ingest(data)

    def test_dropped_accumulates(self):
        tracker = FridaGilTracker(pid=0)
        tracker._on_message(
            {"type": "send", "payload": {"type": "events", "dropped": 3}}, b""
        )
        tracker._on_message(
            {"type": "send", "payload": {"type": "events", "dropped": 5}}, b""
        )
        assert tracker.dropped == 8

    def test_done_message_sets_event(self):
        tracker = FridaGilTracker(pid=0)
        assert not tracker._done.is_set()
        tracker._on_message(
            {"type": "send", "payload": {"type": "done", "dropped": 2}}, None
        )
        assert tracker._done.is_set()
        assert tracker.dropped == 2


def _flush(tracer, out):
    """Exit tracer and return the non-empty events from the JSON output."""
    tracer.__exit__(None, None, None)
    return [e for e in json.loads(out.getvalue()) if e]


def _setup():
    """Return (tracker, tracer, out) with a real keke.TraceOutput."""
    out = StringIO()
    tracer = keke.TraceOutput(out, close_output_file=False)
    tracer.__enter__()
    tracker = FridaGilTracker(pid=999, tracer=tracer)
    return tracker, tracer, out


class TestIngestOutput:
    """Tests that verify the actual JSON events produced by _ingest()."""

    def teardown_method(self):
        if keke.TRACER is not None:
            try:
                keke.TRACER.__exit__(None, None, None)
            except Exception:
                pass

    # ── virtual tid ──────────────────────────────────────────────────────────

    def test_virtual_tid_is_native_id_times_10_minus_1(self):
        tracker, tracer, out = _setup()
        native_id = 12345
        raw_tid = native_id | _GIL_TID_BIT
        tracker._ingest(_make_event(ts=2000, dur=500, tid=raw_tid, kind=1))
        events = _flush(tracer, out)
        trace_events = [e for e in events if e.get("ph") == "X"]
        assert len(trace_events) == 1
        assert trace_events[0]["tid"] == native_id * 10 - 1

    def test_virtual_tid_no_collision_with_consecutive_native_ids(self):
        """GIL row TID must not equal any real thread's native_id."""
        tracker, tracer, out = _setup()
        native_id = 6001316  # realistic get_native_id() value
        raw_tid = native_id | _GIL_TID_BIT
        tracker._ingest(_make_event(ts=5000, dur=100, tid=raw_tid, kind=1))
        events = _flush(tracer, out)
        trace_events = [e for e in events if e.get("ph") == "X"]
        # native_id * 10 - 1 is always > native_id, so can't collide with
        # this thread's own native_id or the next consecutive native_id.
        assert trace_events[0]["tid"] == native_id * 10 - 1

    # ── thread metadata ───────────────────────────────────────────────────────

    def test_thread_name_underscore_prefix(self):
        tracker, tracer, out = _setup()
        native_id = 54321
        raw_tid = native_id | _GIL_TID_BIT
        tracker._ingest(_make_event(ts=1000, dur=100, tid=raw_tid, kind=1))
        events = _flush(tracer, out)
        name_events = [
            e
            for e in events
            if e.get("ph") == "M"
            and e.get("name") == "thread_name"
            and e.get("tid") == native_id * 10 - 1
        ]
        assert len(name_events) == 1
        assert name_events[0]["args"]["name"] == f"GIL state {native_id}"

    def test_thread_sort_index_is_native_id_times_10_minus_1(self):
        tracker, tracer, out = _setup()
        native_id = 8888
        raw_tid = native_id | _GIL_TID_BIT
        tracker._ingest(_make_event(ts=1000, dur=100, tid=raw_tid, kind=1))
        events = _flush(tracer, out)
        sort_events = [
            e
            for e in events
            if e.get("ph") == "M"
            and e.get("name") == "thread_sort_index"
            and e.get("tid") == native_id * 10 - 1
        ]
        assert len(sort_events) == 1
        assert sort_events[0]["args"]["sort_index"] == native_id * 10 - 1

    def test_thread_metadata_emitted_once_per_tid(self):
        tracker, tracer, out = _setup()
        raw_tid = 111 | _GIL_TID_BIT
        tracker._ingest(_make_event(ts=1000, dur=100, tid=raw_tid, kind=1))
        tracker._ingest(_make_event(ts=2000, dur=100, tid=raw_tid, kind=1))
        events = _flush(tracer, out)
        name_events = [
            e
            for e in events
            if e.get("ph") == "M"
            and e.get("name") == "thread_name"
            and e.get("tid") == 111 * 10 - 1
        ]
        assert len(name_events) == 1  # not duplicated on second call

    def test_thread_metadata_emitted_per_unique_tid(self):
        tracker, tracer, out = _setup()
        tid_a = 111 | _GIL_TID_BIT
        tid_b = 222 | _GIL_TID_BIT
        tracker._ingest(_make_event(ts=1000, dur=100, tid=tid_a, kind=1))
        tracker._ingest(_make_event(ts=2000, dur=100, tid=tid_b, kind=1))
        events = _flush(tracer, out)
        name_events = [
            e
            for e in events
            if e.get("ph") == "M"
            and e.get("name") == "thread_name"
            and e.get("pid") == 999
        ]
        tids = {e["tid"] for e in name_events}
        assert tids == {111 * 10 - 1, 222 * 10 - 1}

    # ── timestamp and duration ────────────────────────────────────────────────

    def test_ts_is_start_not_end(self):
        """ts in the wire format is the END timestamp; output ts must be ts - dur."""
        tracker, tracer, out = _setup()
        raw_tid = 77 | _GIL_TID_BIT
        tracker._ingest(_make_event(ts=3000, dur=800, tid=raw_tid, kind=1))
        events = _flush(tracer, out)
        trace_events = [e for e in events if e.get("ph") == "X"]
        assert trace_events[0]["ts"] == 3000 - 800
        assert trace_events[0]["dur"] == 800

    # ── event fields ──────────────────────────────────────────────────────────

    def test_held_event_fields(self):
        tracker, tracer, out = _setup()
        raw_tid = 42 | _GIL_TID_BIT
        tracker._ingest(_make_event(ts=2000, dur=500, tid=raw_tid, kind=1))
        events = _flush(tracer, out)
        trace_events = [e for e in events if e.get("ph") == "X"]
        e = trace_events[0]
        assert e["name"] == "GIL held"
        assert e["cat"] == "gil_held"
        assert e["cname"] == "thread_state_running"
        assert e["pid"] == 999

    def test_wait_event_fields(self):
        tracker, tracer, out = _setup()
        raw_tid = 43 | _GIL_TID_BIT
        tracker._ingest(_make_event(ts=2000, dur=500, tid=raw_tid, kind=0))
        events = _flush(tracer, out)
        trace_events = [e for e in events if e.get("ph") == "X"]
        e = trace_events[0]
        assert e["name"] == "GIL wait"
        assert e["cat"] == "gil_wait"
        assert e["cname"] == "bad"

    def test_sleeping_event_fields(self):
        tracker, tracer, out = _setup()
        raw_tid = 44 | _GIL_TID_BIT
        tracker._ingest(_make_event(ts=2000, dur=500, tid=raw_tid, kind=3))
        events = _flush(tracer, out)
        trace_events = [e for e in events if e.get("ph") == "X"]
        e = trace_events[0]
        assert e["name"] == "sleeping"
        assert e["cat"] == "sleeping"
        assert e["cname"] == "thread_state_iowait"

    @pytest.mark.parametrize(
        "kind,expected_name",
        [
            (4, "select"),
            (5, "poll"),
            (6, "kevent"),
            (7, "epoll_wait"),
            (8, "pselect"),
        ],
    )
    def test_iowait_event_fields(self, kind, expected_name):
        tracker, tracer, out = _setup()
        raw_tid = 45 | _GIL_TID_BIT
        tracker._ingest(_make_event(ts=2000, dur=500, tid=raw_tid, kind=kind))
        events = _flush(tracer, out)
        trace_events = [e for e in events if e.get("ph") == "X" and e.get("pid") == 999]
        e = trace_events[0]
        assert e["name"] == expected_name
        assert e["cat"] == "io_wait"
        assert e["cname"] == "thread_state_unknown"

    # ── batch handling ────────────────────────────────────────────────────────

    def test_batch_of_n_events_all_appear(self):
        tracker, tracer, out = _setup()
        raw_tid = 55 | _GIL_TID_BIT
        n = 10
        data = b"".join(
            _make_event(ts=1000 + i * 100, dur=50, tid=raw_tid, kind=1)
            for i in range(n)
        )
        tracker._ingest(data)
        events = _flush(tracer, out)
        trace_events = [e for e in events if e.get("ph") == "X"]
        assert len(trace_events) == n

    def test_mixed_kinds_in_batch(self):
        tracker, tracer, out = _setup()
        raw_tid = 66 | _GIL_TID_BIT
        data = (
            _make_event(ts=1000, dur=100, tid=raw_tid, kind=0)  # wait
            + _make_event(ts=2000, dur=200, tid=raw_tid, kind=1)  # held
            + _make_event(ts=3000, dur=300, tid=raw_tid, kind=3)  # sleeping
        )
        tracker._ingest(data)
        events = _flush(tracer, out)
        trace_events = [e for e in events if e.get("ph") == "X"]
        names = {e["name"] for e in trace_events}
        assert names == {"GIL wait", "GIL held", "sleeping"}

    # ── correctness invariants ────────────────────────────────────────────────

    def test_no_cross_thread_held_overlaps(self):
        """Two different threads must never both show 'GIL held' simultaneously."""
        tracker, tracer, out = _setup()
        tid_a = 100 | _GIL_TID_BIT
        tid_b = 200 | _GIL_TID_BIT
        # Non-overlapping: a holds 1000-2000, b holds 2000-3000
        data = _make_event(ts=2000, dur=1000, tid=tid_a, kind=1) + _make_event(
            ts=3000, dur=1000, tid=tid_b, kind=1
        )
        tracker._ingest(data)
        events = _flush(tracer, out)
        held = sorted(
            [e for e in events if e.get("cat") == "gil_held"],
            key=lambda e: e["ts"],
        )
        overlaps = 0
        for i, a in enumerate(held):
            a_end = a["ts"] + a["dur"]
            for b in held[i + 1 :]:
                if b["ts"] >= a_end:
                    break
                if b["tid"] == a["tid"]:
                    continue
                overlaps += 1
        assert overlaps == 0

    def test_unknown_kind_produces_no_trace_event(self):
        tracker, tracer, out = _setup()
        raw_tid = 77 | _GIL_TID_BIT
        tracker._ingest(_make_event(ts=1000, dur=100, tid=raw_tid, kind=42))
        events = _flush(tracer, out)
        trace_events = [e for e in events if e.get("ph") == "X"]
        assert trace_events == []

    def test_metadata_pid_matches_target(self):
        tracker, tracer, out = _setup()
        raw_tid = 88 | _GIL_TID_BIT
        tracker._ingest(_make_event(ts=1000, dur=100, tid=raw_tid, kind=1))
        events = _flush(tracer, out)
        meta = [e for e in events if e.get("ph") == "M" and e.get("tid") == 88 * 10 - 1]
        assert all(e["pid"] == 999 for e in meta)
