"""Unit tests for FridaKekeCollector (frida and OS mocked)."""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import keke
import pytest
from zap_trace.keke_tap import FridaKekeCollector, _fifo_read_loop

# ── _fifo_read_loop ───────────────────────────────────────────────────────────


def _make_jsonl(*objs) -> str:
    return "".join(json.dumps(obj, separators=(",", ":")) + "\n" for obj in objs)


class TestFifoReadLoop:
    def _run_loop(self, pipe_data: str):
        r, w = os.pipe()
        encoded = pipe_data.encode()
        os.write(w, encoded)
        os.close(w)
        events = []
        mock_tracer = MagicMock()
        mock_tracer.put = lambda ev, with_tid: events.append(ev)
        _fifo_read_loop(r, mock_tracer, [0])
        try:
            os.close(r)
        except OSError:
            pass
        return events

    def test_single_event(self):
        events = self._run_loop(_make_jsonl({"ph": "X", "name": "foo"}))
        assert len(events) == 1
        assert events[0]["name"] == "foo"

    def test_multiple_events(self):
        events = self._run_loop(_make_jsonl(*[{"n": i} for i in range(3)]))
        assert len(events) == 3

    def test_eof_on_empty_pipe(self):
        events = self._run_loop("")
        assert events == []

    def test_malformed_json_skipped(self):
        bad = "not-json\n"
        good = _make_jsonl({"ph": "X"})
        events = self._run_loop(bad + good)
        assert len(events) == 1

    def test_blank_lines_skipped(self):
        data = "\n" + _make_jsonl({"ph": "X"}) + "\n"
        events = self._run_loop(data)
        assert len(events) == 1

    def test_uses_keke_tracer_when_tracer_none(self):
        msg = _make_jsonl({"ph": "X"})
        r, w = os.pipe()
        os.write(w, msg.encode())
        os.close(w)
        events = []
        mock_tracer = MagicMock()
        mock_tracer.put = lambda ev, with_tid: events.append(ev)
        with patch("zap_trace.keke_tap.keke") as mock_keke:
            mock_keke.TRACER = mock_tracer
            mock_keke.EVENT = keke.EVENT
            _fifo_read_loop(r, None, [0])
        try:
            os.close(r)
        except OSError:
            pass
        assert len(events) == 1


# ── FridaKekeCollector ────────────────────────────────────────────────────────


def _make_session_and_script():
    script = MagicMock()
    script.exports_sync.inject = MagicMock(return_value={"ok": True})
    script.exports_sync.cleanup = MagicMock()
    session = MagicMock()
    session.create_script = MagicMock(return_value=script)
    return session, script


class TestFridaKekeCollectorEnterExit:
    def _collector_with_mocks(self, tmp_path):
        fifo = str(tmp_path / "test.fifo")
        session, script = _make_session_and_script()
        mock_frida = MagicMock()
        mock_frida.attach.return_value = session
        return fifo, session, script, mock_frida

    def test_enter_creates_fifo_and_attaches(self, tmp_path):
        fifo, session, script, mock_frida = self._collector_with_mocks(tmp_path)
        col = FridaKekeCollector(pid=1234, fifo_path=fifo)
        with patch.dict("sys.modules", {"frida": mock_frida}):
            col.__enter__()
        assert os.path.exists(fifo)
        mock_frida.attach.assert_called_once_with(1234)
        script.load.assert_called_once()
        script.exports_sync.inject.assert_called_once_with(fifo)
        col.__exit__(None, None, None)

    def test_exit_calls_cleanup_and_detach(self, tmp_path):
        fifo, session, script, mock_frida = self._collector_with_mocks(tmp_path)
        col = FridaKekeCollector(pid=1, fifo_path=fifo)
        with patch.dict("sys.modules", {"frida": mock_frida}):
            col.__enter__()
            col.__exit__(None, None, None)
        script.exports_sync.cleanup.assert_called_once()
        script.unload.assert_called_once()
        session.detach.assert_called_once()

    def test_exit_suppresses_frida_errors(self, tmp_path):
        fifo, session, script, mock_frida = self._collector_with_mocks(tmp_path)
        script.exports_sync.cleanup.side_effect = RuntimeError("gone")
        session.detach.side_effect = RuntimeError("gone")
        col = FridaKekeCollector(pid=1, fifo_path=fifo)
        with patch.dict("sys.modules", {"frida": mock_frida}):
            col.__enter__()
            col.__exit__(None, None, None)  # must not raise

    def test_disconnect_is_idempotent(self, tmp_path):
        fifo, session, script, mock_frida = self._collector_with_mocks(tmp_path)
        col = FridaKekeCollector(pid=1, fifo_path=fifo)
        with patch.dict("sys.modules", {"frida": mock_frida}):
            col.__enter__()
            col.disconnect()
            col.disconnect()  # second call must not raise or double-cleanup
        session.detach.assert_called_once()

    def test_fifo_path_property(self, tmp_path):
        fifo = str(tmp_path / "my.fifo")
        col = FridaKekeCollector(pid=1, fifo_path=fifo)
        assert col.fifo_path == fifo

    def test_inject_failure_raises(self, tmp_path):
        fifo, session, script, mock_frida = self._collector_with_mocks(tmp_path)
        script.exports_sync.inject.return_value = {
            "ok": False,
            "error": "libpython not found",
        }
        col = FridaKekeCollector(pid=1, fifo_path=fifo)
        with patch.dict("sys.modules", {"frida": mock_frida}):
            with pytest.raises(RuntimeError, match="libpython not found"):
                col.__enter__()
        col.__exit__(None, None, None)

    def test_context_manager_returns_self(self, tmp_path):
        fifo, session, script, mock_frida = self._collector_with_mocks(tmp_path)
        col = FridaKekeCollector(pid=1, fifo_path=fifo)
        with patch.dict("sys.modules", {"frida": mock_frida}):
            result = col.__enter__()
        assert result is col
        col.__exit__(None, None, None)
