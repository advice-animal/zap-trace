"""Tests for the zap-trace CLI entry point."""

from __future__ import annotations

import sys
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest
from zap_trace.__main__ import _build_parser, _main

# ── Argument parsing ──────────────────────────────────────────────────────────


class TestParser:
    def test_pid_and_gil(self):
        p = _build_parser()
        args = p.parse_args(["-p", "1234", "--gil"])
        assert args.pid == 1234
        assert args.gil is True
        assert args.keke is False

    def test_pid_and_keke(self):
        p = _build_parser()
        args = p.parse_args(["-p", "1234", "--keke"])
        assert args.pid == 1234
        assert args.keke is True

    def test_pid_both(self):
        p = _build_parser()
        args = p.parse_args(["-p", "1234", "--gil", "--keke"])
        assert args.gil and args.keke

    def test_duration(self):
        p = _build_parser()
        args = p.parse_args(["-p", "1", "--gil", "--duration", "3.5"])
        assert args.duration == pytest.approx(3.5)

    def test_min_gil_wait_us(self):
        p = _build_parser()
        args = p.parse_args(["-p", "1", "--gil", "--min-gil-wait-us", "100"])
        assert args.min_gil_wait_us == 100

    def test_output(self):
        p = _build_parser()
        args = p.parse_args(["-p", "1", "--gil", "-o", "out.json"])
        assert args.output == "out.json"

    def test_exec_mode(self):
        p = _build_parser()
        args = p.parse_args(["--gil", "--", "python", "-c", "pass"])
        assert args.pid is None
        assert args.command == ["--", "python", "-c", "pass"]


# ── _main dispatch ────────────────────────────────────────────────────────────


def _mock_tracker():
    m = MagicMock()
    m.__enter__ = MagicMock(return_value=m)
    m.__exit__ = MagicMock(return_value=False)
    return m


class TestMain:
    def _run(self, argv, **extra_patches):
        """Run _main with given argv and optional extra patches."""
        patches = {
            "zap_trace.__main__.FridaGilTracker": MagicMock(
                return_value=_mock_tracker()
            ),
            "zap_trace.__main__.FridaKekeCollector": MagicMock(
                return_value=_mock_tracker()
            ),
            "zap_trace.__main__.time.sleep": MagicMock(side_effect=KeyboardInterrupt),
            **extra_patches,
        }
        with patch.multiple("zap_trace.__main__", **patches):
            with patch("sys.argv", ["zap-trace"] + argv):
                with patch("builtins.open", MagicMock(return_value=StringIO())):
                    with patch("keke.TraceOutput") as mock_to:
                        mock_to.return_value.__enter__ = MagicMock(return_value=None)
                        mock_to.return_value.__exit__ = MagicMock(return_value=False)
                        _main()

    def test_no_gil_no_keke_exits(self):
        with pytest.raises(SystemExit):
            with patch("sys.argv", ["zap-trace", "-p", "1"]):
                _main()

    def test_no_pid_no_command_exits(self):
        with pytest.raises(SystemExit):
            with patch("sys.argv", ["zap-trace", "--gil"]):
                _main()

    def test_pid_and_command_exits(self):
        with pytest.raises(SystemExit):
            with patch("sys.argv", ["zap-trace", "-p", "1", "--gil", "--", "python"]):
                _main()

    def test_gil_only_enters_gil_tracker(self):
        mock_gil_cls = MagicMock(return_value=_mock_tracker())
        mock_keke_cls = MagicMock(return_value=_mock_tracker())
        with (
            patch("zap_trace.__main__.FridaGilTracker", mock_gil_cls),
            patch("zap_trace.__main__.FridaKekeCollector", mock_keke_cls),
            patch("zap_trace.__main__.time.sleep", side_effect=KeyboardInterrupt),
            patch("sys.argv", ["zap-trace", "-p", "123", "--gil"]),
            patch("builtins.open", MagicMock(return_value=StringIO())),
        ):
            with patch("keke.TraceOutput") as mto:
                mto.return_value.__enter__ = MagicMock(return_value=None)
                mto.return_value.__exit__ = MagicMock(return_value=False)
                _main()
        mock_gil_cls.assert_called_once_with(123, min_wait_us=0)
        mock_keke_cls.assert_not_called()

    def test_keke_only_enters_keke_collector(self):
        mock_gil_cls = MagicMock(return_value=_mock_tracker())
        mock_keke_cls = MagicMock(return_value=_mock_tracker())
        with (
            patch("zap_trace.__main__.FridaGilTracker", mock_gil_cls),
            patch("zap_trace.__main__.FridaKekeCollector", mock_keke_cls),
            patch("zap_trace.__main__.time.sleep", side_effect=KeyboardInterrupt),
            patch("sys.argv", ["zap-trace", "-p", "123", "--keke"]),
            patch("builtins.open", MagicMock(return_value=StringIO())),
        ):
            with patch("keke.TraceOutput") as mto:
                mto.return_value.__enter__ = MagicMock(return_value=None)
                mto.return_value.__exit__ = MagicMock(return_value=False)
                _main()
        mock_keke_cls.assert_called_once_with(123)
        mock_gil_cls.assert_not_called()

    def test_both_enters_both(self):
        mock_gil_cls = MagicMock(return_value=_mock_tracker())
        mock_keke_cls = MagicMock(return_value=_mock_tracker())
        with (
            patch("zap_trace.__main__.FridaGilTracker", mock_gil_cls),
            patch("zap_trace.__main__.FridaKekeCollector", mock_keke_cls),
            patch("zap_trace.__main__.time.sleep", side_effect=KeyboardInterrupt),
            patch("sys.argv", ["zap-trace", "-p", "123", "--gil", "--keke"]),
            patch("builtins.open", MagicMock(return_value=StringIO())),
        ):
            with patch("keke.TraceOutput") as mto:
                mto.return_value.__enter__ = MagicMock(return_value=None)
                mto.return_value.__exit__ = MagicMock(return_value=False)
                _main()
        mock_gil_cls.assert_called_once()
        mock_keke_cls.assert_called_once()

    def test_duration_calls_sleep(self):
        mock_sleep = MagicMock()
        mock_gil_cls = MagicMock(return_value=_mock_tracker())
        with (
            patch("zap_trace.__main__.FridaGilTracker", mock_gil_cls),
            patch(
                "zap_trace.__main__.FridaKekeCollector",
                MagicMock(return_value=_mock_tracker()),
            ),
            patch("zap_trace.__main__.time.sleep", mock_sleep),
            patch("sys.argv", ["zap-trace", "-p", "123", "--gil", "--duration", "2.5"]),
            patch("builtins.open", MagicMock(return_value=StringIO())),
        ):
            with patch("keke.TraceOutput") as mto:
                mto.return_value.__enter__ = MagicMock(return_value=None)
                mto.return_value.__exit__ = MagicMock(return_value=False)
                _main()
        mock_sleep.assert_called_once_with(2.5)

    def test_min_gil_wait_passed_through(self):
        mock_gil_cls = MagicMock(return_value=_mock_tracker())
        with (
            patch("zap_trace.__main__.FridaGilTracker", mock_gil_cls),
            patch("zap_trace.__main__.time.sleep", side_effect=KeyboardInterrupt),
            patch(
                "sys.argv",
                ["zap-trace", "-p", "5", "--gil", "--min-gil-wait-us", "250"],
            ),
            patch("builtins.open", MagicMock(return_value=StringIO())),
        ):
            with patch("keke.TraceOutput") as mto:
                mto.return_value.__enter__ = MagicMock(return_value=None)
                mto.return_value.__exit__ = MagicMock(return_value=False)
                _main()
        mock_gil_cls.assert_called_once_with(5, min_wait_us=250)

    def test_exec_mode_spawns_popen(self):
        mock_proc = MagicMock()
        mock_proc.pid = 999
        mock_proc.wait = MagicMock(return_value=0)
        mock_popen = MagicMock(return_value=mock_proc)
        mock_gil_cls = MagicMock(return_value=_mock_tracker())
        with (
            patch("zap_trace.__main__.subprocess.Popen", mock_popen),
            patch("zap_trace.__main__.FridaGilTracker", mock_gil_cls),
            patch(
                "sys.argv", ["zap-trace", "--gil", "--", sys.executable, "-c", "pass"]
            ),
            patch("builtins.open", MagicMock(return_value=StringIO())),
        ):
            with patch("keke.TraceOutput") as mto:
                mto.return_value.__enter__ = MagicMock(return_value=None)
                mto.return_value.__exit__ = MagicMock(return_value=False)
                _main()
        mock_popen.assert_called_once_with([sys.executable, "-c", "pass"])
        mock_gil_cls.assert_called_once_with(999, min_wait_us=0)

    def test_default_output_filename(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        mock_gil_cls = MagicMock(return_value=_mock_tracker())
        captured_output = []

        orig_open = __builtins__["open"] if isinstance(__builtins__, dict) else open

        def fake_open(path, *args, **kwargs):
            if isinstance(path, str) and path.startswith("zap_trace_"):
                captured_output.append(path)
                return StringIO()
            return orig_open(path, *args, **kwargs)

        with (
            patch("zap_trace.__main__.FridaGilTracker", mock_gil_cls),
            patch("zap_trace.__main__.time.sleep", side_effect=KeyboardInterrupt),
            patch("sys.argv", ["zap-trace", "-p", "42", "--gil"]),
            patch("builtins.open", fake_open),
        ):
            with patch("keke.TraceOutput") as mto:
                mto.return_value.__enter__ = MagicMock(return_value=None)
                mto.return_value.__exit__ = MagicMock(return_value=False)
                _main()
        assert len(captured_output) == 1
        assert captured_output[0].startswith("zap_trace_42_")
        assert captured_output[0].endswith(".json")
