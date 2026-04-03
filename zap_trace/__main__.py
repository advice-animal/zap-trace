"""Entry point for ``zap-trace``."""

from __future__ import annotations

import argparse
import contextlib
import subprocess
import sys
import time

import keke

from .gil import FridaGilTracker
from .keke_tap import FridaKekeCollector


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zap-trace",
        description=(
            "Attach to a running Python process and record a Chrome-format "
            "trace combining GIL contention and/or keke events."
        ),
        epilog=(
            "Targeting: supply -p PID to attach to an existing process, or "
            "append -- COMMAND [ARGS...] to spawn and auto-attach."
        ),
    )
    target = parser.add_mutually_exclusive_group()
    target.add_argument(
        "-p",
        "--pid",
        type=int,
        default=None,
        metavar="PID",
        help="Attach to this existing process ID.",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        metavar="-- COMMAND [ARGS...]",
        help="Spawn this command and attach to it (use after --).",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        metavar="PATH",
        help="Output trace JSON path (default: zap_trace_<pid>_<ts>.json).",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=None,
        metavar="S",
        help="Stop after S seconds (attach mode only; default: run until Ctrl-C).",
    )
    parser.add_argument(
        "--min-gil-wait-us",
        type=int,
        default=0,
        metavar="N",
        help="Only record GIL-wait events longer than N microseconds (default 0 = all).",
    )
    parser.add_argument(
        "--gil",
        action="store_true",
        help="Enable GIL contention tracing.",
    )
    parser.add_argument(
        "--keke",
        action="store_true",
        help="Enable keke event collection.",
    )
    return parser


def _main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    # Strip leading "--" separator from remainder args.
    command = args.command
    if command and command[0] == "--":
        command = command[1:]

    # Validate targeting.
    if args.pid is not None and command:
        parser.error("Cannot use both -p/--pid and -- COMMAND.")
    if args.pid is None and not command:
        parser.error("Supply either -p PID or -- COMMAND [ARGS...].")

    # Validate tracer selection.
    if not args.gil and not args.keke:
        parser.error("At least one of --gil or --keke is required.")

    # Exec mode: spawn the child process.
    child_proc: subprocess.Popen[bytes] | None = None
    if command:
        child_proc = subprocess.Popen(command)
        pid = child_proc.pid
    else:
        assert args.pid is not None
        pid = args.pid

    # Default output path.
    output = args.output
    if output is None:
        ts = int(time.time())
        output = f"zap_trace_{pid}_{ts}.json"

    print(f"Tracing PID {pid} → {output}", file=sys.stderr)

    with keke.TraceOutput(open(output, "w"), pid=pid):
        with contextlib.ExitStack() as stack:
            if args.gil:
                stack.enter_context(
                    FridaGilTracker(pid, min_wait_us=args.min_gil_wait_us)
                )
            if args.keke:
                stack.enter_context(FridaKekeCollector(pid))

            if child_proc is not None:
                # Exec mode: wait for the child to finish.
                try:
                    child_proc.wait()
                except KeyboardInterrupt:
                    child_proc.terminate()
                    child_proc.wait()
            else:
                # Attach mode: sleep for duration or until Ctrl-C.
                try:
                    if args.duration is not None:
                        time.sleep(args.duration)
                    else:
                        while True:
                            time.sleep(1)
                except KeyboardInterrupt:
                    pass

    print(f"Trace written to: {output}")


if __name__ == "__main__":
    _main()
