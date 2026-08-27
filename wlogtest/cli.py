from __future__ import annotations

import argparse
import json
import sys

from wlogtest import __version__
from wlogtest.client import LogtestClient, LogtestError, LogtestTransportError
from wlogtest.dataset import DatasetError, load_dataset
from wlogtest.report import render_console, render_json, render_junit_xml, render_phases
from wlogtest.runner import DatasetRunner

QUIT_COMMANDS = (":quit", ":q")
PROMPT = "wlogtest> "


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wlogtest",
        description="Offline Wazuh logtest: debug decoders/rules and run log datasets.",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    logtest = subparsers.add_parser(
        "logtest", help="send one or more events to Wazuh logtest"
    )
    logtest.add_argument("-e", "--event", help="single event to process")
    logtest.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="interactive REPL (reads stdin lines when stdin is piped)",
    )
    logtest.add_argument("-l", "--location", default="stdin")
    logtest.add_argument("-f", "--format", default="syslog")
    logtest.add_argument("--token", default=None, help="session token (8 hex chars)")
    logtest.add_argument(
        "--debug", action="store_true", help="enable rules debugging output"
    )
    logtest.add_argument(
        "--end-session", action="store_true", help="remove the session afterwards"
    )
    logtest.add_argument("--socket", default=None, help="logtest socket path")
    logtest.add_argument(
        "--json",
        action="store_true",
        help="print the raw JSON response instead of the 3-phase output",
    )

    run = subparsers.add_parser(
        "run", help="run a dataset against Wazuh logtest"
    )
    run.add_argument("dataset", help="dataset JSON (or YAML) file")
    run.add_argument("--socket", default=None, help="logtest socket path")
    output = run.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="print the report as JSON")
    output.add_argument(
        "--junit", action="store_true", help="print the report as JUnit XML"
    )
    run.add_argument("-v", "--verbose", action="store_true")
    run.add_argument("-o", "--output", metavar="FILE", default=None)

    subparsers.add_parser("version", help="print the version and exit")
    return parser


def _process_event(client, args, token, event) -> tuple:
    """Send one event; return (token, ok). Prints the 3-phase wazuh-logtest
    output (default) or the raw JSON response with --json."""
    options = {"rules_debug": True} if args.debug else None
    try:
        data = client.run_log(
            event,
            location=args.location,
            log_format=args.format,
            token=token,
            options=options,
        )
    except LogtestError as exc:
        error = {"error": exc.code, "message": exc.message}
        if getattr(exc, "codemsg", None) is not None:
            error["codemsg"] = exc.codemsg
        print(json.dumps(error, indent=2), file=sys.stderr)
        return token, False
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(render_phases(data))
    new_token = data.get("token") if isinstance(data, dict) else None
    return new_token or token, True


def _cmd_logtest(parser, args) -> int:
    tty = sys.stdin.isatty()
    if args.event is None and not args.interactive and tty:
        parser.error("one of -e/--event or -i/--interactive is required when stdin is a TTY")
    client = LogtestClient(socket_path=args.socket)
    token = args.token or None
    all_ok = True

    def process(event):
        nonlocal token, all_ok
        try:
            token, ok = _process_event(client, args, token, event)
        except LogtestTransportError as exc:
            print(f"error: {exc}", file=sys.stderr)
            ok = False
        if not ok:
            all_ok = False

    if args.event is not None:
        process(args.event)
    elif not tty:
        for line in sys.stdin:
            line = line.rstrip("\r\n")
            if line:
                process(line)
    else:
        while True:
            try:
                line = input(PROMPT)
            except EOFError:
                break
            line = line.strip()
            if line in QUIT_COMMANDS:
                break
            if line:
                process(line)

    if args.end_session and token:
        try:
            client.remove_session(token)
        except Exception:
            pass
    client.close()
    return 0 if all_ok else 1


def _cmd_run(args) -> int:
    try:
        dataset = load_dataset(args.dataset)
    except DatasetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    client = LogtestClient(socket_path=args.socket)
    report = DatasetRunner(client, dataset).run()
    client.close()
    if args.json:
        out = render_json(report)
    elif args.junit:
        out = render_junit_xml(report)
    else:
        out = render_console(report, verbose=args.verbose)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(out + "\n")
        except OSError as exc:
            print(f"error: cannot write {args.output}: {exc}", file=sys.stderr)
            return 1
    else:
        print(out)
    return 0 if report.passed else 1


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "version":
        print(__version__)
        return 0
    if args.command == "run":
        return _cmd_run(args)
    if args.command == "logtest":
        return _cmd_logtest(parser, args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
