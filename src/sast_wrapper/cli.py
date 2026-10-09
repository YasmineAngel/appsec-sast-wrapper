import argparse
import sys
from pathlib import Path

from sast_wrapper import __version__
from sast_wrapper.models import Severity
from sast_wrapper.parsers.bandit import parse_bandit
from sast_wrapper.parsers.semgrep import parse_semgrep
from sast_wrapper.report import build_report, write_report
from sast_wrapper.runners import (
    DEFAULT_EXCLUDES,
    DEFAULT_SEMGREP_CONFIGS,
    ScanError,
    count_scanned,
    relative_paths,
    run_bandit,
    run_semgrep,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sast-wrapper",
        description="Run SAST tools and produce an OWASP-grouped report.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan a folder and write a Markdown report.")
    scan.add_argument("target", help="Folder to scan")
    scan.add_argument("--tool", choices=["semgrep", "bandit"], required=True)
    scan.add_argument("--out", help="Report path (default: reports/<folder>-<tool>.md)")
    scan.add_argument("--title", help="Report title (default: folder name + tool)")
    scan.add_argument("--config", action="append",
                      help="Semgrep rule pack, can repeat (default: p/owasp-top-ten + p/secrets)")
    scan.add_argument("--exclude", action="append", default=[],
                      help="Extra folder to skip, can repeat")
    scan.add_argument("--fail-on", choices=[s.name.lower() for s in Severity],
                      help="Exit with code 1 if any finding is at least this severe")
    return parser


def run_scan(args) -> int:
    target = Path(args.target)
    excludes = DEFAULT_EXCLUDES + args.exclude
    print(f"Scanning {target} with {args.tool}...")

    if args.tool == "bandit":
        data = run_bandit(target, excludes=excludes)
        findings = parse_bandit(data)
    else:
        data = run_semgrep(target, configs=args.config or DEFAULT_SEMGREP_CONFIGS, excludes=excludes)
        findings = parse_semgrep(data)

    scanned = count_scanned(args.tool, data)
    if scanned == 0:
        print("WARNING: 0 files were scanned. An empty scan is not a clean result; "
              "check the folder path and excludes.", file=sys.stderr)

    findings = relative_paths(findings, target)
    name = target.resolve().name
    title = args.title or f"{name} ({args.tool})"
    out = Path(args.out or f"reports/{name}-{args.tool}.md")
    write_report(out, build_report(findings, title))
    print(f"{scanned} files scanned, {len(findings)} findings. Report: {out}")

    if args.fail_on:
        threshold = Severity[args.fail_on.upper()]
        serious = [f for f in findings if f.severity >= threshold]
        if serious:
            print(f"FAIL: {len(serious)} finding(s) at {threshold.name} or above.", file=sys.stderr)
            return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        try:
            return run_scan(args)
        except ScanError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())