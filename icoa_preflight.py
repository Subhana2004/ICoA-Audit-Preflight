"""Read-only coverage check for the published ICoA auditor directory resolver.

The upstream auditor/judge.py and auditor/judge_batch.py resolve exactly one
model-output directory per run. This utility does not run either auditor and
never modifies experimental files.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def model_directories(run_dir: Path) -> list[Path]:
    """Match the immediate-child filter in upstream resolve_local()."""
    return sorted(
        (child for child in run_dir.iterdir() if child.is_dir() and not child.name.startswith(".")),
        key=lambda child: child.name,
    )


def selected_model_directory(children: list[Path]) -> Path | None:
    """Mirror ICoA resolve_local(): first local*, else only child, else None."""
    for child in children:
        if child.name.startswith("local"):
            return child
    if len(children) == 1:
        return children[0]
    return None


def scan_traces(model_dir: Path) -> dict[str, Any]:
    """Count candidate trace files, including those the auditor might skip.

    Traversal follows the upstream pattern suite/user_task_*/attack/injection_task_*.json.
    Only truthy `security` flags are ASR-positive, matching both auditors.
    Trace payloads are never included in the resulting report.
    """
    counts: dict[str, Any] = {
        "directory": str(model_dir),
        "trace_files": 0,
        "asr_positive": 0,
        "asr_negative": 0,
        "missing_security": 0,
        "malformed_json": 0,
    }
    for suite_dir in sorted(model_dir.iterdir()):
        if not suite_dir.is_dir():
            continue
        for task_dir in sorted(suite_dir.iterdir()):
            if not task_dir.is_dir() or not task_dir.name.startswith("user_task_"):
                continue
            for attack_dir in sorted(task_dir.iterdir()):
                if not attack_dir.is_dir() or attack_dir.name == "none":
                    continue
                for file_path in sorted(attack_dir.glob("injection_task_*.json")):
                    if not file_path.is_file():
                        continue
                    counts["trace_files"] += 1
                    try:
                        record = json.loads(file_path.read_text(encoding="utf-8"))
                    except (OSError, ValueError, UnicodeError):
                        counts["malformed_json"] += 1
                        continue
                    if not isinstance(record, dict):
                        counts["malformed_json"] += 1
                    elif "security" not in record:
                        counts["missing_security"] += 1
                    elif record.get("security"):
                        counts["asr_positive"] += 1
                    else:
                        counts["asr_negative"] += 1
    return counts


def inspect_run(name: str, run_dir: str | Path) -> dict[str, Any]:
    """Compare upstream-selected directory with candidate omitted directories."""
    root = Path(run_dir).expanduser().resolve()
    report: dict[str, Any] = {
        "name": name,
        "run_directory": str(root),
        "selected": None,
        "skipped": [],
        "selection": None,
        "risk": False,
        "warnings": [],
    }
    if not root.is_dir():
        report["selection"] = "invalid_run_directory"
        report["risk"] = True
        report["warnings"].append("Run directory is missing or is not a directory.")
        return report

    try:
        children = model_directories(root)
        chosen = selected_model_directory(children)
        report["selection"] = (
            "first_local" if chosen and chosen.name.startswith("local")
            else "single_directory_fallback" if chosen else "unresolved"
        )
        report["selected"] = scan_traces(chosen) if chosen else None
        report["skipped"] = [scan_traces(path) for path in children if path != chosen]
    except OSError as exc:
        report["selection"] = "scan_error"
        report["risk"] = True
        report["warnings"].append(f"Cannot scan run directory ({type(exc).__name__}).")
        return report

    if not chosen:
        report["warnings"].append(
            "Upstream resolve_local() selects no model directory here."
        )
    skipped_asr = sum(d["asr_positive"] for d in report["skipped"])
    skipped_unknown = sum(d["malformed_json"] + d["missing_security"] for d in report["skipped"])
    if skipped_asr:
        report["warnings"].append(
            f"{skipped_asr} ASR-positive trace(s) occur outside the upstream-selected directory."
        )
    if skipped_unknown:
        report["warnings"].append(
            f"{skipped_unknown} skipped trace(s) have unreadable or missing security metadata; "
            "their eligibility cannot be established."
        )
    if chosen and report["selected"]["malformed_json"]:
        report["warnings"].append(
            "Malformed JSON exists in the selected directory; upstream silently ignores it."
        )
    report["risk"] = bool(skipped_asr or skipped_unknown or not chosen)
    return report


def parse_named_run(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("--run requires NAME=PATH")
    name, path = value.split("=", 1)
    if not name.strip() or not path.strip():
        raise argparse.ArgumentTypeError("--run requires nonempty NAME and PATH")
    return name.strip(), Path(path.strip())


def inspect_runs(runs: list[tuple[str, Path]]) -> dict[str, Any]:
    results = [inspect_run(name, path) for name, path in runs]
    return {
        "tool": "ICoA Audit Preflight",
        "upstream": "https://github.com/yslmoment/ICoA",
        "runs_checked": len(results),
        "runs_at_risk": sum(bool(r["risk"]) for r in results),
        "skipped_asr_positive": sum(
            sum(d["asr_positive"] for d in r["skipped"]) for r in results
        ),
        "results": results,
    }


def format_text(report: dict[str, Any]) -> str:
    lines = [
        f"ICoA Audit Preflight | runs checked: {report['runs_checked']} | "
        f"runs at risk: {report['runs_at_risk']}",
    ]
    for item in report["results"]:
        chosen = item["selected"]
        selected_name = Path(chosen["directory"]).name if chosen else "NONE"
        lines.append(f"\n[{item['name']}] selected={selected_name} ({item['selection']})")
        if chosen:
            lines.append(
                f"  included: {chosen['trace_files']} traces; "
                f"ASR-positive={chosen['asr_positive']}"
            )
        for skipped in item["skipped"]:
            lines.append(
                f"  skipped: {Path(skipped['directory']).name} "
                f"({skipped['trace_files']} traces, "
                f"ASR-positive={skipped['asr_positive']}, "
                f"unknown={skipped['malformed_json'] + skipped['missing_security']})"
            )
        for warning in item["warnings"]:
            lines.append(f"  WARNING: {warning}")
    lines.append(
        f"\nASR-positive traces outside selected directories: "
        f"{report['skipped_asr_positive']}"
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only ICoA evaluation-directory coverage checker (no API calls)."
    )
    parser.add_argument("--run", action="append", type=parse_named_run, default=[],
                        metavar="NAME=PATH", help="Audit one run directory; repeatable")
    parser.add_argument("--runs-root", type=Path,
                        help="Discover run directories one level below PATH")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output", type=Path, help="Write report to a file")
    parser.add_argument("--fail-on-risk", action="store_true",
                        help="Exit with status 2 when an audit-coverage risk is found")
    args = parser.parse_args(argv)
    runs = list(args.run)
    if args.runs_root is not None:
        root = args.runs_root.expanduser().resolve()
        if not root.is_dir():
            parser.error(f"--runs-root is not a directory: {root}")
        runs += [(d.name, d) for d in sorted(root.iterdir())
                 if d.is_dir() and not d.name.startswith(".")]
    if not runs:
        parser.error("Provide at least one --run NAME=PATH or --runs-root PATH")
    report = inspect_runs(runs)
    output = json.dumps(report, indent=2, ensure_ascii=False) if args.format == "json" else format_text(report)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    return 2 if args.fail_on_risk and report["runs_at_risk"] else 0


if __name__ == "__main__":
    sys.exit(main())
