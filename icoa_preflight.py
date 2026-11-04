"""Read-only coverage reconciliation for ICoA's published auditor traversal.

This does not call a judge or assign scientific outcome labels. All percentages
refer to truthy-security candidate files visible in the supplied directories.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def model_directories(run_dir: Path) -> list[Path]:
    """Mirror the immediate non-hidden directory filter of resolve_local()."""
    return [p for p in sorted(run_dir.iterdir()) if p.is_dir() and not p.name.startswith(".")]


def selected_model_directory(children: list[Path]) -> Path | None:
    for child in children:
        if child.name.startswith("local"):
            return child
    return children[0] if len(children) == 1 else None


def scan_traces(model_dir: Path) -> dict[str, Any]:
    """Mirror the upstream path traversal and truthiness test, retaining diagnostics."""
    counts: dict[str, Any] = {
        "directory": str(model_dir), "trace_files": 0, "asr_positive": 0,
        "asr_negative": 0, "missing_security": 0, "malformed_json": 0,
        "invalid_record": 0, "positive_paths": [], "unknown_paths": [],
    }
    for suite_dir in sorted(model_dir.iterdir()):
        if not suite_dir.is_dir():
            continue
        for task_dir in sorted(suite_dir.iterdir()):
            if not task_dir.is_dir() or not task_dir.name.startswith("user_task_"):
                continue
            # Upstream leaves attack directory order to the filesystem.
            for attack_dir in task_dir.iterdir():
                if not attack_dir.is_dir() or attack_dir.name == "none":
                    continue
                for file_path in sorted(attack_dir.glob("injection_task_*.json")):
                    counts["trace_files"] += 1
                    relative = str(file_path.relative_to(model_dir))
                    try:
                        record = json.loads(file_path.read_text())
                    except (OSError, ValueError, UnicodeError):
                        counts["malformed_json"] += 1
                        counts["unknown_paths"].append(relative)
                        continue
                    if not isinstance(record, dict):
                        # Upstream would raise at record.get(), not silently skip.
                        counts["invalid_record"] += 1
                        counts["unknown_paths"].append(relative)
                    elif "security" not in record:
                        # Upstream skips this (get returns None); provenance is unknown.
                        counts["missing_security"] += 1
                        counts["unknown_paths"].append(relative)
                    elif record.get("security"):
                        counts["asr_positive"] += 1
                        counts["positive_paths"].append(relative)
                    else:
                        counts["asr_negative"] += 1
    return counts


def inspect_run(name: str, run_dir: str | Path) -> dict[str, Any]:
    root = Path(run_dir).expanduser().resolve()
    report: dict[str, Any] = {
        "name": name, "run_directory": str(root), "selected": None,
        "skipped": [], "selection": None, "risk": False, "warnings": [],
        "reconciliation": {}, "corrective_actions": [],
    }
    if not root.is_dir():
        report["selection"] = "invalid_run_directory"
        report["risk"] = True
        report["warnings"].append("Run directory is missing or is not a directory.")
        report["corrective_actions"].append("Supply the existing run parent via --run NAME=PATH.")
        return report
    try:
        children = model_directories(root)
        chosen = selected_model_directory(children)
        report["selection"] = (
            "first_local" if chosen and chosen.name.startswith("local")
            else "single_directory_fallback" if chosen else "unresolved"
        )
        report["selected"] = scan_traces(chosen) if chosen else None
        report["skipped"] = [scan_traces(p) for p in children if p != chosen]
    except (OSError, UnicodeError) as exc:
        report["selection"] = "scan_error"
        report["risk"] = True
        report["warnings"].append(f"Cannot scan run directory ({type(exc).__name__}).")
        report["corrective_actions"].append("Check read permissions and inspect the affected run manually.")
        return report

    selected = report["selected"]
    skipped = report["skipped"]
    selected_n = selected["asr_positive"] if selected else 0
    omitted_n = sum(d["asr_positive"] for d in skipped)
    eligible = selected_n + omitted_n
    unknown = sum(d["missing_security"] + d["malformed_json"] + d["invalid_record"]
                  for d in skipped + ([selected] if selected else []))
    report["reconciliation"] = {
        "selected_positive": selected_n,
        "potentially_omitted_positive": omitted_n,
        "known_positive_total": eligible,
        "selected_coverage_pct": round(100 * selected_n / eligible, 2) if eligible else None,
        "unknown_eligibility": unknown,
        "unknown_coverage_pct": None,
        "scope": "Observed truthy-security files in recognized paths; not completed judgments.",
    }
    if not chosen:
        report["warnings"].append("Upstream resolve_local() selects no model directory here.")
    if omitted_n:
        report["warnings"].append(
            f"{omitted_n} truthy-security trace(s) occur outside the upstream-selected directory."
        )
    if unknown:
        report["warnings"].append(
            f"{unknown} trace(s) have missing security, malformed JSON, or a non-object record; "
            "eligibility or successful processing cannot be established."
        )
    for d in skipped:
        if d["asr_positive"] or d["missing_security"] or d["malformed_json"] or d["invalid_record"]:
            report["corrective_actions"].append(
                f"To audit {d['directory']}, place that model directory alone under its own "
                "run parent, then pass that parent as --run NAME=PATH to the original auditor. "
                "Verify trace metadata and judge output before reporting scores."
            )
    if selected and (selected["missing_security"] or selected["malformed_json"] or selected["invalid_record"]):
        report["corrective_actions"].append(
            "Inspect selected-directory unknown paths: missing security and malformed JSON "
            "are skipped by the auditor; a valid non-object JSON record can abort traversal."
        )
    if not children:
        report["corrective_actions"].append("Check that this is a run parent containing a model-output directory.")
    report["risk"] = bool(omitted_n or unknown or not chosen)
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
        "tool": "ICoA Audit Preflight", "upstream": "https://github.com/yslmoment/ICoA",
        "runs_checked": len(results), "runs_at_risk": sum(bool(r["risk"]) for r in results),
        "skipped_asr_positive": sum(r["reconciliation"].get("potentially_omitted_positive", 0)
                                    for r in results),
        "results": results,
    }


def format_text(report: dict[str, Any]) -> str:
    lines = [f"ICoA Audit Preflight | runs checked: {report['runs_checked']} | "
             f"runs at risk: {report['runs_at_risk']}"]
    for item in report["results"]:
        chosen = item["selected"]
        selected_name = Path(chosen["directory"]).name if chosen else "NONE"
        lines.append(f"\n[{item['name']}] selected={selected_name} ({item['selection']})")
        if chosen:
            lines.append(f"  selected: {chosen['trace_files']} candidate files; "
                         f"truthy-security={chosen['asr_positive']}")
            for p in chosen["positive_paths"]:
                lines.append(f"    selected positive path: {p}")
            for p in chosen["unknown_paths"]:
                lines.append(f"    selected unknown path: {p}")
        for d in item["skipped"]:
            lines.append(f"  potentially omitted: {Path(d['directory']).name} "
                         f"({d['trace_files']} files, truthy-security={d['asr_positive']}, "
                         f"unknown={d['missing_security'] + d['malformed_json'] + d['invalid_record']})")
            for p in d["positive_paths"]:
                lines.append(f"    positive path: {p}")
            for p in d["unknown_paths"]:
                lines.append(f"    unknown path: {p}")
        r = item["reconciliation"]
        if r:
            pct = f"{r['selected_coverage_pct']:.2f}%" if r["selected_coverage_pct"] is not None else "N/A"
            lines.append(f"  coverage: {r['selected_positive']}/{r['known_positive_total']} "
                         f"known positives selected ({pct}); potentially omitted="
                         f"{r['potentially_omitted_positive']}; unknown={r['unknown_eligibility']}")
        for warning in item["warnings"]:
            lines.append(f"  WARNING: {warning}")
        for action in item["corrective_actions"]:
            lines.append(f"  ACTION: {action}")
    lines.append(f"\nTruthy-security traces outside selected directories: "
                 f"{report['skipped_asr_positive']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only ICoA coverage checker (no API calls).")
    parser.add_argument("--run", action="append", type=parse_named_run, default=[],
                        metavar="NAME=PATH", help="Audit one run parent; repeatable")
    parser.add_argument("--runs-root", type=Path, help="Discover run parents one level below PATH")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output", type=Path, help="Write report to a file")
    parser.add_argument("--fail-on-risk", action="store_true",
                        help="Exit 2 if a run has omitted positives, unknowns, or unresolved selection")
    args = parser.parse_args(argv)
    runs = list(args.run)
    if args.runs_root is not None:
        root = args.runs_root.expanduser().resolve()
        if not root.is_dir():
            parser.error(f"--runs-root is not a directory: {root}")
        # Match run_auditor.sh's audit_results* exclusion for root discovery.
        runs += [(d.name, d) for d in sorted(root.iterdir())
                 if d.is_dir() and not d.name.startswith(".")
                 and not d.name.startswith("audit_results")]
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
