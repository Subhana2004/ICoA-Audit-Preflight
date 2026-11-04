"""Optional direct parity check against a local checkout of original ICoA.

Usage: python -m tests.upstream_parity /path/to/ICoA
This imports the original auditor iterators, but never invokes their main()
functions or makes API calls.
"""

import json
import sys
import tempfile
from pathlib import Path

from icoa_preflight import inspect_run


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python -m tests.upstream_parity /path/to/ICoA")
    auditor = Path(sys.argv[1]).resolve() / "auditor"
    if not (auditor / "judge.py").is_file() or not (auditor / "judge_batch.py").is_file():
        raise SystemExit(f"Expected ICoA auditor files in {auditor}")
    sys.path.insert(0, str(auditor))
    import judge  # noqa: E402
    import judge_batch  # noqa: E402

    cases = [
        (("local-a", "local-b"), "local-a"),
        (("gpt-a",), "gpt-a"),
        (("gpt-a", "gpt-b"), None),
        (("local-z", "local-a", "gpt-a"), "local-a"),
    ]
    with tempfile.TemporaryDirectory(prefix="icoa-parity-") as temporary:
        for i, (models, expected) in enumerate(cases):
            root = Path(temporary) / f"run-{i}"
            for j, model in enumerate(models):
                path = root / model / "banking" / "user_task_0" / "icoa" / f"injection_task_{j}.json"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps({"security": True, "messages": [], "injections": {}}))
            r = inspect_run("parity", root)
            selected = Path(r["selected"]["directory"]).name if r["selected"] else None
            assert selected == expected
            assert judge.resolve_local(root) == judge_batch.resolve_local(root)
            assert selected == (judge.resolve_local(root).name if judge.resolve_local(root) else None)
            sync_paths = [case["path"] for case in judge.iter_asr_cases(root)]
            batch_paths = [case["path"] for case in judge_batch.iter_asr_cases_from_results(root)]
            assert sync_paths == batch_paths
            assert len(sync_paths) == r["reconciliation"]["selected_positive"]
        print(f"PASS: {len(cases)} synthetic selection/traversal scenarios match both original auditors")


if __name__ == "__main__":
    main()
