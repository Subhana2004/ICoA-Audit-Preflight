"""Reproducible synthetic ICoA-shaped directory demonstration (no actual runs)."""

import json
import tempfile
from pathlib import Path

from icoa_preflight import format_text, inspect_runs


def write_trace(model: Path, task: int, attack: str, injection: int, record: object) -> None:
    path = model / "banking" / f"user_task_{task}" / attack / f"injection_task_{injection}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record), encoding="utf-8")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="icoa-synthetic-") as temporary:
        run = Path(temporary) / "llama33_task_shield"
        a, b = run / "local-a", run / "local-b"
        write_trace(a, 0, "icoa", 0, {"security": True, "utility": True,
                                       "messages": [{"role": "assistant", "content": "demo"}],
                                       "injections": {"tool": "synthetic"}})
        write_trace(a, 0, "icoa", 1, {"security": False, "messages": []})
        write_trace(b, 0, "icoa", 2, {"security": True, "messages": []})
        write_trace(b, 1, "icoa", 3, {"security": True, "messages": []})
        write_trace(b, 1, "icoa", 4, {"messages": []})
        malformed = b / "banking" / "user_task_1" / "icoa" / "injection_task_5.json"
        malformed.write_text("{broken", encoding="utf-8")
        report = inspect_runs([("synthetic", run)])
        reconciled = report["results"][0]["reconciliation"]
        assert reconciled["selected_positive"] == 1
        assert reconciled["potentially_omitted_positive"] == 2
        assert reconciled["selected_coverage_pct"] == 33.33
        assert reconciled["unknown_eligibility"] == 2
        print("SYNTHETIC DEMONSTRATION — NOT ICoA EXPERIMENTAL RESULTS")
        print(format_text(report))


if __name__ == "__main__":
    main()
