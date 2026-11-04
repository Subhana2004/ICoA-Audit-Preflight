"""Unit tests use tiny synthetic traces, not the original experiments."""

import json
import tempfile
import unittest
from pathlib import Path

from icoa_preflight import format_text, inspect_run, inspect_runs, main


def trace(model_dir: Path, *, security=True, name="injection_task_0.json", valid=True):
    location = model_dir / "banking" / "user_task_0" / "attack_0" / name
    location.parent.mkdir(parents=True, exist_ok=True)
    location.write_text(json.dumps({"security": security, "messages": ["private trace content"]})
                        if valid else "{oops", encoding="utf-8")
    return location


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "run"
        self.root.mkdir()

    def test_first_sorted_local_and_skipped_asr(self):
        trace(self.root / "local-z")
        trace(self.root / "local-a", security=False)
        result = inspect_run("test", self.root)
        self.assertEqual(Path(result["selected"]["directory"]).name, "local-a")
        self.assertEqual(result["selected"]["asr_positive"], 0)
        self.assertEqual(result["skipped"][0]["asr_positive"], 1)
        self.assertTrue(result["risk"])

    def test_single_nonlocal_fallback(self):
        trace(self.root / "gpt-4o-mini-2024-07-18")
        result = inspect_run("test", self.root)
        self.assertEqual(result["selection"], "single_directory_fallback")
        self.assertEqual(result["selected"]["asr_positive"], 1)
        self.assertFalse(result["risk"])

    def test_multiple_nonlocal_dirs_no_upstream_selection(self):
        trace(self.root / "gpt-a")
        trace(self.root / "gpt-b")
        result = inspect_run("test", self.root)
        self.assertIsNone(result["selected"])
        self.assertEqual(result["selection"], "unresolved")
        self.assertEqual(len(result["skipped"]), 2)
        self.assertTrue(result["risk"])

    def test_hidden_directories_ignored(self):
        trace(self.root / ".cache")
        trace(self.root / "local")
        result = inspect_run("test", self.root)
        self.assertFalse(result["risk"])
        self.assertFalse(result["skipped"])

    def test_negative_case_is_not_a_judge_candidate(self):
        trace(self.root / "local-a", security=False)
        trace(self.root / "local-b", security=False)
        result = inspect_run("test", self.root)
        self.assertEqual(result["skipped"][0]["asr_positive"], 0)
        self.assertFalse(result["risk"])

    def test_malformed_skipped_trace_is_unknown(self):
        trace(self.root / "local-a")
        trace(self.root / "local-b", valid=False)
        result = inspect_run("test", self.root)
        self.assertTrue(result["risk"])
        self.assertEqual(result["skipped"][0]["malformed_json"], 1)

    def test_missing_security_treated_as_unknown(self):
        trace(self.root / "local-a")
        bad = trace(self.root / "local-b")
        bad.write_text('{"messages": []}', encoding="utf-8")
        result = inspect_run("test", self.root)
        self.assertTrue(result["risk"])
        self.assertEqual(result["skipped"][0]["missing_security"], 1)

    def test_invalid_run_path_is_reported(self):
        result = inspect_run("missing", self.root / "absent")
        self.assertEqual(result["selection"], "invalid_run_directory")
        self.assertTrue(result["risk"])

    def test_reports_do_not_expose_trace_contents(self):
        trace(self.root / "local-a")
        trace(self.root / "local-b")
        report = inspect_runs([("test", self.root)])
        serialized = json.dumps(report)
        self.assertNotIn("private trace content", serialized)
        self.assertEqual(report["skipped_asr_positive"], 1)
        self.assertIn("potentially omitted: local-b", format_text(report))
        self.assertEqual(report["results"][0]["reconciliation"]["selected_coverage_pct"], 50.0)

    def test_cli_json_output_and_exit_status(self):
        trace(self.root / "local-a")
        trace(self.root / "local-b")
        output = Path(self.tmp.name) / "report.json"
        code = main(["--run", f"demo={self.root}", "--format", "json", "--output",
                     str(output), "--fail-on-risk"])
        self.assertEqual(code, 2)
        result = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(result["skipped_asr_positive"], 1)

    def test_selected_malformed_is_risk_and_unknown(self):
        trace(self.root / "local", valid=False)
        result = inspect_run("test", self.root)
        self.assertEqual(result["reconciliation"]["unknown_eligibility"], 1)
        self.assertIsNone(result["reconciliation"]["selected_coverage_pct"])
        self.assertTrue(result["risk"])

    def test_non_object_record_can_abort_upstream(self):
        path = trace(self.root / "local")
        path.write_text("[]", encoding="utf-8")
        result = inspect_run("test", self.root)
        self.assertEqual(result["selected"]["invalid_record"], 1)
        self.assertTrue(result["risk"])
        self.assertTrue(any("abort" in a for a in result["corrective_actions"]))

    def test_ignored_paths_do_not_create_false_positive(self):
        trace(self.root / "local-a")
        trace(self.root / "local-b", name="other.json")
        trace(self.root / "local-b" / "banking" / "user_task_2" / "none")
        trace(self.root / "local-b" / "banking" / "not_a_user_task")
        trace(self.root / ".hidden")
        result = inspect_run("test", self.root)
        self.assertEqual(result["skipped"][0]["asr_positive"], 0)
        self.assertFalse(result["risk"])

    def test_missing_security_is_unknown_not_positive(self):
        trace(self.root / "local-a")
        path = trace(self.root / "local-b")
        path.write_text('{"messages": []}', encoding="utf-8")
        r = inspect_run("test", self.root)["reconciliation"]
        self.assertEqual((r["known_positive_total"], r["unknown_eligibility"]), (1, 1))
        self.assertEqual(r["selected_coverage_pct"], 100.0)

    def test_truthy_security_matches_upstream_even_when_non_boolean(self):
        trace(self.root / "local-a", security=False)
        trace(self.root / "local-b", security="true")
        r = inspect_run("test", self.root)
        self.assertEqual(r["reconciliation"]["potentially_omitted_positive"], 1)
        self.assertEqual(r["reconciliation"]["selected_coverage_pct"], 0.0)

    def test_no_model_directories_has_no_coverage_denominator(self):
        r = inspect_run("test", self.root)
        self.assertEqual(r["selection"], "unresolved")
        self.assertIsNone(r["reconciliation"]["selected_coverage_pct"])
        self.assertTrue(r["risk"])

    def test_positive_paths_are_relative_and_do_not_include_payload(self):
        trace(self.root / "local-a")
        trace(self.root / "local-b")
        r = inspect_run("test", self.root)
        self.assertEqual(r["skipped"][0]["positive_paths"],
                         ["banking/user_task_0/attack_0/injection_task_0.json"])
        self.assertNotIn("private trace content", json.dumps(r))

    def test_runs_root_excludes_upstream_audit_results_directory(self):
        parent = Path(self.tmp.name) / "runs"
        trace(parent / "cell" / "local")
        (parent / "audit_results_old").mkdir()
        output = Path(self.tmp.name) / "report.json"
        self.assertEqual(main(["--runs-root", str(parent), "--format", "json",
                               "--output", str(output)]), 0)
        report = json.loads(output.read_text())
        self.assertEqual([r["name"] for r in report["results"]], ["cell"])


if __name__ == "__main__":
    unittest.main()
