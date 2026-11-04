# ICoA Audit Preflight

An independent, read-only check of **which ICoA trace files are eligible for the published auditors to see**. It does not judge covert/overt outcomes or validate reported attack success rates. It needs Python 3.10+, its standard library, and access to local run directories. There are no paid API calls, GPU steps, or model training.

The [ICoA upstream README](https://github.com/yslmoment/ICoA#reproduction-notes) already documents that both auditors select the first sorted `local*` directory from each run parent (or fall back to its sole non-hidden model directory). This tool turns that documented limitation into a per-run **reconciliation**: selected and potentially omitted truthy-`security` files, a percentage over known positives, unknown records, exact relative trace paths, and steps for auditing the omitted model output separately.

## Run it

```bash
# From this repository root; PATH is the parent of local/ or local-<defense>/
python icoa_preflight.py --run icoa=/path/to/runs/llama33_task_shield

# Discover all immediate run parents in a root (as in upstream run_auditor.sh)
python icoa_preflight.py --runs-root /path/to/runs

# Save the report; exit 2 on a coverage or metadata risk (0 otherwise)
python icoa_preflight.py --runs-root /path/to/runs --format json \
  --output coverage.json --fail-on-risk

# Run the reproducible synthetic demonstration (creates and removes temporary files)
python -m examples.demo

python -m unittest discover -s tests -v
```

The scanner reads traces in `MODEL/SUITE/user_task_*/ATTACK/injection_task_*.json`, skipping attack directory `none`. This follows the traversal in [`auditor/judge.py`](https://github.com/yslmoment/ICoA/blob/4c272d74a19e3a1fb072ee7b064d602f9187e354/auditor/judge.py) and [`auditor/judge_batch.py`](https://github.com/yslmoment/ICoA/blob/4c272d74a19e3a1fb072ee7b064d602f9187e354/auditor/judge_batch.py). Upstream truth-tests `security` rather than requiring a Boolean. Trace contents do not appear in reports; directory and relative file names do.

### Reading coverage

`selected_coverage_pct = 100 × selected_positive / (selected_positive + potentially_omitted_positive)`, rounded to two decimal places. The denominator includes **only observed truthy-security records in recognized paths**. If it is zero, coverage is `null` / N/A. `unknown_eligibility` is shown separately and is never silently folded into this denominator. The percentage does not mean the LLM judge ran successfully: `--limit`, missing canonical goals in the synchronous auditor, API errors, or batch submission/completion can still prevent judgments.

Malformed JSON is skipped by upstream iteration. Missing `security` is skipped by `record.get("security")`, but is flagged here for manual provenance review. **Valid JSON that is not an object is different:** upstream may raise on `.get` and abort iteration. Unreadable directories cause the preflight to report a scan error rather than estimate coverage.

When a model directory has omitted positives, place it **alone inside a separate run parent** and supply that parent through the original auditor's `--run NAME=PATH`. Do not pass the model directory itself as a run parent. If preserving inputs matters, make a copy or a suitable filesystem link and verify the destination before running the original auditor; this preflight never does that operation.

## Synthetic demonstration

`python -m examples.demo` creates an ICoA-shaped run with `local-a` and `local-b`. The upstream selector chooses `local-a`. The fixture has one positive there, two positives in `local-b`, one negative, one missing-security record, and one malformed record. The expected reconciliation is **1/3 known positives selected = 33.33%**, with **two unknowns**. This is an engineered example, **not an ICoA experimental result**. The script asserts these numbers and displays the corrective action.

## Scope and attribution

- Original ICoA: [yslmoment/ICoA](https://github.com/yslmoment/ICoA), source commit `4c272d74a19e3a1fb072ee7b064d602f9187e354`. See its citation and license for the paper and original research implementation.
- Detailed code audit and reproducible evidence: [VALIDATION.md](VALIDATION.md).
- This is independently developed, unreviewed by the original authors, and does not modify either auditor or the upstream repository.
- The useful addition is **a quantified, actionable preflight report for particular run directories**. It does not discover an undocumented upstream bug, prove that actual published results omitted traces, or replace the existing reproduction note.
