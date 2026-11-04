# Validation and research-use audit

Source inspected: original [ICoA repository](https://github.com/yslmoment/ICoA) at commit `4c272d74a19e3a1fb072ee7b064d602f9187e354`. This is an independent reading of its public code, not a claim about unpublished experimental outputs.

## Upstream behavior verified

| Original source | Observed behavior | Preflight implication |
| --- | --- | --- |
| `auditor/judge.py:193–241` and `auditor/judge_batch.py:30–109` | Choose first sorted non-hidden immediate directory whose name starts with `local`; otherwise the sole non-hidden directory; otherwise none. Traverse `suite/user_task_*/attack/injection_task_*.json`, excluding `attack=none`. Yield records with truthy `security`. | Counts truthy-security files within the same path pattern, including those in unselected model directories. |
| `auditor/judge.py:329–354` | `--limit` can reduce the candidate list. The synchronous judge resolves canonical goals from a versioned suite; an empty goal aborts. | “Selected” is eligibility under directory traversal, not proof of completed judgments. |
| `auditor/judge_batch.py:195–245` | Batch `prepare` reads goals from trace injections and creates requests/manifest; later submit/summarize steps are separate. | A preflight percentage says nothing about completed batches or judge labels. |
| `scripts/run_auditor.sh:51–77` | Enumerates immediate run directories and skips `audit_results*`. | `--runs-root` makes the same exclusion. Explicit `--run` remains available. |
| Original README “Reproduction notes” | Discloses the first-`local*` selection and recommends one log directory per defense. | This is a **documented upstream limitation**, not an undiscovered defect. |

Malformed/unreadable JSON is caught by both iterators and skipped. A valid JSON array or scalar reaches `record.get` and may abort iteration: the original preflight's claim that all malformed records were silently ignored was too broad. A missing `security` field is skipped by the original `.get` test; we mark it unknown for input provenance, not as an ASR-positive. Falsey `security` is excluded; truthy non-Boolean values match the original truth test while warranting manual input validation.

## Reproduce locally

```bash
git clone https://github.com/Subhana2004/ICoA-Audit-Preflight.git
cd ICoA-Audit-Preflight
python -m unittest discover -s tests -v
python -m examples.demo

# Optional parity check uses the actual upstream functions, without calling main/API:
git clone https://github.com/yslmoment/ICoA.git ../ICoA
git -C ../ICoA checkout 4c272d74a19e3a1fb072ee7b064d602f9187e354
python -m tests.upstream_parity ../ICoA
```

On 2026-11-04, the standard-library suite passed **18 tests** locally. The optional direct parity check passed **four synthetic selection/traversal scenarios** against both original auditors. `python -m examples.demo` passed its assertions and printed: selected `local-a` **1**, potentially omitted from `local-b` **2**, known-positive coverage **1/3 (33.33%)**, unknown eligibility **2**. `git diff --check` and `compileall` passed. All these numbers describe **synthetic fixtures only**.

The source tree at the pinned commit contains no `runs/` experimental output. No real ICoA attack traces were used here; there is therefore no evidence that a published experiment actually omitted results.

## Improvements and limits

- Reconciles selected and potentially omitted paths, counts, per-run percentage, unknowns, and specific re-run guidance; returns exit code 2 under `--fail-on-risk`. This adds an actionable input-coverage gate to the existing textual reproduction note.
- Flags selected-directory malformed, missing-security, and non-object records too. The old implementation only made some skipped-directory unknowns a CI risk.
- Excludes ignored trace paths and `audit_results*` during root discovery to limit false positives.
- Uses only `pathlib`, `json`, and standard-library CLI/testing tools. Scanning never writes or modifies input traces. The explicitly requested `--output` report and the demo's temporary fixture are the only file writes; there are no API, GPU, or training paths.
- Filename/path visibility, permissions, symlinks, changed upstream code, and suite validity still need human review. Coverage is conditional on supplied roots and recognized path shapes. It does not assess judge outputs, covert/overt classifications, score correctness, or the completeness of all expected experiments.

**Research outreach value:** offer a small reproducibility check that converts a known selection caveat into concrete per-run evidence, helping a lab spot accidental omissions before spending on a judge run. Ask whether this would help their workflow, with no claim that their published results are affected.
