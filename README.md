# ICoA Audit Preflight

A **read-only, dependency-free** diagnostic for potential audit-coverage gaps in the published [ICoA evaluation workflow](https://github.com/yslmoment/ICoA).

The original `auditor/judge.py` and `auditor/judge_batch.py` each select **one** immediate model-output subdirectory per benchmark run: the first sorted `local*` directory, or the only non-hidden subdirectory if there is exactly one. ICoA's README documents this behavior as a reproduction note, **not an undiscovered bug**. If several model-output directories coexist, other positive-security traces may not be audited.

This independently developed utility **does not change the original auditors, retrain models, perform LLM inference, send API requests, or publish attack traces**. It identifies directory-selection decisions and counts candidate ASR-positive (`security` truthy) trace files, providing evidence before an audit job runs. It is not an official ICoA tool and is not endorsed by its authors.

## Quick start

Requires Python **3.10+**. No dependencies or API keys.

```bash
# Check one ICoA run directory (the directory containing local/ or local-<defense>/)
python icoa_preflight.py --run icoa=runs/llama33_task_shield

# Or scan one level below a runs root (each immediate child treated as a run)
python icoa_preflight.py --runs-root runs/

# Save a structured JSON report and fail CI if coverage may be incomplete
python icoa_preflight.py --runs-root runs/ --format json --output coverage.json --fail-on-risk
```

**Example output from synthetic fixture data — not actual ICoA results:**

```text
ICoA Audit Preflight | runs checked: 1 | runs at risk: 1

[demo] selected=local-a (first_local)
  included: 1 traces; ASR-positive=1
  skipped: local-b (2 traces, ASR-positive=1, unknown=0)
  WARNING: 1 ASR-positive trace(s) occur outside the upstream-selected directory.

ASR-positive traces outside selected directories: 1
```

## What it detects

- Multiple `local*` directories where only the first sorted model directory would be selected.
- Multiple non-`local*` directories where upstream selection returns `None`.
- ASR-positive candidate trace files outside the chosen directory, following the upstream directory structure.
- Malformed JSON or missing `security` flags outside the chosen directory: flagged as **unknown**, not automatically counted as positive.
- Missing/unreadable run directories and malformed trace files in the chosen directory.

It intentionally reports **counts and directory paths only**, not trace payloads. A positive `security` flag is only an *input eligibility check* for the upstream auditor: this utility does **not** validate attack outcomes, auditor judgments, or scientific scores.

## Test

```bash
python -m unittest discover -s tests -v
```

Tests use synthetic temporary directories and no external research data.

## Reference and credit

The selection behavior was checked against the published `resolve_local()` implementations in:

- [yslmoment/ICoA — auditor/judge.py](https://github.com/yslmoment/ICoA/blob/main/auditor/judge.py)
- [yslmoment/ICoA — auditor/judge_batch.py](https://github.com/yslmoment/ICoA/blob/main/auditor/judge_batch.py)
- [ICoA README reproduction notes](https://github.com/yslmoment/ICoA#reproduction-notes)

Original paper: Yunseok Lee, Yunji Kim, and Woojin Lee. *Will the User Ever Know? Covert Indirect Prompt Injection Attacks on Tool-Using LLM Agents* (EMNLP 2026). See the original repository for complete citation and license information.

This project is independently authored and offered as an optional reproducibility aid. The authors have not been contacted about or approved this utility.
