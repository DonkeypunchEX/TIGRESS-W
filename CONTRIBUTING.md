# Contributing to TIGRESS-W

TIGRESS-W is the Windows edition of TIGRESS, kept as a **single cross-platform
codebase** — the detection, correlation, dashboard, storage, and security
layers are shared, and only the sensor/notification edges are platform-specific.
Please keep that property intact: changes should work (or degrade gracefully)
regardless of host OS, and the test suite must run without real sensors,
Termux, Windows, or the network.

## Branch → PR → green → merge

`main` is the integration branch and is meant to stay releasable. Do not commit
to it directly:

1. **Branch** off `main` with a descriptive name
   (`feat/…`, `fix/…`, `chore/…`).
2. **Commit** focused changes with clear messages.
3. **Open a pull request** against `main` (draft while it's in progress) and
   fill in the PR template.
4. **Get CI green** — every required check must pass (see below).
5. **Merge** once CI is green and review (if required) is satisfied.

## Local gate (run before pushing)

```bash
pip install -r requirements-dev.txt   # once
ruff check src tests                   # lint (CI-enforced)
pytest -q                              # full hermetic suite
bandit -r src -ll                      # security scan (CI-enforced)
pip-audit -r requirements.txt          # dependency audit (CI-enforced)
```

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request:

| Job | What it enforces |
| --- | --- |
| `lint-and-test` (Python 3.10, 3.11, 3.12) | `ruff check src tests` + `pytest -q` |
| `security-scan` | `bandit -r src -ll` + `pip-audit -r requirements.txt` |

These four check runs — `lint-and-test (3.10)`, `lint-and-test (3.11)`,
`lint-and-test (3.12)`, and `security-scan` — are the ones to require in the
branch-protection rule for `main`.

## Conventions

- Python 3.8+ syntax, line length 100, imports sorted by ruff (`I` rules).
- Docstrings are **required** on everything public in `src/` (ruff `D100`–`D104`)
  and deliberately **not** required in `tests/`.
- Alert-delivery channels stay standard-library only (no new runtime deps).
- Preserve forensic-evidence discipline: hashes live separately from the data
  they protect (manifest sidecars, verified evidence bundles).
- New Windows sensor/notifier code shells out to OS tools (`netsh`, PowerShell);
  factor the parsing into pure functions so it stays unit-testable off-Windows.
