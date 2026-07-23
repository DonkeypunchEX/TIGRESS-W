<!--
TIGRESS-W pull-request template. Fill in the sections that apply; delete the
rest. Keep the checklist honest — CI enforces most of it, but the reviewer
relies on it too.
-->

## What & why

<!-- One or two sentences: what this changes and the reason for it. -->

## Changes

<!-- Bullet the notable changes. Call out anything platform-specific
     (Windows netsh/PowerShell, Termux) or anything touching the
     forensic/evidence, correlation, or alerting paths. -->

-

## Testing

<!-- How you verified this. New/updated tests, and the local gate below. -->

- [ ] `pytest -q` passes
- [ ] `ruff check src tests` clean
- [ ] `bandit -r src -ll` clean
- [ ] Tests stay hermetic (no real sensors, Termux, Windows, or network)

## Notes / limitations

<!-- Follow-ups, known gaps, or anything a reviewer should keep in mind. -->
