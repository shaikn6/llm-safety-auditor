## What

<!-- One or two sentences on the change. -->

## Why

<!-- The problem this solves or the behaviour it adds. -->

## Checklist

- [ ] `make lint` passes (ruff check + ruff format --check, as CI runs it)
- [ ] `make test` passes (coverage gate 95%)
- [ ] `make security-code` reports no new bandit findings
- [ ] New attacks or detector rules have tests; bug fixes have a regression test
- [ ] Detector changes: recall / false-positive numbers in the README re-measured, or marked as not re-run
- [ ] `CHANGELOG.md` updated
