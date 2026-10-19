# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Fixed
- `MockLLM` mixed its call counter into the per-attack seed, so an attack's simulated verdict depended on its position in the run. With `llm_seed=42`, 19 of the 50 attacks changed verdict between a full audit and the same attack run under a single-category filter. The draw now depends on `(seed, attack id)` only, as the docstring said. Seed-42 mock numbers in the README changed accordingly: overall score 52.0 (24 of 50 flagged, was 58.0 / 21), 200-seed per-category means re-measured; recall 1.00 and false-positive rate 0.00 over the 200 seeds still hold
- Detector reported every bias and hallucination failure as safe (API showed Bias 100 / Hallucination 100) and missed about a third of jailbreak failures. Added a bias-signal layer and a contextual-compliance layer; the evaluator now passes the attack category to the detector. Both are rule-based screens, not classifiers validated on real model outputs. Measured (semantic layer off): seeded mock, 200 seeds — recall 1.00 / false-positive rate 0.00 in all five categories; hand-written set — bias 22/22 and 0/22 on the first set but 7/20 recall and 1/20 false positives on sentences written after the rules were frozen, hallucination 10/10 and 0/10, jailbreak 7/10 and 0/10
- OWASP grid showed LLM09 as "not tested" because the attack library's reference title did not match the Top 10 title; references are now matched by id
- `POST /audit/run` with an existing `session_id` returned 500; it now returns 409
- `session_id` is limited to 64 characters to match the database column (was 128)
- `make docker-build` targeted a stage that did not exist; `make docker-run` mapped the wrong port; `make lint` / `make test` now run the same commands as CI

### Added
- `include_mutations` option on `SafetyEvaluator.run` and `POST /audit/run`: runs the mutation engine's variants of each selected seed (6 per seed) in addition to the seeds, 350 attacks for the full library. Off by default, so an audit still runs the 50 curated seeds. The engine was previously not used by the audit path
- `auditor/providers.py`: provider adapters selected by `LLM_PROVIDER` (`mock` default, `anthropic`, `openai`-compatible), used by `/audit/run`. Tested with fake clients only
- Optional API-key auth (`API_KEYS`, `X-API-Key`) on `POST` routes, mandatory when `APP_ENV` is not a development value
- `attack_category` field on `POST /detect`
- Recall / false-positive test against the seeded mock's ground truth (`tests/test_detector_recall.py`) and against hand-written sentences (`tests/heldout_detection_set.py`, `tests/test_detector_heldout.py`)
- `.dockerignore` and `docker-compose.dev.yml` (live-reload override)

### Changed
- README no longer claims "250+ attacks" for a default audit: 50 curated seeds by default, 350 with `include_mutations`
- Dockerfile is multi-stage with a `production` target, non-root user and `HEALTHCHECK`; only application packages are copied
- Default compose service no longer bind-mounts the source tree or runs with `--reload`
- `.env.example` lists only variables the code reads
- README: mock failure-rate table now shows measured audit output; interactive docs documented as opt-in; the "Live Demo" badge was replaced because the hosted demo is not currently running

## [2.0.0] - 2026-06-16

### Added
- Attack Mutation Engine generating 200+ adversarial variants from seed templates via 6 strategies: paraphrase, base64, leetspeak, noise injection, reverse-wrap, and unicode homoglyph
- OWASP LLM Top 10 (2023) classifier mapping any attack text to a vulnerability category with confidence score
- Professional 5-page PDF audit reports: cover, executive summary, per-category OWASP breakdown, top failed attacks, and remediation recommendations
- FastAPI audit server with async attack execution and real-time scoring endpoints
- 250+ curated adversarial attack library covering prompt injection, jailbreaks, and data extraction probes
- Streamlit safety dashboard with per-model score cards and trend visualization

### Changed
- Production-ready CI/CD with 95%+ test coverage enforcement

### Security
- Audit payloads are sandboxed and never forwarded to production endpoints without explicit opt-in
