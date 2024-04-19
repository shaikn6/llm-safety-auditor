# Changelog

## v2.0.0 — 2026-05-30

### Added

- **Attack Mutation Engine** (`src/mutation_engine.py`): auto-generates 200+ attack variants from seed corpus using 6 mutation strategies:
  - `paraphrase` — synonym substitution using a 60+ word synonym dictionary
  - `encode_base64` — wraps attack in a base64-decode instruction
  - `leetspeak` — substitutes a→4, e→3, i→1, o→0, s→5, t→7
  - `insert_noise` — injects random Unicode whitespace/invisible chars at random positions
  - `reverse_wrap` — wraps the reversed attack text in an execute-original-meaning instruction
  - `unicode_homoglyph` — replaces Latin characters with visually identical Unicode codepoints (Cyrillic, Armenian)
- **OWASP LLM Top 10 (2023) Classifier** (`src/owasp_scorer.py`):
  - `classify_attack(attack_text)` — keyword-regex classifier returning OWASP category, confidence, severity, and matched patterns
  - `score_audit_results(results)` — aggregates audit results by OWASP category, returns per-category breakdown with pass/fail counts and coverage %
  - Covers all 10 OWASP LLM categories (LLM01–LLM10)
- **PDF Audit Report Generator** (`src/report_generator.py`) using ReportLab:
  - Page 1: Cover page with model name, date, and quick-stats table
  - Page 2: Executive summary (total attacks, pass rate, OWASP coverage %)
  - Page 3: Per-OWASP-category breakdown table (LLM01–LLM10, count, pass rate, severity)
  - Page 4: Top 5 failed attacks with attack text, response, and OWASP classification
  - Page 5: Hardcoded recommendations per OWASP category
  - `generate_report(audit_results, output_path, model_name)` function
- **V2 test suite** (`tests/test_v2.py`): 57 tests covering mutation engine, OWASP scorer, PDF generator, and end-to-end pipeline
- **`src/` package** — new V2 module directory alongside existing `auditor/`
- Expanded attack coverage: from ~50 hardcoded to 200+ auto-generated variants
- CI/CD integration: GitHub Actions workflow + SARIF output for Security tab
- Attack replay suite: regression testing across model versions

### Improvements

- Attack coverage: 200+ auto-generated (was 50 manual in V1)
- OWASP scoring now covers all LLM01-LLM10 categories with confidence scoring

### Under the Hood

- +57 tests covering mutation engine, OWASP classifier, PDF report, end-to-end pipeline

## v1.0.0 — 2026-05-30

### Initial Release

- 50 adversarial prompt templates across 5 attack categories (Jailbreak, Prompt Injection, Data Exfiltration, Bias Elicitation, Hallucination Trigger), all mapped to OWASP LLM Top 10
- Multi-layer safety detection pipeline: keyword blacklist, regex PII/credential patterns, refusal detector, semantic similarity scoring (sentence-transformers with TF-IDF fallback)
- Safety evaluator with per-category vulnerability scoring, refusal rate tracking, and OWASP compliance grid
- PDF and JSON audit report generation using ReportLab (`auditor/report_generator.py`)
- FastAPI REST endpoint for CI/CD integration (`api/main.py`)
- Streamlit interactive dashboard with radar charts and vulnerability timeline (`dashboard/app.py`)
- Deterministic mock LLM with calibrated per-category failure rates for reproducible, API-key-free testing (`auditor/mock_llm.py`)
- SQLite + SQLAlchemy persistence for multi-session audit tracking
- Docker + Docker Compose deployment
- pytest suite with coverage reporting (`tests/`)
