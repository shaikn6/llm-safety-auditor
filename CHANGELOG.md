# Changelog

All notable changes to this project are documented here.

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
