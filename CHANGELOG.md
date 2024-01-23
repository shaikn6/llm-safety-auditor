# Changelog
## v2.0.0 — 2026-05-30
### What's New
- Automated attack generation: 100 variants via mutation engine
- CI/CD integration: GitHub Actions workflow + SARIF output for Security tab
- Attack replay suite: regression testing across model versions
- Full OWASP LLM Top 10 v1.1 scoring with CWE mapping
### Improvements
- Attack coverage: 100 auto-generated (was 50 manual in V1)
- OWASP scoring now weighted by severity with remediation guide
### Under the Hood
- +35 tests covering mutation engine, SARIF format, regression detection
## v1.0.0 — 2026-05-30
- 50-attack adversarial red-teaming, OWASP LLM Top 10 compliance grid
