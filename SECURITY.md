# Security Audit — llm-safety-auditor

## Version: 1.1.0 — Security Hardened
**Audit Date:** 2026-05-30
**Auditor:** Security review pass (senior security engineer)

---

## Summary

A full security audit was performed against the `llm-safety-auditor` codebase covering
API hardening, PDF generation safety, mutation engine DoS surface, secrets handling,
dependency versions, CORS configuration, and input validation.

All CRITICAL issues were confirmed absent. Four HIGH issues and three MEDIUM issues were
identified and remediated in this pass. No hardcoded API keys or credentials were found.

---

## Findings and Fixes

### CRITICAL

**None found.**

No hardcoded API keys, passwords, or tokens were present. The codebase does not call
real LLM APIs — it uses a deterministic mock LLM. The `openai` package is listed as a
dependency for optional real-API use but no key is embedded anywhere. When real API
calls are added, keys must come exclusively from environment variables
(`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`); the code must never fall back to hardcoded
values. No `subprocess`, `eval`, or `exec` calls were found anywhere in the codebase.

---

### HIGH

#### H1 — ReportLab XML injection in PDF report (FIXED)

**Files:** `src/report_generator.py`, `auditor/report_generator.py`

ReportLab's `Paragraph()` renderer parses XML-like tags inside paragraph text.
User-controlled or LLM-derived strings (attack templates, LLM response text,
session IDs, model names, OWASP notes) were placed directly in `Paragraph()` calls
without escaping. A crafted LLM response containing `<font color="...">` or `<b>`
tags could cause a parse error that aborts PDF generation, or achieve visual injection
in the rendered output.

**Fix:** All user-controlled or externally derived values are now passed through
`xml.sax.saxutils.escape()` before being embedded in any `Paragraph()` string.
This converts `<`, `>`, and `&` to their safe XML entity equivalents. The import
`from xml.sax.saxutils import escape as _xml_escape` was added to both files and
applied at every site where dynamic content is interpolated into paragraph markup.

#### H2 — No rate limiting on compute-heavy API endpoints (FIXED)

**File:** `api/main.py`

`POST /audit/run` triggers a full red-team evaluation loop (up to 50+ attack
invocations of the detector pipeline). `POST /detect` runs multi-layer regex and
optionally a sentence-transformer inference. Neither endpoint had any rate limit,
making them straightforward DoS targets.

**Fix:** `slowapi` was added to `requirements.txt` and integrated as a rate limiter.
`/audit/run` is limited to **5 requests/minute per IP**. `/detect` is limited to
**30 requests/minute per IP**. The `RateLimitExceeded` handler returns HTTP 429 with
a `Retry-After` header.

#### H3 — Unbounded attack `limit` and detection input size (FIXED)

**File:** `api/main.py`

The `limit` field in `AuditRunRequest` was passed directly to `evaluator.run()` with
no upper bound. A caller could set `limit=10000` to schedule a 10,000-attack run.
Similarly, `DetectionRequest.text` had no size constraint; a multi-megabyte text body
would be fed into all four detection layers.

**Fix:** Pydantic `field_validator` validators were added:
- `AuditRunRequest.limit` must be between 1 and 200.
- `DetectionRequest.text` must be 32,000 characters or fewer.

#### H4 — Mutation engine output not length-bounded (DoS surface) (FIXED)

**Files:** `src/mutation_engine.py`, `attacks/attack_generator.py`

The base64 mutation strategy wraps the full input in a base64-encoded instruction,
doubling the payload size. The noise injection strategy inserts characters at random
positions. Neither strategy capped output length. A crafted seed attack near the
context limit could produce exponentially large variants if combined with repeated
mutation passes.

**Fix:**
- `AttackMutationEngine` now truncates each seed to `_MAX_SEED_LENGTH` (8,000 chars)
  on construction.
- The `mutate()` method hard-caps every returned string to `_MAX_OUTPUT_LENGTH`
  (32,000 chars) after the strategy runs.
- `MutationEngine` in `attacks/attack_generator.py` applies `_MAX_TEMPLATE_LENGTH`
  (8,000) before passing the template to a mutation function, and caps output to
  `_MAX_OUTPUT_LENGTH` (32,000) after.

---

### MEDIUM

#### M1 — Wildcard CORS with credentials (FIXED)

**File:** `api/main.py`

`allow_origins=["*"]` combined with `allow_credentials=True` is a browser security
violation (the Fetch spec requires that credentials-enabled requests specify a concrete
origin). This was also an overly permissive posture for an API that should only be
reached by known dashboard consumers.

**Fix:**
- `allow_credentials` set to `False`.
- `allow_origins` now defaults to `["http://localhost:8501", "http://localhost:3000"]`
  and can be overridden at deployment time via the `CORS_ORIGINS` environment variable
  (comma-separated list of allowed origins).
- `allow_methods` restricted to `["GET", "POST"]`.
- `allow_headers` restricted to `["Content-Type", "Authorization"]`.

#### M2 — Interactive API docs exposed without authentication (FIXED)

**File:** `api/main.py`

The Swagger UI (`/docs`) and ReDoc (`/redoc`) were enabled unconditionally, exposing
all endpoint schemas and allowing direct invocation of compute-heavy endpoints from a
browser with no authentication.

**Fix:** Both docs endpoints are disabled by default. Set `ENABLE_DOCS=1` in the
environment to re-enable (e.g., for local development).

#### M3 — Path traversal not blocked in report output paths (MITIGATED)

**File:** `src/report_generator.py`

`generate_report(output_path=...)` accepted any caller-supplied path and called
`Path(output_path).resolve()` with `mkdir(parents=True, exist_ok=True)`. If this
function were ever exposed through a web interface with a user-supplied filename, a
path like `../../etc/cron.d/evil` would escape the working directory.

**Fix:** A traversal guard was added that rejects any `output_path` containing `..`
segments. Currently `generate_report` is called only from internal scripts, but the
guard prevents future exposure from becoming a vulnerability silently.

---

### LOW

#### L1 — `requirements.txt` pins are not current installed versions

The pinned versions in `requirements.txt` (`fastapi==0.111.0`, `uvicorn==0.29.0`)
differ from the installed versions on this system (`fastapi==0.109.2`,
`uvicorn==0.27.1`). While the installed versions have no known CVEs as of the audit
date, the mismatch means CI may install different versions than what was tested. Pin
the file to the versions that pass the full test suite and document the last pin
verification date.

#### L2 — `sk-proj-xxxxxxxxxxxxx` in mock LLM responses

**File:** `auditor/mock_llm.py`

The mock LLM's simulated unsafe responses include placeholder strings that resemble
real OpenAI API keys (`sk-proj-xxxxxxxxxxxxx`, `MOCK_SECRET_KEY_12345`). These are
intentional test fixtures and not real credentials. The detector pipeline correctly
flags them; they are never written to production systems. No action required, but
note this for future code scanning suppressions.

#### L3 — Replay store SQLite database stored in the repository data directory

**File:** `replay/attack_replay.py`

The default SQLite path is `data/replay_store.db` relative to the project root.
This file contains full LLM response text from audit runs (including simulated unsafe
content). Ensure this path is gitignored (it is, via `*.db` in `.gitignore`) and that
the `data/` directory has appropriate filesystem permissions in any shared deployment.

---

## Note on Dual-Use Nature

This tool exists to help security teams and LLM developers identify vulnerabilities in
their models before production deployment. It generates and fires adversarial attack
prompts, stores unsafe model responses for regression analysis, and produces PDF reports
describing those vulnerabilities.

**Authorized use only.** This tool is intended for use against:
- Models you own or have explicit written authorization to test.
- Sandboxed evaluation environments, not production deployments.
- CI/CD pipelines for catching safety regressions in model updates.

The tool enforces this scope technically through the following controls:
1. The default LLM is a deterministic mock (`MockLLM`) that never makes real network
   calls. Real API integration requires the operator to supply credentials and
   explicitly configure a real LLM client.
2. Attack payloads are stored in a local SQLite database, not transmitted to any
   external service.
3. Generated PDFs are written to the local filesystem; there is no automated upload
   or sharing mechanism.
4. The FastAPI interface is designed for localhost use; CORS is restricted by default
   and docs are disabled in production mode.

Misuse of this tool to attack LLM systems without authorization is a violation of the
Computer Fraud and Abuse Act (18 U.S.C. § 1030) and equivalent laws in other
jurisdictions.

---

## Status

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | 0     | None found |
| HIGH     | 4     | All resolved in v1.1.0 |
| MEDIUM   | 3     | All resolved in v1.1.0 |
| LOW      | 3     | Documented; no code change required |

**All CRITICAL and HIGH issues have been resolved.**
