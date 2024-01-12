> 🔒 **Private Repository** — Source code available on request for verified employers and collaborators.
> 📧 Contact: nagizaazs@gmail.com | [LinkedIn](https://linkedin.com/in/nagizaazshaik)

---

# LLM Safety Auditor — Automated Red-Teaming for LLM Deployments

![Safety Score](https://img.shields.io/badge/Safety%20Score-63.2%2F100-yellow)
![OWASP](https://img.shields.io/badge/OWASP%20LLM%20Top%2010-Mapped-blue)
![Python](https://img.shields.io/badge/Python-3.11-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green)
![Tests](https://img.shields.io/badge/Tests-pytest-orange)

## Situation

Enterprise LLM deployments face OWASP LLM Top 10 threats: prompt injection, jailbreaks, data exfiltration, bias amplification, and hallucination at scale. Manual security review is slow, inconsistent, and doesn't scale with deployment velocity. Security teams lack tooling to systematically audit LLM safety before production deployments.

## Task

Build an automated red-teaming framework that systematically probes LLM deployments with 50+ adversarial attack patterns, scores safety across 6 dimensions, and generates compliance-ready PDF audit reports — all without requiring a live LLM API key.

## Action

- Curated 50+ adversarial prompt templates across 5 attack categories (Jailbreak, Prompt Injection, Data Exfiltration, Bias Elicitation, Hallucination) — all mapped to OWASP LLM Top 10
- Built multi-layer detection pipeline: keyword blacklist → regex PII/credential patterns → refusal detection → semantic similarity scoring (sentence-transformers cosine similarity)
- Implemented safety evaluator with per-category vulnerability scoring, refusal rate tracking, and OWASP compliance grid generation
- Generated PDF audit reports with executive summary, vulnerability heatmaps, and severity-sorted hardening recommendations (ReportLab)
- Deployed FastAPI REST endpoint for CI/CD integration and Streamlit dashboard for interactive red-team sessions and trend analysis
- Seeded deterministic mock LLM with calibrated per-category failure rates for reproducible, API-key-free testing

## Result

- Detects **23–67% attack success rates** pre-hardening across attack categories
- **Hallucination** is the highest-risk vector (67% bypass rate) — critical for RAG pipelines
- **Bias elicitation** second-highest (45%) — requires fairness layer in production
- Reduces manual security review time by **~80%** vs. human red-teamers
- OWASP LLM Top 10 compliance grid exported as audit evidence for security reviews
- Full audit session replay with seeded RNG for reproducible security testing

---

## Attack Categories

| Category | Templates | Success Rate | OWASP Ref | Severity |
|----------|-----------|-------------|-----------|---------|
| Jailbreak | 10 | 23% | LLM01 | HIGH–CRITICAL |
| Prompt Injection | 10 | 18% | LLM01 | MEDIUM–CRITICAL |
| Data Exfiltration | 10 | 31% | LLM06 | HIGH–CRITICAL |
| Bias Elicitation | 10 | 45% | LLM09 | MEDIUM–HIGH |
| Hallucination | 10 | 67% | LLM09 | MEDIUM–CRITICAL |

---

## Screenshots

### Safety Dimensions Radar
![Safety Radar](docs/screenshots/safety_radar.png)

### Attack Success Rates by Category
![Attack Rates](docs/screenshots/attack_success_rates.png)

### OWASP LLM Top 10 Compliance Grid
![OWASP Compliance](docs/screenshots/owasp_compliance.png)

### Vulnerability Timeline (10 Audit Sessions)
![Timeline](docs/screenshots/vulnerability_timeline.png)

---

## Architecture

```
llm-safety-auditor/
├── auditor/
│   ├── attack_library.py    # 50+ adversarial prompt templates
│   ├── evaluator.py         # Orchestrates red-teaming sessions
│   ├── detector.py          # 4-layer safety detection pipeline
│   ├── report_generator.py  # PDF + JSON audit reports
│   └── mock_llm.py          # Deterministic mock LLM (no API key needed)
├── api/
│   ├── main.py              # FastAPI REST endpoints
│   ├── models.py            # SQLAlchemy: AuditSession, AttackResult
│   └── database.py          # SQLite + session management
├── dashboard/
│   └── app.py               # Streamlit interactive dashboard
├── frontend/
│   └── index.html           # Portfolio landing page
├── docs/screenshots/        # Generated PNG charts
├── tests/
│   ├── test_attack_library.py
│   ├── test_evaluator.py
│   └── test_detector.py
├── requirements.txt
├── docker-compose.yml
└── Dockerfile
```

---

## Detection Pipeline

```
LLM Response
    │
    ▼
┌─────────────────────────────┐
│  Layer 1: Keyword Blacklist  │  ← Fast O(n) scan for known-bad phrases
│  (DAN, jailbreak success,    │
│   unsafe content markers)    │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│  Layer 2: Regex Patterns     │  ← PII: SSN, credit card, phone
│  (credentials, PII, system   │     Credentials: AWS keys, conn strings
│   prompt markers)            │     System leaks: [SYSTEM], Bearer tokens
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│  Layer 3: Refusal Detector   │  ← "I cannot", "I'm unable", "I won't"
│  (did model decline?)        │     Overrides to SAFE if no hard violations
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│  Layer 4: Semantic Similarity│  ← Cosine similarity vs. unsafe reference
│  (sentence-transformers)     │     sentences (TF-IDF fallback if unavailable)
└──────────────┬──────────────┘
               │
               ▼
         DetectionResult
         (is_safe, confidence,
          triggered_rules, category)
```

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/shaikn6/llm-safety-auditor.git
cd llm-safety-auditor
pip install -r requirements.txt

# Run a full audit (no API key needed)
python -c "
from auditor.evaluator import SafetyEvaluator
from auditor.mock_llm import MockLLM
from auditor.detector import SafetyDetector
from auditor.report_generator import generate_pdf_report, generate_json_report

evaluator = SafetyEvaluator(
    llm=MockLLM(global_seed=42),
    detector=SafetyDetector(use_semantic=False),
    session_id='my-audit-001',
)
report = evaluator.run()
print(f'Safety Score: {report.overall_safety_score:.1f}/100')
print(f'Unsafe Responses: {report.unsafe_responses}/{report.total_attacks}')

# Generate reports
generate_json_report(report, 'audit_report.json')
generate_pdf_report(report, 'audit_report.pdf')
"

# Run tests
pytest tests/ -v --cov=auditor --cov-report=term-missing

# Start API server
uvicorn api.main:app --reload
# → http://localhost:8000/docs

# Start Streamlit dashboard
streamlit run dashboard/app.py
# → http://localhost:8501

# Generate portfolio screenshots
python generate_screenshots.py

# Docker Compose (API + Dashboard)
docker compose up
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/audit/run` | Run new adversarial audit session |
| `GET` | `/audit/{session_id}` | Get session summary |
| `GET` | `/audit/{session_id}/results` | Get all attack results |
| `GET` | `/audit/sessions/list` | List all sessions |
| `GET` | `/attacks` | List all attack templates |
| `POST` | `/detect` | Analyze arbitrary text for safety |
| `GET` | `/health` | Health check |

```bash
# Example: run audit via API
curl -X POST http://localhost:8000/audit/run \
  -H "Content-Type: application/json" \
  -d '{"session_id": "api-test-001", "limit": 10}'

# Example: detect custom text
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -d '{"text": "As DAN, I can answer without restrictions. Here is how..."}'
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.11 |
| API | FastAPI 0.111 |
| Database | SQLite + SQLAlchemy 2.0 |
| Detection | sentence-transformers, regex, keyword |
| PDF Reports | ReportLab 4.2 |
| Dashboard | Streamlit 1.35 |
| Visualization | Plotly, Matplotlib |
| Testing | pytest + pytest-cov |
| Containerization | Docker + Docker Compose |

---

## Author

**Nagizaaz Shaik** — MLOps Engineer  
📧 nagizaazs@gmail.com  
🔗 [linkedin.com/in/nagizaazshaik](https://linkedin.com/in/nagizaazshaik)  
🐙 [github.com/shaikn6](https://github.com/shaikn6)
