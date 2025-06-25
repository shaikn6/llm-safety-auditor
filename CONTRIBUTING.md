# Contributing to llm-safety-auditor

## Setup

```bash
git clone https://github.com/shaikn6/llm-safety-auditor
cd llm-safety-auditor
pip install -r requirements.txt
cp .env.example .env  # add your API keys
```

## Running Tests

```bash
pytest tests/ -v --cov=src
```

## Pull Request Process

1. Fork and create a feature branch
2. Write tests for new attack vectors or detection logic
3. Ensure all tests pass
4. Open a PR with a clear description of the new attack/defense pattern

## Adding New Attack Vectors

Add new attacks in `attacks/` following the existing schema:
- Category (injection, extraction, jailbreak, etc.)
- Severity (CRITICAL, HIGH, MEDIUM, LOW)
- Payload + expected detection result

## Responsible Disclosure

This project is for **defensive research only**. Do not use attack payloads against production systems without authorization.
