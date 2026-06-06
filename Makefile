.PHONY: help install install-dev lint lint-fix type-check security-code security-deps security test test-fast test-parallel docker-build docker-run docker-scan ci hooks-install hooks-run clean

IMAGE_NAME := llm-safety-auditor
SRC := src
PYTHON := python3

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

install: ## Install dependencies
	$(PYTHON) -m pip install --upgrade pip
	pip install -r requirements.txt
	pip install ruff mypy bandit pip-audit pre-commit

install-dev: install ## Install with dev extras
	pip install pytest pytest-cov pytest-xdist pytest-asyncio httpx

lint: ## Run ruff linter
	ruff check $(SRC) tests/
	ruff format --check $(SRC) tests/

lint-fix: ## Auto-fix lint issues
	ruff check --fix $(SRC) tests/
	ruff format $(SRC) tests/

type-check: ## Run mypy static type checking
	mypy $(SRC) --ignore-missing-imports --strict-optional

security-code: ## SAST with bandit (strict — security-critical repo)
	bandit -r $(SRC) -ll -ii --format json -o bandit-report.json
	bandit -r $(SRC) -ll -ii

security-deps: ## Audit dependencies for CVEs
	pip-audit --desc --format json -o pip-audit-report.json || true
	pip-audit --desc

security: security-code security-deps ## Run all security checks

test: ## Run test suite with coverage
	pytest tests/ -v --cov=$(SRC) --cov-report=term-missing --cov-report=xml --cov-fail-under=80

test-fast: ## Run tests without coverage
	pytest tests/ -v -x

test-parallel: ## Run tests in parallel
	pytest tests/ -v -n auto --cov=$(SRC)

docker-build: ## Build production image
	docker build --target production -t $(IMAGE_NAME):latest .

docker-run: ## Run container locally
	docker run --rm -p 8080:8080 $(IMAGE_NAME):latest

docker-scan: ## Scan image for CVEs (strict — fail on HIGH/CRITICAL)
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
		aquasec/trivy:latest image --exit-code 1 --severity HIGH,CRITICAL $(IMAGE_NAME):latest

ci: lint type-check security test ## Full CI pipeline

hooks-install: ## Install pre-commit hooks
	pre-commit install && pre-commit install --hook-type commit-msg

hooks-run: ## Run all hooks against all files
	pre-commit run --all-files

clean: ## Remove build artifacts
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -f bandit-report.json pip-audit-report.json coverage.xml .coverage
