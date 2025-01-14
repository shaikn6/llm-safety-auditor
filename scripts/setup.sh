#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$PROJECT_ROOT/.venv"
PROD_MODE="${1:-}"

log()  { echo "[setup] $*"; }
warn() { echo "[warn]  $*" >&2; }
die()  { echo "[error] $*" >&2; exit 1; }

check_python() {
    if ! command -v python3 &>/dev/null; then
        die "python3 not found. Install Python 3.11+"
    fi
    PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    log "Found Python $PYTHON_VERSION"
}

create_venv() {
    if [[ ! -d "$VENV_DIR" ]]; then
        log "Creating virtual environment at $VENV_DIR"
        python3 -m venv "$VENV_DIR"
    else
        log "Virtual environment already exists"
    fi
}

install_deps() {
    log "Installing dependencies..."
    "$VENV_DIR/bin/pip" install --upgrade pip --quiet
    "$VENV_DIR/bin/pip" install -r "$PROJECT_ROOT/requirements.txt" --quiet
    if [[ "$PROD_MODE" != "--prod" ]]; then
        "$VENV_DIR/bin/pip" install ruff mypy bandit pip-audit pre-commit pytest pytest-cov --quiet
        log "Installing pre-commit hooks..."
        "$VENV_DIR/bin/pre-commit" install --quiet 2>/dev/null || warn "pre-commit install skipped"
    fi
}

verify_install() {
    log "Verifying installation..."
    "$VENV_DIR/bin/python" -c "import sys; print(f'  Python: {sys.version}')"
    log "Done. Activate with: source .venv/bin/activate"
}

main() {
    log "Bootstrapping project environment..."
    check_python
    create_venv
    install_deps
    verify_install
}

main "$@"
