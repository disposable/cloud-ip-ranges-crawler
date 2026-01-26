# Makefile

.PHONY: all format check validate test test-unit test-integration test-all help

# Default target: runs format and check
all: validate test-unit

# Format the code using ruff
format:
	ruff format --check --diff .

reformat-ruff:
	ruff format .

# Check the code using ruff
check:
	ruff check .

fix-ruff:
	ruff check . --fix

fix: reformat-ruff fix-ruff
	@echo "Updated code."

vulture:
	vulture . --exclude .venv,migrations,tests --make-whitelist

complexity:
	radon cc . -a -nc

xenon:
	xenon -b D -m B -a B .

bandit:
	bandit -c pyproject.toml -r .

pyright:
	pyright

test:
	pytest

test-unit:
	pytest tests/unit/ --cov-fail-under=85

test-integration:
	pytest -m integration

test-all:
	pytest --tb=short

# Validate the code (format + check)
validate: format check complexity bandit pyright vulture
	@echo "Validation passed. Your code is ready to push."

# Help target
help:
	@echo "Available targets:"
	@echo "  all           - Run validation and unit tests (default)"
	@echo "  format        - Check code formatting with ruff"
	@echo "  reformat-ruff - Format code with ruff"
	@echo "  check         - Run ruff linting"
	@echo "  fix-ruff      - Auto-fix ruff issues"
	@echo "  fix           - Run reformat-ruff and fix-ruff"
	@echo "  vulture       - Run dead code detection"
	@echo "  complexity    - Run complexity analysis"
	@echo "  xenon         - Run xenon complexity check"
	@echo "  bandit        - Run security analysis"
	@echo "  pyright       - Run type checking"
	@echo "  test          - Run all tests"
	@echo "  test-unit     - Run unit tests only"
	@echo "  test-integration - Run integration tests only"
	@echo "  test-all      - Run all tests with short traceback"
	@echo "  validate      - Run all validation checks"
	@echo "  help          - Show this help message"