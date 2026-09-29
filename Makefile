# Makefile

.PHONY: all format reformat-ruff check fix-ruff fix vulture complexity xenon bandit pyright typecheck test test-unit test-cov test-integration test-all validate mutation clean build help

# Default target: runs validation and unit tests
all: validate test-unit

# Format the code using ruff
format:
	uv run ruff format --check --diff .

reformat-ruff:
	uv run ruff format .

# Check the code using ruff
check:
	uv run ruff check .

fix-ruff:
	uv run ruff check . --fix

fix: reformat-ruff fix-ruff
	@echo "Updated code."

vulture:
	uv run vulture . --exclude .venv,migrations,tests,mutants --make-whitelist

complexity:
	uv run radon cc src -a -nc

xenon:
	uv run xenon -b D -m D -a C src

bandit:
	uv run bandit -c pyproject.toml -r src

typecheck:
	uv run pyright

pyright: typecheck

test:
	uv run pytest

test-unit:
	uv run pytest tests/unit/ --cov-fail-under=85

test-cov:
	uv run pytest tests/unit/ --cov-fail-under=85

test-integration:
	uv run pytest -m integration --timeout=300

test-all:
	uv run pytest --tb=short --timeout=300

# Mutation testing (mutates src/, runs the unit suite per mutant)
mutation:
	uv run mutmut run
	uv run mutmut results

# Validate the code (format + check)
validate: format check complexity xenon bandit pyright vulture
	@echo "Validation passed. Your code is ready to push."

clean:
	rm -rf build dist src/*.egg-info *.egg-info

build: clean
	uv build

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
	@echo "  test-unit     - Run unit tests only (with coverage)"
	@echo "  test-integration - Run integration tests only"
	@echo "  test-all      - Run all tests with short traceback"
	@echo "  mutation      - Run mutation testing (mutmut)"
	@echo "  validate      - Run all validation checks"
	@echo "  clean         - Remove build artifacts"
	@echo "  build         - Build the package"
	@echo "  help          - Show this help message"
