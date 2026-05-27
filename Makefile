.PHONY: install dev install-docs test lint typecheck coverage clean build serve-docs precommit

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

install-docs:
	pip install -e ".[docs]"

test:
	python -m pytest tests/ -v

lint:
	ruff check src/ tests/

typecheck:
	mypy src/ --ignore-missing-imports

coverage:
	python -m pytest tests/ --cov=memmark --cov-report=term-missing --cov-report=html
	@echo "Coverage report: htmlcov/index.html"

build:
	python -m build

serve-docs:
	python -m mkdocs serve

precommit:
	pre-commit install
	pre-commit run --all-files

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .coverage coverage.xml htmlcov site/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

all: install dev install-docs lint typecheck test coverage
