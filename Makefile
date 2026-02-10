PYTHON ?= python3
VENV_PYTHON := .venv/bin/python
ifneq (,$(wildcard $(VENV_PYTHON)))
PYTHON := $(VENV_PYTHON)
endif

.PHONY: setup dev test lint typecheck security build check release

setup:
	$(PYTHON) -m venv .venv
	. .venv/bin/activate && $(PYTHON) -m pip install --upgrade pip
	. .venv/bin/activate && $(PYTHON) -m pip install -e .[dev]

dev:
	@echo "Run 'csp-doctor --help' after activating your venv."

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check src tests

typecheck:
	$(PYTHON) -m mypy src

security:
	$(PYTHON) -m bandit -q -r src
	$(PYTHON) -m pip_audit --cache-dir .pip-audit-cache --progress-spinner off

build:
	$(PYTHON) -m build

check: lint typecheck test build

release: check
	@echo "Tag a release and publish artifacts per docs/RELEASE.md"
