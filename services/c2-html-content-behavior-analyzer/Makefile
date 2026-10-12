PYTHON ?= python
PORT ?= 8002

.PHONY: install install-dev test lint format run-api

install:
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install --no-deps -e .

install-dev: install
	$(PYTHON) -m pip install -r requirements-dev.txt

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check src tests scripts
	$(PYTHON) -m black --check src tests scripts

format:
	$(PYTHON) -m ruff check --fix src tests scripts
	$(PYTHON) -m black src tests scripts

run-api:
	$(PYTHON) -m uvicorn c2_analyzer.api.main:app --reload --port $(PORT)
