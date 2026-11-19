.PHONY: help venv setup-platform makemigrations migrate build-engine test-engine lint-engine test-platform run-platform superuser dev check clean

CARGO := cargo
ENGINE_DIR := engine
PLATFORM_DIR := platform
VENV_DIR := $(PLATFORM_DIR)/.venv
PYTHON := $(VENV_DIR)/bin/python
PIP := $(VENV_DIR)/bin/pip

help:
	@echo "SovereignGate monorepo targets:"
	@echo "  make setup-platform   Create .venv, install dependencies, copy .env"
	@echo "  make migrate          Apply database migrations"
	@echo "  make makemigrations   Generate new migrations after a model change"
	@echo "  make superuser        Create the first admin / DPO account"
	@echo "  make build-engine     Compile the Rust scanner (release)"
	@echo "  make test-engine      Run Rust unit tests"
	@echo "  make lint-engine      cargo fmt --check and clippy"
	@echo "  make test-platform    Run the Django test suite"
	@echo "  make run-platform     Start the Django development server"
	@echo "  make dev              Build engine, migrate, start the platform"
	@echo "  make check            Lint + test everything"

venv:
	@test -d $(VENV_DIR) || python3 -m venv $(VENV_DIR)

setup-platform: venv
	$(PIP) install --upgrade pip
	$(PIP) install -r $(PLATFORM_DIR)/requirements.txt
	@test -f $(PLATFORM_DIR)/.env || cp $(PLATFORM_DIR)/.env.example $(PLATFORM_DIR)/.env

makemigrations:
	cd $(PLATFORM_DIR) && ../$(PYTHON) manage.py makemigrations accounts compliance

migrate:
	cd $(PLATFORM_DIR) && ../$(PYTHON) manage.py migrate

superuser:
	cd $(PLATFORM_DIR) && ../$(PYTHON) manage.py createsuperuser

build-engine:
	cd $(ENGINE_DIR) && $(CARGO) build --release --locked

test-engine:
	cd $(ENGINE_DIR) && $(CARGO) test --all-features --locked

lint-engine:
	cd $(ENGINE_DIR) && $(CARGO) fmt --all -- --check && $(CARGO) clippy --all-targets -- -D warnings

test-platform:
	cd $(PLATFORM_DIR) && ../$(PYTHON) manage.py test

run-platform:
	cd $(PLATFORM_DIR) && DEBUG=True ../$(PYTHON) manage.py runserver 127.0.0.1:8000

dev: build-engine migrate run-platform

check: lint-engine test-engine test-platform
