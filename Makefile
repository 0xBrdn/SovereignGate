.PHONY: help venv setup-platform migrate build-engine test-engine lint-engine run-platform dev check

CARGO := cargo
ENGINE_DIR := engine
PLATFORM_DIR := platform
VENV_DIR := $(PLATFORM_DIR)/.venv
PYTHON := $(VENV_DIR)/bin/python
PIP := $(VENV_DIR)/bin/pip

help:
	@echo "SovereignGate Monorepo Targets:"
	@echo "  make setup-platform   Create .venv, install dependencies, and copy .env"
	@echo "  make migrate          Generate and apply Django migrations"
	@echo "  make build-engine     Compile the Rust scanner engine in release mode"
	@echo "  make test-engine      Run Rust unit and integration tests"
	@echo "  make lint-engine      Run cargo fmt check and clippy"
	@echo "  make run-platform     Start Django development server"
	@echo "  make dev              Build Rust engine, apply migrations, and start Django server"
	@echo "  make check            Run full verification across engine and platform"

venv:
	@test -d $(VENV_DIR) || python3 -m venv $(VENV_DIR)

setup-platform: venv
	$(PIP) install --upgrade pip
	$(PIP) install -r $(PLATFORM_DIR)/requirements.txt
	@test -f $(PLATFORM_DIR)/.env || cp $(PLATFORM_DIR)/.env.example $(PLATFORM_DIR)/.env

migrate:
	cd $(PLATFORM_DIR) && ../$(PYTHON) manage.py makemigrations accounts compliance
	cd $(PLATFORM_DIR) && ../$(PYTHON) manage.py migrate

build-engine:
	cd $(ENGINE_DIR) && $(CARGO) build --release

test-engine:
	cd $(ENGINE_DIR) && $(CARGO) test --all-features

lint-engine:
	cd $(ENGINE_DIR) && $(CARGO) fmt --all -- --check && $(CARGO) clippy --all-targets -- -D warnings

run-platform:
	cd $(PLATFORM_DIR) && ../$(PYTHON) manage.py runserver 0.0.0.0:8000

dev: build-engine migrate run-platform

check: lint-engine test-engine
	cd $(PLATFORM_DIR) && ../$(PYTHON) manage.py test