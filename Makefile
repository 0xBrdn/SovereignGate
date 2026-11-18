.PHONY: help setup-engine setup-platform build-engine test-engine lint-engine run-platform test-platform check

CARGO := cargo
PYTHON := python3
ENGINE_DIR := engine
PLATFORM_DIR := platform

help:
	@echo "SovereignGate Monorepo Targets:"
	@echo "  make setup-platform   Install Python dependencies and run initial migrations"
	@echo "  make build-engine     Compile the Rust scanner engine in release mode"
	@echo "  make test-engine      Run Rust unit and integration tests"
	@echo "  make lint-engine      Run cargo fmt check and clippy"
	@echo "  make run-platform     Start Django development server"
	@echo "  make test-platform    Run Django test suite"
	@echo "  make check            Run full verification across engine and platform"

setup-platform:
	cd $(PLATFORM_DIR) && $(PYTHON) -m pip install --upgrade pip && pip install -r requirements.txt
	cd $(PLATFORM_DIR) && $(PYTHON) manage.py migrate

build-engine:
	cd $(ENGINE_DIR) && $(CARGO) build --release

test-engine:
	cd $(ENGINE_DIR) && $(CARGO) test --all-features

lint-engine:
	cd $(ENGINE_DIR) && $(CARGO) fmt --all -- --check && $(CARGO) clippy --all-targets -- -D warnings

run-platform:
	cd $(PLATFORM_DIR) && $(PYTHON) manage.py runserver 0.0.0.0:8000

test-platform:
	cd $(PLATFORM_DIR) && $(PYTHON) manage.py test

check: lint-engine test-engine test-platform