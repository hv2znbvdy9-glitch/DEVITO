# Makefile for AVA project

.PHONY: help install install-dev test lint format check clean docker-build docker-dev

help:
	@echo "AVA Project - Available targets:"
	@echo "  install       - Install the package"
	@echo "  install-dev   - Install with development dependencies"
	@echo "  test          - Run tests"
	@echo "  lint          - Run linters (flake8, mypy)"
	@echo "  format        - Format code (black, isort)"
	@echo "  check         - Run all checks (lint + format + test)"
	@echo "  clean         - Clean up build artifacts"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-dev    - Start development container"

install:
	pip install .

install-dev:
	pip install -e ".[dev]"

test:
	pytest tests/ --cov=ava

lint:
	flake8 ava tests
	mypy ava

format:
	black ava tests
	isort ava tests

check: format lint test

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	find . -type d -name .mypy_cache -exec rm -rf {} +
	find . -type d -name htmlcov -exec rm -rf {} +
	find . -type f -name .coverage -delete
	find . -type f -name "*.egg-info" -delete
	rm -rf build/ dist/

docker-build:
	docker build -t ava:latest .

docker-dev:
	docker-compose up
