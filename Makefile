# Makefile for AVA project

.PHONY: help install install-dev test lint format check clean docker-build docker-dev proto-compile grpc-certs

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
	@echo "  proto-compile - Compile Protocol Buffer definitions"
	@echo "  grpc-certs    - Generate self-signed TLS certificates for gRPC"

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

proto-compile:
	@echo "Compiling Protocol Buffer definitions..."
	python -m grpc_tools.protoc \
		--proto_path=ava/api/proto \
		--python_out=ava/api/proto \
		--grpc_python_out=ava/api/proto \
		ava/api/proto/*.proto
	@echo "✅ Proto files compiled successfully"

grpc-certs:
	@echo "Generating TLS/mTLS certificates for gRPC..."
	./scripts/generate_grpc_certs.sh
	@echo "✅ Certificates generated in ./certs/"
