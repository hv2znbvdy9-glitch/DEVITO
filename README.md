# AVA

A Python project with professional setup and configuration.

## Features

- 🐍 Python 3.8+ support
- 📦 Modern packaging with `pyproject.toml`
- 🧪 Testing with pytest and coverage
- 🎨 Code formatting with Black
- ✅ Type checking with mypy
- 📝 Linting with flake8
- 🐳 Docker support with docker-compose
- 🚀 GitHub Actions CI/CD
- 📚 Documentation structure

## Quick Start

### Installation

```bash
# Clone and install
git clone https://github.com/hv2znbvdy9-glitch/AVA.git
cd AVA
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest tests/
```

### Code Quality

```bash
# Format code
make format

# Run linters
make lint

# Run all checks
make check
```

### Docker

```bash
# Build development image
docker-compose build

# Start development container
docker-compose run app
```

## Project Structure

```
AVA/
├── ava/                          # Main package
│   ├── __init__.py
│   └── __main__.py
├── tests/                        # Test suite
│   ├── conftest.py
│   └── test_ava.py
├── docs/                         # Documentation
│   ├── README.md
│   ├── getting-started.md
│   └── api.md
├── examples/                     # Example scripts
│   └── basic.py
├── .github/workflows/            # GitHub Actions
│   ├── tests.yml
│   └── code-quality.yml
├── pyproject.toml                # Project configuration
├── Makefile                      # Make commands
├── Dockerfile                    # Production image
├── Dockerfile.dev                # Development image
├── docker-compose.yml            # Docker compose
├── tox.ini                       # Tox testing
├── .flake8                       # Flake8 config
└── requirements.txt              # Dependencies
```

## Available Commands

```bash
make help              # Show all available commands
make install           # Install package
make install-dev       # Install with dev dependencies
make test              # Run tests with coverage
make lint              # Run linters
make format            # Format code automatically
make check             # Run all checks
make clean             # Clean build artifacts
make docker-build      # Build production Docker image
make docker-dev        # Start dev container
```

## Development

See [Getting Started Guide](docs/getting-started.md) for detailed setup instructions.

## Contributing

Contributions are welcome! Please ensure all tests pass and code is properly formatted.

## License

MIT

## Author

Developer
