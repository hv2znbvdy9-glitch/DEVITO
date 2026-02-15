# Getting Started

## Installation

### From source

```bash
# Clone the repository
git clone https://github.com/hv2znbvdy9-glitch/AVA.git
cd AVA

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"
```

### Using Docker

```bash
docker-compose build
docker-compose run app
```

## Running Tests

```bash
pytest tests/
```

## Code Quality

### Format Code

```bash
black ava tests
isort ava tests
```

### Lint Code

```bash
flake8 ava tests
mypy ava
```

### Run All Checks

```bash
black --check ava tests
isort --check-only ava tests
flake8 ava tests
mypy ava
pytest tests/
```
