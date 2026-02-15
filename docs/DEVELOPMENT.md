# Development Guidelines for AVA

## Project Structure

```
ava/
├── core/           # Core application logic
│   ├── engine.py   # Main processing engine
│   └── logging.py  # Logging configuration
├── cli/            # Command-line interface
│   └── main.py     # CLI commands
├── config/         # Configuration management
│   └── settings.py # Configuration classes
├── utils/          # Utility functions
│   ├── validators.py
│   ├── exceptions.py
│   ├── models.py
│   └── performance.py
```

## Adding New Features

1. **Create the feature module** in the appropriate subdirectory
2. **Write comprehensive tests** in `tests/test_*.py`
3. **Update imports** in package `__init__.py` files
4. **Document** the feature in this file
5. **Run tests**: `make test`
6. **Check quality**: `make check`

## Testing

- Use **pytest** for all tests
- Aim for **>80% code coverage**
- Write **unit tests** for each module
- Test **edge cases** and **error handling**

## Code Quality

- **Format**: Black (100 char line length)
- **Lint**: Flake8
- **Types**: MyPy
- **Imports**: isort

Run all checks:
```bash
make check
```

## Logging

Use the centralized logger:

```python
from ava.core.logging import logger

logger.info("Message")
logger.warning("Warning")
logger.error("Error")
```

## Performance

Use the performance decorator:

```python
from ava.utils.performance import measure_performance

@measure_performance
def my_function():
    pass
```

## Configuration

Get global configuration:

```python
from ava.config import get_config

config = get_config()
print(config.debug)
print(config.features)
```

## CLI Usage

```bash
ava add "Task name"
ava list
ava complete <task-id>
ava stats
```

## Contributing

1. Create a feature branch
2. Write code following guidelines
3. Run `make check` - all tests must pass
4. Update documentation
5. Commit with clear message
6. Create pull request

## Pre-commit Hooks

Install pre-commit hooks:

```bash
pre-commit install
```

This will automatically run checks before each commit.
