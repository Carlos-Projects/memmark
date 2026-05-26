# Contributing to MemMark

Thank you for your interest in contributing to MemMark! This document provides guidelines and instructions for contributing.

## Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Carlos-Projects/memmark.git
   cd memmark
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -e ".[dev]"
   ```

## Code Style

- Follow PEP 8 conventions
- Use type hints on all functions and methods
- Maximum line length: 88 characters
- Use `ruff` for linting:
  ```bash
  ruff check src/ tests/
  ```

## Testing

- Write tests for all new functionality
- Minimum coverage: 80%
- Run tests with:
  ```bash
  python -m pytest tests/ -v
  ```

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes with appropriate tests
3. Ensure all tests pass and coverage meets the threshold
4. Run `ruff check` and fix any issues
5. Submit a pull request with a clear description of changes

## Commit Messages

Follow conventional commits:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Test additions or modifications
- `refactor:` Code refactoring
- `chore:` Maintenance tasks

## Architecture

MemMark follows a modular architecture:

```
src/memmark/
├── scanner.py          # Core scanning engine
├── cli.py              # Typer CLI interface
├── watermark/          # Memory watermarking
├── poisoning/          # Poisoning detection
├── provenance/         # Provenance tracking
├── integrity/          # Integrity verification
├── reporters/          # Output formatters
└── utils/              # Shared utilities
```

## Integration with Ecosystem

- Uses `mcp-taxonomy` for standardized finding classification
- Generates policies compatible with `MCPGuard`
- Reports consumable by `MCPscop`
- Complements `reverse-abliterate` (model integrity vs memory integrity)

## Questions?

Open an issue on GitHub or reach out via the project discussions.
