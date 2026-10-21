# Contributing to R3X-BugBounty

We welcome contributions from the cybersecurity, open-source, and AI community!

## Development Setup

1. Fork the repository and clone it locally.
2. Run `./install.sh` or create a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   pip install -e ".[dev]"
   ```
3. Run the test suite:
   ```bash
   pytest tests/
   ```

## Pull Request Guidelines

- Ensure all new features have accompanying unit tests.
- Maintain non-destructive safety principles: never introduce weaponized exploit scripts or unvalidated shell execution.
- Respect linting, formatting, and type safety standards (Pydantic models, Rich outputs).
- Redact all sensitive information in examples and tests.
