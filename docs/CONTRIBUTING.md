# Contributing to SIEM System

Thank you for your interest in contributing to the SIEM System! This document outlines the process for contributing to the project.

## Getting Started

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/yourusername/siem.git`
3. **Create a branch** for your feature: `git checkout -b feature/your-feature`
4. **Commit** your changes: `git commit -m 'Add some feature'`
5. **Push** to the branch: `git push origin feature/your-feature`
6. Open a **Pull Request**

## Development Setup

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: .\venv\Scripts\activate
   ```

2. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

3. Install pre-commit hooks:
   ```bash
   pre-commit install
   ```

## Code Style

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- Use type hints for all new code
- Keep lines under 88 characters
- Use double quotes for strings
- Use absolute imports

## Testing

Run tests with:
```bash
pytest
```

Run with coverage:
```bash
pytest --cov=siem
```

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Types:
- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation only changes
- `style`: Changes that do not affect the meaning of the code
- `refactor`: A code change that neither fixes a bug nor adds a feature
- `perf`: A code change that improves performance
- `test`: Adding missing tests or correcting existing tests
- `chore`: Changes to the build process or auxiliary tools

## Pull Requests

1. Keep PRs focused on a single feature or bug fix
2. Update documentation as needed
3. Add tests for new features
4. Ensure all tests pass
5. Update the CHANGELOG.md

## Reporting Issues

When reporting issues, please include:
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Environment details (Python version, OS, etc.)
- Any relevant error messages

## Code of Conduct

Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.
