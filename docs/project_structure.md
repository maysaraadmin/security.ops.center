# Project Structure

This document outlines the standard directory structure for the Security Operations Center project.

## Directory Structure

```
.
├── config/               # Configuration files
│   ├── development/      # Development environment configs
│   ├── production/       # Production environment configs
│   └── testing/          # Testing environment configs
├── data/                 # Data storage
│   ├── backups/          # Database backups
│   └── logs/             # Application logs
├── docs/                 # Documentation
├── scripts/              # Utility and management scripts
├── src/                  # Source code
│   ├── api/              # API endpoints
│   ├── core/             # Core functionality
│   ├── models/           # Data models
│   ├── services/         # Business logic
│   └── utils/            # Utility functions
├── tests/                # Test files
│   ├── unit/             # Unit tests
│   ├── integration/      # Integration tests
│   └── e2e/              # End-to-end tests
└── web/                  # Web interface
    ├── static/           # Static files (CSS, JS, images)
    └── templates/        # HTML templates
```

## File Naming Conventions

- Python files: `snake_case.py`
- Configuration files: `lowercase-with-dashes.yaml`
- Test files: `test_*.py`
- Log files: `service-name_YYYYMMDD.log`

## Maintenance

1. **Log Rotation**: Set up log rotation to prevent log files from growing too large.
2. **Backups**: Regularly back up the `data/` directory.
3. **Dependencies**: Keep `requirements.txt` and `pyproject.toml` up to date.
4. **Documentation**: Update documentation when making significant changes.

## Cleanup Scripts

- `organize.ps1`: Organizes Python scripts and log files
- `cleanup.ps1`: Cleans up temporary and cache files
