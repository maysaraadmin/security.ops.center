# Project Structure Documentation

This document provides a detailed overview of the SIEM project's directory structure and organization.

## Overview

```
siem/
├── src/                    # Source code
│   ├── common/             # Shared utilities and libraries
│   ├── core/               # Core framework components
│   └── services/           # Security services
├── tests/                  # Test files
│   ├── unit/               # Unit tests
│   └── integration/        # Integration tests
├── scripts/                # Utility scripts
│   ├── setup/              # Setup and installation
│   ├── deployment/         # Deployment scripts
│   ├── maintenance/        # Maintenance tasks
│   ├── development/        # Development helpers
│   ├── database/           # Database management
│   └── monitoring/         # Monitoring and metrics
├── config/                 # Configuration files
├── docs/                   # Documentation
└── .github/                # GitHub configurations
```

## Source Code (`src/`)

### Common Utilities (`src/common/`)
- `config/`: Configuration management and constants
- `logging/`: Logging utilities and formatters
- `security/`: Security-related functions and utilities
- `utils/`: General utility functions

### Core Framework (`src/core/`)
- `base/`: Base classes and interfaces
- `events/`: Event handling and processing
- `services/`: Core service implementations

### Services (`src/services/`)

Each service follows a consistent structure:
- `service_name/`
  - `core/`: Main service implementation
  - `models/`: Data models and schemas
  - `rules/`: Detection and processing rules
  - `utils/`: Service-specific utilities

## Testing (`tests/`)

- `unit/`: Unit tests
  - `common/`: Tests for common utilities
  - `core/`: Tests for core components
  - `services/`: Tests for individual services
- `integration/`: Integration tests
- `e2e/`: End-to-end tests

## Scripts (`scripts/`)

- `setup/`: Installation and environment setup
- `deployment/`: Deployment and release management
- `maintenance/`: Maintenance and cleanup tasks
- `development/`: Development helper scripts
- `database/`: Database management scripts
- `monitoring/`: Monitoring and metrics collection

## Configuration (`config/`)

- Service configurations
- Environment-specific settings
- Default configurations

## Documentation (`docs/`)

- Project documentation
- API references
- Development guides
- Deployment guides
