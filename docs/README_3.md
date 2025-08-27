# SIEM Scripts

This directory contains various utility scripts for managing and maintaining the SIEM system.

## Available Commands

### Database Management

Run database-related commands using:

```bash
python -m scripts database <command>
```

Available commands:
- `check_db`: Check database integrity
- `check_db_schema`: Verify database schema
- `create_database`: Initialize a new database
- `fix_database_schema`: Fix database schema issues
- `init_db`: Initialize database tables
- `reset_database`: Reset the database to initial state
- `verify_db`: Verify database structure
- `verify_schema`: Verify database schema

### Tools

Run utility tools using:

```bash
python -m scripts tools <tool>
```

Available tools:
- `cli`: Main SIEM CLI interface
- `edr_cli`: EDR (Endpoint Detection and Response) CLI tool

## Development

To add a new script:

1. Create a new Python file in the appropriate directory (`database/` or `tools/`)
2. Implement a `main()` function that will be called when the script is executed
3. The script will be automatically discovered and made available through the command-line interface

## Best Practices

- Use the `logging` module for output instead of `print()`
- Include proper error handling and meaningful error messages
- Add docstrings to document the purpose and usage of each script
- Keep scripts focused on a single responsibility
