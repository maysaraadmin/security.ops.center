"""
SIEM Scripts - Command Line Interface

This module provides command-line access to various SIEM utility scripts.

Usage:
    python -m scripts database check_db
    python -m scripts database verify_schema
    python -m scripts tools cli
"""

import argparse
import importlib
import sys
import os
from pathlib import Path

def list_commands():
    """List all available commands."""
    commands = {}
    scripts_dir = Path(__file__).parent
    
    for item in scripts_dir.iterdir():
        if item.is_dir() and (item / "__main__.py").exists():
            rel_path = item.relative_to(scripts_dir) / "__main__.py"
            commands[item.name] = str(rel_path)
    
    return commands

def main():
    parser = argparse.ArgumentParser(description='SIEM Scripts - Command Line Interface')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List all available commands')
    
    # Add commands from subdirectories
    commands = list_commands()
    for cmd, module_path in commands.items():
        cmd_parser = subparsers.add_parser(cmd, help=f'Run {cmd} commands')
        cmd_parser.add_argument('subcommand', nargs='?', help=f'{cmd} subcommand')
    
    args = parser.parse_args()
    
    if args.command == 'list' or not args.command:
        print("Available commands:")
        for cmd in sorted(commands):
            print(f"  {cmd}")
        return 0
    
    if args.command not in commands:
        print(f"Error: Unknown command '{args.command}'", file=sys.stderr)
        print("Available commands:", ', '.join(commands.keys()))
        return 1
    
    # Import and run the command module
    module_name = f"scripts.{args.command}.__main__"
    try:
        module = importlib.import_module(module_name)
        sys.argv = sys.argv[2:]  # Remove the script name and command
        return module.main()
    except ImportError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
