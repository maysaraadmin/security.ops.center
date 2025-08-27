"""
SIEM Database Management Scripts

This module provides command-line access to various database management scripts.

Usage:
    python -m scripts database check
    python -m scripts database verify
    python -m scripts database fix
"""

import argparse
import importlib
import sys
import os
from pathlib import Path

def list_commands():
    """List all available database commands."""
    commands = {}
    db_scripts_dir = Path(__file__).parent
    
    for script in db_scripts_dir.glob("*.py"):
        if script.stem != "__main__" and script.suffix == '.py':
            command_name = script.stem
            commands[command_name] = str(script)
    
    return commands

def main():
    parser = argparse.ArgumentParser(description='SIEM Database Management')
    subparsers = parser.add_subparsers(dest='subcommand', help='Available commands')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List all available database commands')
    
    # Add commands from script files
    commands = list_commands()
    for cmd in commands:
        subparsers.add_parser(cmd, help=f'Run {cmd}')
    
    args = parser.parse_args()
    
    if args.subcommand == 'list' or not args.subcommand:
        print("Available database commands:")
        for cmd in sorted(commands):
            print(f"  {cmd}")
        return 0
    
    if args.subcommand not in commands:
        print(f"Error: Unknown database command '{args.subcommand}'", file=sys.stderr)
        print("Available commands:", ', '.join(commands.keys()))
        return 1
    
    # Import and run the command module
    script_path = commands[args.subcommand]
    try:
        # Add the scripts directory to the path
        scripts_dir = str(Path(__file__).parent.parent)
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)
            
        # Import the module
        module_name = f"scripts.database.{args.subcommand}"
        module = importlib.import_module(module_name)
        
        # Run the main function if it exists
        if hasattr(module, 'main'):
            return module.main()
        else:
            print(f"Error: {args.subcommand}.py does not have a main() function", file=sys.stderr)
            return 1
            
    except Exception as e:
        print(f"Error running {args.subcommand}: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())
