"""
SIEM Tools - Command Line Utilities

This module provides command-line access to various SIEM utility tools.

Usage:
    python -m scripts tools cli
    python -m scripts tools edr
"""

import argparse
import importlib
import sys
import os
from pathlib import Path

def list_commands():
    """List all available tool commands."""
    commands = {}
    tools_dir = Path(__file__).parent
    
    for script in tools_dir.glob("*.py"):
        if script.stem != "__main__" and script.suffix == '.py':
            command_name = script.stem
            commands[command_name] = str(script)
    
    return commands

def main():
    parser = argparse.ArgumentParser(description='SIEM Tools - Command Line Utilities')
    subparsers = parser.add_subparsers(dest='tool', help='Available tools')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List all available tools')
    
    # Add commands from tool files
    tools = list_commands()
    for tool in tools:
        subparsers.add_parser(tool, help=f'Run {tool} tool')
    
    args = parser.parse_args()
    
    if args.tool == 'list' or not args.tool:
        print("Available tools:")
        for tool in sorted(tools):
            print(f"  {tool}")
        return 0
    
    if args.tool not in tools:
        print(f"Error: Unknown tool '{args.tool}'", file=sys.stderr)
        print("Available tools:", ', '.join(tools.keys()))
        return 1
    
    # Import and run the tool module
    tool_path = tools[args.tool]
    try:
        # Add the scripts directory to the path
        scripts_dir = str(Path(__file__).parent.parent)
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)
            
        # Import the module
        module_name = f"scripts.tools.{args.tool}"
        module = importlib.import_module(module_name)
        
        # Run the main function if it exists
        if hasattr(module, 'main'):
            return module.main()
        else:
            print(f"Error: {args.tool}.py does not have a main() function", file=sys.stderr)
            return 1
            
    except Exception as e:
        print(f"Error running {args.tool}: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())
