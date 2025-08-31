"""
DLP Main Entry Point

This module provides the command-line entry point for the DLP application.
"""

def main():
    """Run the DLP GUI application."""
    from .dlp_gui import main as gui_main
    gui_main()

if __name__ == "__main__":
    main()
