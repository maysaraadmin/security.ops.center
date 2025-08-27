"""
Fix for Unicode logging in Windows console.
This script configures the console to properly handle Unicode characters.
"""

import sys
import io
import os

# Set the console output to UTF-8
if sys.platform == 'win32':
    # Set console output code page to UTF-8
    os.system('chcp 65001')
    
    # Reopen stdout and stderr with UTF-8 encoding
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, 
        encoding='utf-8', 
        errors='replace',
        line_buffering=True
    )
    
    sys.stderr = io.TextIOWrapper(
        sys.stderr.buffer, 
        encoding='utf-8', 
        errors='replace',
        line_buffering=True
    )

if __name__ == "__main__":
    print("✅ Console encoding has been configured to support Unicode characters.")
    print("🔧 You can now run your scripts with proper Unicode support.")
