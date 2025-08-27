"""Script to clean up log files and ensure single log file configuration."""
import os
import shutil
import sys
from pathlib import Path

def clean_logs():
    """Remove all log files and ensure only siem.log exists."""
    log_dir = Path("logs")
    
    if not log_dir.exists():
        print("Logs directory does not exist. Nothing to clean up.")
        return
    
    # Create a backup of the current siem.log if it exists
    siem_log = log_dir / "siem.log"
    if siem_log.exists():
        backup_path = log_dir / "siem.log.bak"
        try:
            shutil.copy2(siem_log, backup_path)
            print(f"Created backup of siem.log at {backup_path}")
        except Exception as e:
            print(f"Warning: Could not create backup of siem.log: {e}")
    
    # Remove all .log files
    removed_count = 0
    for log_file in log_dir.glob("*.log"):
        try:
            log_file.unlink()
            print(f"Removed: {log_file}")
            removed_count += 1
        except Exception as e:
            print(f"Error removing {log_file}: {e}")
    
    # Create a new empty siem.log
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        with open(siem_log, 'w') as f:
            f.write("")
        print(f"Created new empty {siem_log}")
    except Exception as e:
        print(f"Error creating new siem.log: {e}")
        sys.exit(1)
    
    print(f"\nCleaned up {removed_count} log files. Only {siem_log} remains.")

if __name__ == "__main__":
    print("=== SIEM Log Cleanup Tool ===")
    clean_logs()
