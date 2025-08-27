"""Script to monitor and maintain centralized logging."""
import os
import time
import logging
from pathlib import Path

class LogMonitor:
    def __init__(self, log_dir: str = "logs", main_log: str = "siem.log"):
        self.log_dir = Path(log_dir)
        self.main_log = self.log_dir / main_log
        self.known_logs = set()
        
    def setup(self):
        """Ensure log directory exists and main log file is created."""
        self.log_dir.mkdir(exist_ok=True)
        if not self.main_log.exists():
            self.main_log.touch()
        
        # Add all current log files to known logs
        self.known_logs.update(
            str(p) for p in self.log_dir.glob("*.log")
            if p.name != self.main_log.name
        )
    
    def check_logs(self):
        """Check for and clean up any non-main log files."""
        current_logs = set(
            str(p) for p in self.log_dir.glob("*.log")
            if p.name != self.main_log.name
        )
        
        # Find new log files that weren't there before
        new_logs = current_logs - self.known_logs
        
        for log_file in new_logs:
            try:
                # If the log file is empty, just remove it
                if os.path.getsize(log_file) == 0:
                    os.unlink(log_file)
                    print(f"Removed empty log file: {log_file}")
                else:
                    # If it has content, move it to the main log
                    with open(log_file, 'r') as f:
                        content = f.read()
                    with open(self.main_log, 'a') as f:
                        f.write(f"\n\n=== Merged from {Path(log_file).name} ===\n")
                        f.write(content)
                    os.unlink(log_file)
                    print(f"Merged and removed: {log_file}")
                
                self.known_logs.add(log_file)
            except Exception as e:
                print(f"Error processing {log_file}: {e}")

def main():
    """Run the log monitor."""
    monitor = LogMonitor()
    monitor.setup()
    
    print(f"Monitoring log directory: {monitor.log_dir}")
    print(f"Main log file: {monitor.main_log}")
    print("Press Ctrl+C to exit")
    
    try:
        while True:
            monitor.check_logs()
            time.sleep(5)  # Check every 5 seconds
    except KeyboardInterrupt:
        print("\nStopping log monitor...")

if __name__ == "__main__":
    main()
