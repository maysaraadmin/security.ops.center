"""
File Integrity Monitoring (FIM) Manager - Coordinates FIM components and provides a high-level API.
"""
import os
import time
import logging
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Callable, Any, Set
from queue import Queue
import json

from .integrity_checker import IntegrityChecker, FileIntegrityRecord
from .monitor import FIMMonitor, FIMEvent

class FIMManager:
    """Manages File Integrity Monitoring operations."""
    
    def __init__(self, alert_callback: Callable[[Dict], None] = None):
        """
        Initialize the FIM manager.
        
        Args:
            alert_callback: Optional callback function for alerts
        """
        self.integrity_checker = IntegrityChecker()
        self.monitor = FIMMonitor()
        self.alert_callback = alert_callback
        self.logger = logging.getLogger(__name__)
        self.running = False
        self.verification_interval = 3600  # 1 hour in seconds
        self.verification_thread = None
        self.baseline_file = os.path.join(
            os.path.expanduser("~"), 
            ".siem_fim_baselines.json"
        )
        
        # Load existing baselines if they exist
        self._load_baselines()
    
    def start(self) -> bool:
        """
        Start the FIM system.
        
        Returns:
            True if started successfully, False otherwise
        """
        if self.running:
            self.logger.warning("FIM system is already running")
            return True
        
        try:
            # Start the monitor
            self.monitor = FIMMonitor(self.monitor.baselines)
            self.monitor.start()
            
            # Start the periodic verification thread
            self.running = True
            self.verification_thread = threading.Thread(
                target=self._periodic_verification,
                name="FIMVerification",
                daemon=True
            )
            self.verification_thread.start()
            
            self.logger.info("FIM system started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start FIM system: {e}", exc_info=True)
            self.running = False
            return False
    
    def stop(self) -> None:
        """Stop the FIM system."""
        if not self.running:
            return
            
        self.logger.info("Stopping FIM system...")
        self.running = False
        
        # Stop the monitor
        self.monitor.stop()
        
        # Wait for verification thread to finish
        if self.verification_thread and self.verification_thread.is_alive():
            self.verification_thread.join(timeout=5.0)
            if self.verification_thread.is_alive():
                self.logger.warning("Verification thread did not stop gracefully")
        
        # Save baselines
        self._save_baselines()
        
        self.logger.info("FIM system stopped")
    
    def _periodic_verification(self) -> None:
        """Run periodic verification of all monitored files."""
        self.logger.info("Starting periodic FIM verification")
        
        while self.running:
            try:
                # Wait for the verification interval
                time.sleep(self.verification_interval)
                
                if not self.running:
                    break
                    
                self.logger.debug("Running periodic FIM verification...")
                results = self.verify_all()
                
                # Log results
                violations = [r for r in results if not r[0]]
                if violations:
                    self.logger.warning(
                        f"Found {len(violations)} integrity violations in periodic check"
                    )
                
            except Exception as e:
                self.logger.error(f"Error in periodic verification: {e}", exc_info=True)
    
    def add_directory(self, directory: str, 
                     file_patterns: List[str] = None,
                     exclude_dirs: List[str] = None,
                     recursive: bool = True) -> int:
        """
        Add a directory to monitor.
        
        Args:
            directory: Directory path to monitor
            file_patterns: List of file patterns to include (e.g., ['*.exe', '*.dll'])
            exclude_dirs: List of directory names to exclude
            recursive: Whether to scan subdirectories
            
        Returns:
            Number of files added to monitoring
        """
        try:
            # Scan the directory for files
            records = self.integrity_checker.scan_directory(
                directory=directory,
                file_patterns=file_patterns,
                exclude_dirs=exclude_dirs
            )
            
            # Add to monitor
            for record in records:
                self.monitor.add_baseline(record)
            
            # Save baselines
            self._save_baselines()
            
            self.logger.info(f"Added {len(records)} files from {directory} to monitoring")
            return len(records)
            
        except Exception as e:
            self.logger.error(f"Failed to add directory {directory}: {e}", exc_info=True)
            return 0
    
    def remove_directory(self, directory: str) -> int:
        """
        Remove a directory from monitoring.
        
        Args:
            directory: Directory path to remove from monitoring
            
        Returns:
            Number of files removed from monitoring
        """
        try:
            directory = str(Path(directory).resolve())
            removed = 0
            
            # Find all files under this directory
            to_remove = []
            for path in list(self.monitor.baselines.keys()):
                if path.startswith(directory):
                    to_remove.append(path)
            
            # Remove them
            for path in to_remove:
                if self.monitor.remove_baseline(path):
                    removed += 1
            
            # Save baselines
            if removed > 0:
                self._save_baselines()
            
            self.logger.info(f"Removed {removed} files from monitoring under {directory}")
            return removed
            
        except Exception as e:
            self.logger.error(f"Failed to remove directory {directory}: {e}", exc_info=True)
            return 0
    
    def add_file(self, file_path: str, metadata: Dict = None) -> bool:
        """
        Add a file to monitor.
        
        Args:
            file_path: Path to the file to monitor
            metadata: Optional metadata to include with the file
            
        Returns:
            True if added successfully, False otherwise
        """
        try:
            record = self.integrity_checker.create_baseline(file_path, metadata)
            if not record:
                return False
                
            self.monitor.add_baseline(record)
            self._save_baselines()
            
            self.logger.info(f"Added file to monitoring: {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add file {file_path}: {e}", exc_info=True)
            return False
    
    def remove_file(self, file_path: str) -> bool:
        """
        Remove a file from monitoring.
        
        Args:
            file_path: Path to the file to remove from monitoring
            
        Returns:
            True if removed successfully, False otherwise
        """
        try:
            file_path = str(Path(file_path).resolve())
            if self.monitor.remove_baseline(file_path):
                self._save_baselines()
                self.logger.info(f"Removed file from monitoring: {file_path}")
                return True
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to remove file {file_path}: {e}", exc_info=True)
            return False
    
    def verify_all(self) -> List[Tuple[bool, str, Dict]]:
        """
        Verify all monitored files.
        
        Returns:
            List of (is_ok, file_path, result_dict) tuples
        """
        return self.monitor.verify_all()
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get the current status of the FIM system.
        
        Returns:
            Dictionary with status information
        """
        return {
            'running': self.running,
            'monitored_files': len(self.monitor.baselines),
            'verification_interval': self.verification_interval,
            'baseline_file': self.baseline_file
        }
    
    def get_monitored_files(self) -> List[Dict]:
        """
        Get a list of all monitored files.
        
        Returns:
            List of dictionaries with file information
        """
        return [
            {
                'path': record.file_path,
                'size': record.size,
                'created': record.created,
                'modified': record.modified,
                'last_checked': record.last_checked,
                'metadata': record.metadata
            }
            for record in self.monitor.baselines.values()
        ]
    
    def _save_baselines(self) -> bool:
        """Save baselines to a file."""
        try:
            with open(self.baseline_file, 'w') as f:
                data = {
                    'version': '1.0',
                    'timestamp': time.time(),
                    'baselines': [
                        record.to_dict()
                        for record in self.monitor.baselines.values()
                    ]
                }
                json.dump(data, f, indent=2)
            
            self.logger.debug(f"Saved {len(self.monitor.baselines)} baselines to {self.baseline_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save baselines to {self.baseline_file}: {e}")
            return False
    
    def _load_baselines(self) -> bool:
        """Load baselines from a file."""
        if not os.path.exists(self.baseline_file):
            self.logger.debug(f"No baseline file found at {self.baseline_file}")
            return False
            
        try:
            with open(self.baseline_file, 'r') as f:
                data = json.load(f)
                
            # Clear existing baselines
            self.monitor.baselines.clear()
            
            # Load baselines
            for item in data.get('baselines', []):
                try:
                    record = FileIntegrityRecord(
                        file_path=item['file_path'],
                        size=item['size'],
                        created=item['created'],
                        modified=item['modified'],
                        hash_md5=item['hash_md5'],
                        hash_sha1=item['hash_sha1'],
                        hash_sha256=item['hash_sha256'],
                        last_checked=item.get('last_checked', 0),
                        metadata=item.get('metadata', {})
                    )
                    self.monitor.baselines[record.file_path] = record
                    
                except Exception as e:
                    self.logger.error(f"Failed to load baseline for {item.get('file_path', 'unknown')}: {e}")
            
            self.logger.info(f"Loaded {len(self.monitor.baselines)} baselines from {self.baseline_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load baselines from {self.baseline_file}: {e}")
            return False

# Example usage
if __name__ == "__main__":
    import logging
    import time
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create a test directory
    test_dir = os.path.join(os.path.expanduser("~"), "fim_test")
    os.makedirs(test_dir, exist_ok=True)
    
    # Create some test files
    test_files = [
        os.path.join(test_dir, "test1.txt"),
        os.path.join(test_dir, "test2.txt")
    ]
    
    for file_path in test_files:
        with open(file_path, 'w') as f:
            f.write(f"Test content for {os.path.basename(file_path)}")
    
    print(f"Created test files in {test_dir}")
    
    try:
        # Initialize FIM manager
        fim = FIMManager()
        
        # Add test directory to monitoring
        print(f"\nAdding directory to monitoring: {test_dir}")
        count = fim.add_directory(test_dir)
        print(f"Added {count} files to monitoring")
        
        # Start monitoring
        print("\nStarting FIM monitoring...")
        fim.start()
        
        # Let it run for a bit
        print("\nFIM is running. Try modifying the test files in:")
        print(f"  {test_dir}")
        print("\nPress Ctrl+C to stop...")
        
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping FIM...")
        
    finally:
        # Clean up
        if 'fim' in locals():
            fim.stop()
        
        # Remove test files
        for file_path in test_files:
            try:
                os.remove(file_path)
            except:
                pass
        
        try:
            os.rmdir(test_dir)
        except:
            pass
