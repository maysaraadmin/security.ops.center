"""
FIM (File Integrity Monitoring) Service

This module provides file integrity monitoring, change detection, and compliance reporting.
"""
import os
import hashlib
import time
import threading
import json
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass, asdict
from datetime import datetime

from src.core.base_service import BaseService

@dataclass
class FileState:
    """Represents the state of a monitored file."""
    path: str
    size: int
    mtime: float
    mode: int
    owner: str
    group: str
    hash_sha256: str
    last_checked: float
    last_modified: float
    created: float
    is_new: bool = False
    is_deleted: bool = False
    changes: List[Dict[str, any]] = None

class FIMService(BaseService):
    """File Integrity Monitoring Service."""
    
    def __init__(self, config_path: str = None):
        """Initialize the FIM service."""
        super().__init__("FIM", config_path)
        self._monitored_paths: Set[str] = set()
        self._baseline: Dict[str, FileState] = {}
        self._baseline_file = "fim_baseline.json"
        self._scan_interval = 300  # 5 minutes
        self._stop_event = threading.Event()
        self._scan_thread = None
        self._stats = {
            'files_monitored': 0,
            'changes_detected': 0,
            'last_scan_time': 0,
            'scan_duration': 0
        }
        
        # Default paths to monitor
        self._default_paths = [
            "/etc",
            "/usr/bin",
            "/usr/sbin",
            "/bin",
            "/sbin",
            "/lib",
            "/lib64",
            "/usr/local/bin",
            "/usr/local/sbin"
        ]
        
        # File patterns to ignore
        self._ignore_patterns = [
            '*.log',
            '*.tmp',
            '*.swp',
            '*.swx',
            '*.bak',
            '*.backup',
            '/tmp/*',
            '/var/tmp/*',
            '/dev/*',
            '/proc/*',
            '/sys/*',
            '/run/*',
            '/var/run/*',
            '/var/lock/*'
        ]
    
    def start(self):
        """Start the FIM service."""
        if self._running:
            self.logger.warning("FIM service is already running")
            return True
            
        super().start()
        self.logger.info("Initializing FIM service...")
        
        try:
            # Load baseline if it exists
            self._load_baseline()
            
            # Add default paths if none configured
            if not self._monitored_paths:
                self.logger.info("No paths configured, adding default system paths")
                for path in self._default_paths:
                    if os.path.exists(path):
                        self.add_monitored_path(path)
            
            # Start background scanning
            self._stop_event.clear()
            self._scan_thread = threading.Thread(
                target=self._monitor_loop,
                daemon=True
            )
            self._scan_thread.start()
            
            self.logger.info(f"FIM service started, monitoring {len(self._monitored_paths)} paths")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start FIM service: {e}")
            self.stop()
            return False
    
    def stop(self):
        """Stop the FIM service."""
        if not self._running:
            return
            
        self.logger.info("Stopping FIM service...")
        
        # Signal scan thread to stop
        self._stop_event.set()
        
        try:
            # Save baseline before stopping
            self._save_baseline()
            
            # Wait for scan thread to finish
            if self._scan_thread and self._scan_thread.is_alive():
                self._scan_thread.join(timeout=5.0)
                
            super().stop()
            self.logger.info("FIM service stopped")
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping FIM service: {e}")
            return False
    
    def add_monitored_path(self, path: str) -> bool:
        """Add a path to monitor."""
        path = os.path.abspath(path)
        if not os.path.exists(path):
            self.logger.warning(f"Path does not exist: {path}")
            return False
            
        self._monitored_paths.add(path)
        self.logger.info(f"Added path to monitor: {path}")
        return True
    
    def remove_monitored_path(self, path: str) -> bool:
        """Remove a path from monitoring."""
        path = os.path.abspath(path)
        if path in self._monitored_paths:
            self._monitored_paths.remove(path)
            self.logger.info(f"Removed path from monitoring: {path}")
            
            # Also remove from baseline
            paths_to_remove = [p for p in self._baseline.keys() if p.startswith(path)]
            for p in paths_to_remove:
                del self._baseline[p]
                
            return True
        return False
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        self.logger.info("Starting FIM monitoring loop")
        
        while not self._stop_event.is_set():
            try:
                start_time = time.time()
                
                # Scan all monitored paths
                for path in list(self._monitored_paths):
                    if self._stop_event.is_set():
                        break
                        
                    if os.path.isfile(path):
                        self._check_file(path)
                    elif os.path.isdir(path):
                        self._scan_directory(path)
                
                # Update stats
                scan_duration = time.time() - start_time
                self._stats['last_scan_time'] = time.time()
                self._stats['scan_duration'] = scan_duration
                self._stats['files_monitored'] = len(self._baseline)
                
                # Save baseline periodically
                if int(time.time()) % 3600 == 0:  # Save hourly
                    self._save_baseline()
                
                # Sleep until next scan, but check for stop event frequently
                for _ in range(self._scan_interval):
                    if self._stop_event.is_set():
                        break
                    time.sleep(1)
                    
            except Exception as e:
                self.logger.error(f"Error in FIM monitoring loop: {e}")
                time.sleep(5)  # Prevent tight error loops
        
        self.logger.info("FIM monitoring loop stopped")
    
    def _scan_directory(self, directory: str):
        """Recursively scan a directory for files."""
        try:
            for root, _, files in os.walk(directory):
                if self._stop_event.is_set():
                    return
                    
                for file in files:
                    if self._stop_event.is_set():
                        return
                        
                    file_path = os.path.join(root, file)
                    
                    # Skip ignored paths
                    if self._should_ignore(file_path):
                        continue
                        
                    self._check_file(file_path)
                    
        except Exception as e:
            self.logger.error(f"Error scanning directory {directory}: {e}")
    
    def _should_ignore(self, path: str) -> bool:
        """Check if a path should be ignored based on patterns."""
        from fnmatch import fnmatch
        
        path = os.path.abspath(path)
        
        for pattern in self._ignore_patterns:
            # Handle directory patterns (ending with /*)
            if pattern.endswith('/*'):
                dir_path = os.path.dirname(pattern)
                if path.startswith(os.path.abspath(dir_path) + os.sep):
                    return True
            # Handle file patterns
            elif fnmatch(os.path.basename(path), pattern):
                return True
                
        return False
    
    def _check_file(self, file_path: str):
        """Check a file for changes."""
        try:
            # Get file stats
            try:
                stat = os.stat(file_path, follow_symlinks=False)
            except (OSError, PermissionError) as e:
                self.logger.warning(f"Cannot access {file_path}: {e}")
                return
            
            # Check if file is in baseline
            if file_path in self._baseline:
                self._check_for_changes(file_path, stat)
            else:
                # New file detected
                self._add_to_baseline(file_path, stat)
                
        except Exception as e:
            self.logger.error(f"Error checking file {file_path}: {e}")
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        
        try:
            with open(file_path, "rb") as f:
                # Read file in chunks to handle large files
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
            
        except (IOError, PermissionError) as e:
            self.logger.warning(f"Cannot calculate hash for {file_path}: {e}")
            return ""
    
    def _add_to_baseline(self, file_path: str, stat: os.stat_result):
        """Add a file to the baseline."""
        try:
            file_hash = self._calculate_file_hash(file_path)
            
            file_state = FileState(
                path=file_path,
                size=stat.st_size,
                mtime=stat.st_mtime,
                mode=stat.st_mode,
                owner="",  # Would use pwd.getpwuid(stat.st_uid).pw_name on Unix
                group="",   # Would use grp.getgrgid(stat.st_gid).gr_name on Unix
                hash_sha256=file_hash,
                last_checked=time.time(),
                last_modified=stat.st_mtime,
                created=stat.st_ctime,
                is_new=True,
                changes=[]
            )
            
            self._baseline[file_path] = file_state
            
            # Log the new file
            self._log_change(
                file_path=file_path,
                change_type="created",
                details="File added to monitoring",
                severity="info"
            )
            
        except Exception as e:
            self.logger.error(f"Error adding {file_path} to baseline: {e}")
    
    def _check_for_changes(self, file_path: str, current_stat: os.stat_result):
        """Check if a file has changed since the last scan."""
        file_state = self._baseline[file_path]
        changes = []
        
        # Check if file was deleted
        if not os.path.exists(file_path):
            file_state.is_deleted = True
            changes.append({"type": "deleted", "timestamp": time.time()})
            self._log_change(file_path, "deleted", "File has been deleted", "high")
            return
        
        # Check size change
        if current_stat.st_size != file_state.size:
            changes.append({
                "type": "size_change",
                "old_size": file_state.size,
                "new_size": current_stat.st_size,
                "timestamp": time.time()
            })
            file_state.size = current_stat.st_size
            self._log_change(
                file_path, 
                "modified", 
                f"Size changed from {file_state.size} to {current_stat.st_size} bytes",
                "medium"
            )
        
        # Check modification time
        if current_stat.st_mtime > file_state.last_modified:
            # Calculate file hash to verify content change
            current_hash = self._calculate_file_hash(file_path)
            
            if current_hash != file_state.hash_sha256:
                changes.append({
                    "type": "content_change",
                    "old_hash": file_state.hash_sha256[:12] + "...",
                    "new_hash": current_hash[:12] + "...",
                    "timestamp": time.time()
                })
                file_state.hash_sha256 = current_hash
                
                self._log_change(
                    file_path,
                    "modified",
                    "File content has changed",
                    "high"
                )
            
            file_state.last_modified = current_stat.st_mtime
        
        # Check permissions
        if current_stat.st_mode != file_state.mode:
            changes.append({
                "type": "permission_change",
                "old_mode": oct(file_state.mode),
                "new_mode": oct(current_stat.st_mode),
                "timestamp": time.time()
            })
            file_state.mode = current_stat.st_mode
            
            self._log_change(
                file_path,
                "permission_change",
                f"Permissions changed to {oct(current_stat.st_mode)}",
                "high"
            )
        
        # Update last checked time
        file_state.last_checked = time.time()
        
        # Add changes to history (keep last 10 changes)
        if changes:
            file_state.changes = (file_state.changes or []) + changes
            file_state.changes = file_state.changes[-10:]
            self._stats['changes_detected'] += len(changes)
    
    def _log_change(self, file_path: str, change_type: str, details: str, severity: str):
        """Log a file change event."""
        log_message = (
            f"FIM {change_type.upper()} - {file_path}\n"
            f"  Details: {details}\n"
            f"  Severity: {severity.upper()}"
        )
        
        if severity == 'high':
            self.logger.error(log_message)
        elif severity == 'medium':
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
    
    def _save_baseline(self):
        """Save the current baseline to disk."""
        try:
            # Convert FileState objects to dicts
            baseline_data = {
                path: asdict(state) 
                for path, state in self._baseline.items()
            }
            
            with open(self._baseline_file, 'w') as f:
                json.dump(baseline_data, f, indent=2)
                
            self.logger.debug(f"Saved baseline with {len(baseline_data)} files")
            
        except Exception as e:
            self.logger.error(f"Error saving baseline: {e}")
    
    def _load_baseline(self):
        """Load the baseline from disk if it exists."""
        if not os.path.exists(self._baseline_file):
            self.logger.info("No existing baseline found, starting fresh")
            return
            
        try:
            with open(self._baseline_file, 'r') as f:
                baseline_data = json.load(f)
                
            self._baseline = {
                path: FileState(**state)
                for path, state in baseline_data.items()
            }
            
            self.logger.info(f"Loaded baseline with {len(self._baseline)} files")
            
        except Exception as e:
            self.logger.error(f"Error loading baseline: {e}")
            self._baseline = {}
    
    def get_changes(self, limit: int = 100) -> List[Dict]:
        """Get recent file changes."""
        changes = []
        
        for file_state in self._baseline.values():
            if file_state.changes:
                for change in file_state.changes[-5:]:  # Last 5 changes per file
                    changes.append({
                        'file': file_state.path,
                        'type': change.get('type', 'unknown'),
                        'timestamp': change.get('timestamp', 0),
                        'details': change
                    })
        
        # Sort by timestamp, newest first
        changes.sort(key=lambda x: x['timestamp'], reverse=True)
        return changes[:limit]
    
    def status(self) -> Dict[str, Any]:
        """Get the current status of the FIM service."""
        status = super().status()
        status.update({
            'scan_active': self._scan_thread.is_alive() if self._scan_thread else False,
            'paths_monitored': len(self._monitored_paths),
            'stats': {
                'files_monitored': self._stats['files_monitored'],
                'changes_detected': self._stats['changes_detected'],
                'last_scan_time': self._stats['last_scan_time'],
                'scan_duration': self._stats['scan_duration']
            }
        })
        return status
