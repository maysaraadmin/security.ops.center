"""
File and Registry Integrity Monitor for HIPS

Monitors critical system files, boot sectors, and registry keys for unauthorized changes.
Prevents rootkits, backdoors, and persistence mechanisms.
"""

import os
import sys
import hashlib
import logging
import platform
import threading
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Callable, Any, Tuple
from datetime import datetime
import json

import psutil

if platform.system() == 'Windows':
    import winreg
    import win32api
    import win32con

logger = logging.getLogger(__name__)

class ChangeType(Enum):
    """Types of file/registry changes that can be detected."""
    CREATED = auto()
    MODIFIED = auto()
    DELETED = auto()
    PERMISSIONS_CHANGED = auto()
    OWNER_CHANGED = auto()
    HASH_CHANGED = auto()

@dataclass
class IntegrityViolation:
    """Represents an integrity violation event."""
    path: str
    change_type: ChangeType
    timestamp: float = field(default_factory=time.time)
    process_info: Optional[Dict] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    severity: str = 'medium'  # low, medium, high, critical

class FileRegistryMonitor:
    """
    Monitors files and registry keys for unauthorized changes.
    """
    
    def __init__(self):
        self.running = False
        self._lock = threading.RLock()
        self._file_hashes: Dict[str, str] = {}
        self._registry_hashes: Dict[str, str] = {}
        self._monitored_paths: Set[str] = set()
        self._monitored_registry: Set[Tuple[str, str]] = set()  # (hive, key_path)
        self._alert_handlers: List[Callable[[IntegrityViolation], None]] = []
        
        # Default critical paths to monitor
        self._critical_paths = self._get_default_critical_paths()
        self._critical_registry = self._get_critical_registry_keys()
        
        # Initialize baseline hashes
        self._initialize_baseline()
    
    def _get_default_critical_paths(self) -> Set[str]:
        """Get default critical system paths to monitor based on platform."""
        system_paths = set()
        
        if platform.system() == 'Windows':
            system32 = os.environ.get('SystemRoot', 'C:\\Windows') + '\\System32'
            critical_paths = [
                f"{system32}\\drivers\\etc\\hosts",
                f"{system32}\\drivers\\etc\\networks",
                f"{system32}\\drivers\\etc\\protocol",
                f"{system32}\\drivers\\etc\\services",
                f"{system32}\\ntoskrnl.exe",
                f"{system32}\\kernel32.dll",
                f"{system32}\\user32.dll",
                f"{system32}\\ws2_32.dll",
                f"{system32}\\ntdll.dll",
                f"{system32}\\drivers\\*.sys",
                "C:\\Windows\\System32\\config\\SYSTEM",
                "C:\\Windows\\System32\\config\\SOFTWARE",
                "C:\\Windows\\System32\\config\\SECURITY",
                "C:\\Windows\\System32\\config\\SAM",
                "C:\\Windows\\System32\\config\\DEFAULT",
            ]
            system_paths.update(critical_paths)
            
        elif platform.system() == 'Linux':
            critical_paths = [
                '/sbin/init',
                '/sbin/init.d',
                '/sbin/iptables',
                '/sbin/ip6tables',
                '/sbin/ifconfig',
                '/sbin/route',
                '/sbin/ip',
                '/sbin/sshd',
                '/bin/login',
                '/bin/sh',
                '/bin/bash',
                '/bin/dash',
                '/bin/rbash',
                '/etc/passwd',
                '/etc/shadow',
                '/etc/group',
                '/etc/sudoers',
                '/etc/ssh/sshd_config',
                '/etc/hosts',
                '/etc/hostname',
                '/etc/resolv.conf',
                '/etc/crontab',
                '/etc/cron.d/*',
                '/etc/init.d/*',
                '/etc/rc.local',
                '/etc/ld.so.preload',
                '/lib/modules/*/kernel/drivers/*',
                '/usr/lib/modules/*/kernel/drivers/*',
                '/lib/modules/*/kernel/fs/*',
                '/usr/lib/modules/*/kernel/fs/*',
            ]
            system_paths.update(critical_paths)
            
        return system_paths
    
    def _get_critical_registry_keys(self) -> Set[Tuple[str, str]]:
        """Get critical registry keys to monitor (Windows only)."""
        if platform.system() != 'Windows':
            return set()
            
        return {
            # Run keys
            (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
            (winreg.HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (winreg.HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
            
            # Services
            (winreg.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services"),
            
            # Browser helper objects
            (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects"),
            
            # Winlogon
            (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell"),
            (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit"),
            
            # AppInit DLLs
            (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs"),
            (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs"),
        }
    
    def _initialize_baseline(self):
        """Initialize baseline hashes for all monitored files and registry keys."""
        with self._lock:
            # Initialize file hashes
            for path in self._critical_paths:
                if '*' in path:
                    # Handle wildcard patterns
                    import glob
                    for expanded_path in glob.glob(path):
                        self._add_file_to_baseline(expanded_path)
                else:
                    self._add_file_to_baseline(path)
            
            # Initialize registry hashes (Windows only)
            if platform.system() == 'Windows':
                for hive, key_path in self._critical_registry:
                    self._add_registry_to_baseline(hive, key_path)
    
    def _add_file_to_baseline(self, path: str):
        """Add a file to the baseline with its hash."""
        try:
            if os.path.isfile(path):
                file_hash = self._calculate_file_hash(path)
                self._file_hashes[path] = file_hash
                self._monitored_paths.add(path)
        except Exception as e:
            logger.warning(f"Could not add file to baseline {path}: {e}")
    
    def _add_registry_to_baseline(self, hive, key_path: str):
        """Add a registry key to the baseline with its hash (Windows only)."""
        if platform.system() != 'Windows':
            return
            
        try:
            with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
                # Get all values and their data
                values = []
                try:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            values.append((name, value))
                            i += 1
                        except OSError:
                            break
                except WindowsError:
                    pass
                
                # Create a string representation of the key for hashing
                key_data = json.dumps(values, sort_keys=True).encode('utf-8')
                key_hash = hashlib.sha256(key_data).hexdigest()
                
                # Store the hash
                registry_id = f"{hive}:{key_path}"
                self._registry_hashes[registry_id] = key_hash
                self._monitored_registry.add((hive, key_path))
                
        except WindowsError as e:
            logger.warning(f"Could not add registry key to baseline {key_path}: {e}")
    
    def _calculate_file_hash(self, path: str) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        try:
            with open(path, 'rb') as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {path}: {e}")
            return ""
    
    def start(self):
        """Start the monitoring process."""
        if self.running:
            return
            
        self.running = True
        monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        monitor_thread.start()
        logger.info("File and Registry Integrity Monitor started")
    
    def stop(self):
        """Stop the monitoring process."""
        self.running = False
        logger.info("File and Registry Integrity Monitor stopped")
    
    def add_alert_handler(self, handler: Callable[[IntegrityViolation], None]):
        """Add a callback function to handle integrity violation alerts."""
        self._alert_handlers.append(handler)
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.running:
            try:
                self._check_file_integrity()
                if platform.system() == 'Windows':
                    self._check_registry_integrity()
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}", exc_info=True)
            
            # Sleep for a while before next check
            time.sleep(30)  # Check every 30 seconds
    
    def _check_file_integrity(self):
        """Check integrity of monitored files."""
        with self._lock:
            # Check existing files
            for path in list(self._monitored_paths):
                if not os.path.exists(path):
                    # File was deleted
                    violation = IntegrityViolation(
                        path=path,
                        change_type=ChangeType.DELETED,
                        severity='high',
                        metadata={"type": "file"}
                    )
                    self._handle_violation(violation)
                    continue
                
                # Check if file was modified
                current_hash = self._calculate_file_hash(path)
                if path in self._file_hashes and current_hash != self._file_hashes[path]:
                    # File was modified
                    violation = IntegrityViolation(
                        path=path,
                        change_type=ChangeType.HASH_CHANGED,
                        severity='high',
                        metadata={
                            "type": "file",
                            "old_hash": self._file_hashes[path],
                            "new_hash": current_hash
                        }
                    )
                    self._handle_violation(violation)
                    
                    # Update the hash
                    self._file_hashes[path] = current_hash
            
            # Check for new files in monitored directories
            for path in self._critical_paths:
                if '*' in path:
                    # Handle wildcard patterns
                    import glob
                    for expanded_path in glob.glob(path):
                        if expanded_path not in self._monitored_paths and os.path.isfile(expanded_path):
                            # New file detected
                            violation = IntegrityViolation(
                                path=expanded_path,
                                change_type=ChangeType.CREATED,
                                severity='medium',
                                metadata={"type": "file"}
                            )
                            self._handle_violation(violation)
                            
                            # Add to monitored files
                            self._add_file_to_baseline(expanded_path)
    
    def _check_registry_integrity(self):
        """Check integrity of monitored registry keys (Windows only)."""
        if platform.system() != 'Windows':
            return
            
        with self._lock:
            for hive, key_path in list(self._monitored_registry):
                registry_id = f"{hive}:{key_path}"
                try:
                    with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
                        # Get all values and their data
                        values = []
                        try:
                            i = 0
                            while True:
                                try:
                                    name, value, _ = winreg.EnumValue(key, i)
                                    values.append((name, value))
                                    i += 1
                                except OSError:
                                    break
                        except WindowsError:
                            pass
                        
                        # Create a string representation of the key for hashing
                        key_data = json.dumps(values, sort_keys=True).encode('utf-8')
                        current_hash = hashlib.sha256(key_data).hexdigest()
                        
                        # Check if registry key was modified
                        if registry_id in self._registry_hashes and \
                           current_hash != self._registry_hashes[registry_id]:
                            # Registry key was modified
                            violation = IntegrityViolation(
                                path=f"{hive}\\{key_path}",
                                change_type=ChangeType.MODIFIED,
                                severity='high',
                                metadata={
                                    "type": "registry",
                                    "old_hash": self._registry_hashes[registry_id],
                                    "new_hash": current_hash,
                                    "values": values
                                }
                            )
                            self._handle_violation(violation)
                            
                            # Update the hash
                            self._registry_hashes[registry_id] = current_hash
                            
                except WindowsError as e:
                    if e.winerror == 2:  # Key not found
                        # Registry key was deleted
                        violation = IntegrityViolation(
                            path=f"{hive}\\{key_path}",
                            change_type=ChangeType.DELETED,
                            severity='high',
                            metadata={"type": "registry"}
                        )
                        self._handle_violation(violation)
                        
                        # Remove from monitored registry keys
                        if (hive, key_path) in self._monitored_registry:
                            self._monitored_registry.remove((hive, key_path))
                            if registry_id in self._registry_hashes:
                                del self._registry_hashes[registry_id]
                    else:
                        logger.warning(f"Error accessing registry key {key_path}: {e}")
    
    def _handle_violation(self, violation: IntegrityViolation):
        """Handle an integrity violation by logging and alerting."""
        # Log the violation
        logger.warning(f"Integrity violation detected: {violation}")
        
        # Call all registered alert handlers
        for handler in self._alert_handlers:
            try:
                handler(violation)
            except Exception as e:
                logger.error(f"Error in alert handler: {e}", exc_info=True)

# Example usage
if __name__ == "__main__":
    import sys
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Create and start the monitor
    monitor = FileRegistryMonitor()
    
    # Add a simple alert handler
    def alert_handler(violation):
        print(f"\n[!] INTEGRITY VIOLATION DETECTED!")
        print(f"    Path: {violation.path}")
        print(f"    Type: {violation.change_type.name}")
        print(f"    Severity: {violation.severity.upper()}")
        if violation.metadata:
            print("    Details:")
            for k, v in violation.metadata.items():
                print(f"      {k}: {v}")
    
    monitor.add_alert_handler(alert_handler)
    monitor.start()
    
    print("File and Registry Integrity Monitor started. Press Ctrl+C to stop.")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
        print("\nStopping monitor...")
