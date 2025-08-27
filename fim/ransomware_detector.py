"""
Ransomware Detection Module

This module provides functionality to detect potential ransomware activity
based on file system changes and behavior patterns.
"""
import os
import time
from typing import Dict, List, Set, Optional
from pathlib import Path
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class RansomwareDetector:
    """Detects potential ransomware activity based on file system patterns."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the ransomware detector with configuration."""
        self.config = config or {}
        self.file_operations: Dict[str, List[Dict]] = {}
        self.suspicious_extensions = {
            '.encrypted', '.locked', '.crypt', '.crypto', '.locky', '.zepto', '.odin',
            '.aes', '.rsa', '.cerber', '.xtbl', '.cry', '.zzz', '.xyz', '.zzzzz',
            '.lock', '.cryptolocker', '.cryptowall', '.petya', '.wannacry', '.ryuk'
        }
        self.suspicious_paths = {
            'appdata', 'temp', 'tmp', 'local\temp', 'local\microsoft\windows\temporary',
            'users\public', 'programdata', 'windows\temp'
        }
        self.suspicious_processes = {
            'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe',
            'wmic.exe', 'certutil.exe', 'bitsadmin.exe', 'regsvr32.exe'
        }
        
        # Thresholds for detection
        self.file_mod_threshold = self.config.get('file_mod_threshold', 100)  # files per minute
        self.extension_change_threshold = self.config.get('extension_change_threshold', 20)  # extensions per minute
        self.alert_cooldown = timedelta(minutes=5)  # Minimum time between alerts
        self.last_alert_time: Optional[datetime] = None
        
        # Track recent activity
        self.recent_operations: List[Dict] = []
        self.extension_changes: Dict[str, int] = {}
        self.modified_files: Set[str] = set()
    
    def analyze_event(self, event: Dict) -> Optional[Dict]:
        """
        Analyze a file system event for potential ransomware activity.
        
        Args:
            event: Dictionary containing event details
                - path: str - Path to the file
                - event_type: str - Type of event (created, modified, deleted, etc.)
                - timestamp: datetime - When the event occurred
                - process: Optional[str] - Process that triggered the event
                - user: Optional[str] - User that triggered the event
                
        Returns:
            Optional[Dict]: Alert details if suspicious activity is detected, None otherwise
        """
        if not event or 'path' not in event or 'event_type' not in event:
            return None
            
        path = event['path'].lower()
        event_type = event['event_type'].lower()
        timestamp = event.get('timestamp', datetime.utcnow())
        process = (event.get('process', '').lower() or '').lower()
        
        # Skip system files and directories
        if self._is_system_path(path):
            return None
            
        # Check for suspicious file extensions
        ext = os.path.splitext(path)[1].lower()
        is_suspicious_ext = ext in self.suspicious_extensions
        
        # Track extension changes
        if event_type == 'renamed' and 'new_path' in event:
            old_ext = os.path.splitext(path)[1].lower()
            new_ext = os.path.splitext(event['new_path'])[1].lower()
            if old_ext != new_ext:
                self.extension_changes[new_ext] = self.extension_changes.get(new_ext, 0) + 1
        
        # Track file modifications
        if event_type in ('modified', 'created'):
            self.modified_files.add(path)
        
        # Check for suspicious patterns
        suspicious_patterns = self._detect_suspicious_patterns(path, process, event_type, timestamp)
        
        # Check thresholds
        threshold_alerts = self._check_thresholds(timestamp)
        
        # Combine all alerts
        alerts = []
        if suspicious_patterns:
            alerts.extend(suspicious_patterns)
        if threshold_alerts:
            alerts.extend(threshold_alerts)
            
        if alerts:
            return {
                'timestamp': timestamp.isoformat(),
                'severity': 'high',
                'type': 'ransomware_suspicion',
                'alerts': alerts,
                'file_path': path,
                'process': process,
                'event_type': event_type,
                'details': {
                    'suspicious_extension': is_suspicious_ext,
                    'suspicious_path': any(p in path.lower() for p in self.suspicious_paths),
                    'suspicious_process': any(p in process for p in self.suspicious_processes)
                }
            }
            
        return None
    
    def _is_system_path(self, path: str) -> bool:
        """Check if a path is a system path that should be excluded from monitoring."""
        system_paths = {
            'c:\\windows', 'c:\\program files', 'c:\\program files (x86)',
            'c:\\programdata', 'c:\\system volume information',
            'c:\\$recycle.bin', 'c:\\windows\\.*'
        }
        path = path.lower().replace('/', '\\')
        return any(path.startswith(p) for p in system_paths)
    
    def _detect_suspicious_patterns(
        self,
        path: str,
        process: str,
        event_type: str,
        timestamp: datetime
    ) -> List[Dict]:
        """Detect suspicious patterns that might indicate ransomware activity."""
        alerts = []
        
        # 1. Suspicious file extensions
        ext = os.path.splitext(path)[1].lower()
        if ext in self.suspicious_extensions:
            alerts.append({
                'type': 'suspicious_extension',
                'message': f'Suspicious file extension: {ext}',
                'severity': 'high'
            })
        
        # 2. Suspicious paths
        path_lower = path.lower()
        if any(p in path_lower for p in self.suspicious_paths):
            alerts.append({
                'type': 'suspicious_location',
                'message': f'File operation in suspicious location: {path}',
                'severity': 'medium'
            })
        
        # 3. Suspicious processes
        if any(p in process for p in self.suspicious_processes):
            alerts.append({
                'type': 'suspicious_process',
                'message': f'Suspicious process performing file operation: {process}',
                'severity': 'high'
            })
        
        # 4. Rapid file modifications
        now = datetime.utcnow()
        recent_ops = [op for op in self.recent_operations 
                     if now - op['timestamp'] < timedelta(minutes=1)]
        
        if len(recent_ops) > self.file_mod_threshold:
            alerts.append({
                'type': 'high_file_activity',
                'message': f'High file modification rate detected: {len(recent_ops)} operations/min',
                'severity': 'high',
                'count': len(recent_ops)
            })
        
        return alerts
    
    def _check_thresholds(self, timestamp: datetime) -> List[Dict]:
        """Check if any thresholds have been exceeded."""
        alerts = []
        now = datetime.utcnow()
        
        # Check extension changes threshold
        recent_ext_changes = sum(
            count for ext, count in self.extension_changes.items()
            if now - timestamp < timedelta(minutes=1)
        )
        
        if recent_ext_changes > self.extension_change_threshold:
            alerts.append({
                'type': 'high_extension_changes',
                'message': f'High number of file extension changes: {recent_ext_changes}',
                'severity': 'high',
                'count': recent_ext_changes
            })
        
        # Check file modification threshold
        recent_mods = len([f for f in self.modified_files 
                          if now - timestamp < timedelta(minutes=1)])
        
        if recent_mods > self.file_mod_threshold:
            alerts.append({
                'type': 'high_file_modifications',
                'message': f'High number of file modifications: {recent_mods}',
                'severity': 'high',
                'count': recent_mods
            })
        
        # Clean up old data
        self._cleanup_old_data(now)
        
        return alerts
    
    def _cleanup_old_data(self, current_time: datetime) -> None:
        """Clean up old data to prevent memory leaks."""
        # Keep only recent operations (last 5 minutes)
        self.recent_operations = [
            op for op in self.recent_operations
            if current_time - op['timestamp'] < timedelta(minutes=5)
        ]
        
        # Clean up old extension changes
        old_extensions = [
            ext for ext, count in self.extension_changes.items()
            if count == 0
        ]
        for ext in old_extensions:
            self.extension_changes.pop(ext, None)
        
        # Clean up old modified files
        self.modified_files = {
            f for f in self.modified_files
            if current_time - datetime.fromtimestamp(os.path.getmtime(f)) < timedelta(hours=1)
        }
        
    def reset(self) -> None:
        """Reset the detector's state."""
        self.recent_operations.clear()
        self.extension_changes.clear()
        self.modified_files.clear()
        self.last_alert_time = None
