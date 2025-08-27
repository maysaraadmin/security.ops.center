"""
Process execution behavior analyzer for UEBA.

This module provides analysis of process execution patterns to detect anomalies
such as unusual process execution, privilege escalation, or malicious activity.
"""
import logging
from datetime import datetime
from typing import Dict, Any, Set
import hashlib
import os

from .base import BaseAnalyzer

logger = logging.getLogger('siem.ueba.analyzers.process_execution')

class ProcessExecutionAnalyzer(BaseAnalyzer):
    """Analyzes process execution patterns to detect anomalies."""
    
    def __init__(self, model_type: str = 'statistical'):
        super().__init__(model_type)
        self.suspicious_processes = self._load_suspicious_processes()
        self.privileged_directories = self._get_privileged_directories()
    
    def _load_suspicious_processes(self) -> Set[str]:
        """Load known suspicious processes."""
        return {
            'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
            'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'bitsadmin.exe',
            'certutil.exe', 'wmic.exe', 'msbuild.exe', 'msxsl.exe'
        }
    
    def _get_privileged_directories(self) -> Set[str]:
        """Get system directories where privileged processes typically run from."""
        return {
            os.environ.get('SystemRoot', 'C:\\Windows'),
            os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32'),
            os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'SysWOW64'),
            os.environ.get('ProgramFiles', 'C:\\Program Files'),
            os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)')
        }
    
    def _is_process_execution_event(self, event_data: Dict[str, Any]) -> bool:
        """Check if the event is a process execution event."""
        event_type = event_data.get('event_type', '').lower()
        return any(term in event_type for term in ['process', 'exec', 'launch'])
    
    def _hash_sensitive_value(self, value: str) -> str:
        """Hash sensitive values for privacy."""
        if not value:
            return ''
        return hashlib.sha256(value.encode()).hexdigest()
    
    def _is_privileged_path(self, path: str) -> bool:
        """Check if a file path is in a privileged directory."""
        if not path:
            return False
        
        try:
            normalized_path = os.path.normpath(path).lower()
            return any(
                os.path.normpath(priv_dir).lower() in normalized_path
                for priv_dir in self.privileged_directories
            )
        except (TypeError, ValueError):
            return False
    
    def extract_features(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract process execution features from an event."""
        if not self._is_process_execution_event(event_data):
            return {}
        
        features = {}
        
        # Extract basic info
        timestamp = event_data.get('timestamp')
        user = event_data.get('user', {})
        process = event_data.get('process', {})
        
        # Time-based features
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp) if isinstance(timestamp, str) else timestamp
                features['hour_of_day'] = dt.hour
                features['day_of_week'] = dt.weekday()
            except (ValueError, AttributeError):
                pass
        
        # User features
        if user:
            features['user_id'] = self._hash_sensitive_value(user.get('id', ''))
            features['is_admin'] = 1 if user.get('is_admin', False) else 0
        
        # Process features
        if process:
            # Process name and path
            process_name = process.get('name', '').lower()
            process_path = process.get('path', '').lower()
            
            features['process_name'] = process_name
            features['is_suspicious'] = 1 if process_name in self.suspicious_processes else 0
            
            # Process path analysis
            features['is_privileged_path'] = 1 if self._is_privileged_path(process_path) else 0
            
            # Parent process info
            parent_process = process.get('parent', {})
            if parent_process:
                parent_name = parent_process.get('name', '').lower()
                features['parent_process'] = parent_name
                
                # Check for suspicious parent-child relationships
                if parent_name in ['explorer.exe', 'winword.exe', 'excel.exe'] and \
                   process_name in self.suspicious_processes:
                    features['suspicious_parent_child'] = 1
            
            # Command line arguments
            cmd_line = process.get('command_line', '').lower()
            if cmd_line:
                features['has_encoded_arguments'] = 1 if any(
                    term in cmd_line for term in [' -enc ', ' -e ', ' -en ']
                ) else 0
                
                features['has_suspicious_flags'] = 1 if any(
                    flag in cmd_line for flag in ['/c', '/k', '/q', '/nop', '-nop', '-noni', '-noprofile']
                ) else 0
        
        return features
    
    def describe_anomaly(self, features: Dict[str, Any], score: float) -> str:
        """Generate a human-readable description of a process execution anomaly."""
        if not features:
            return "Suspicious process execution detected"
            
        parts = []
        
        process_name = features.get('process_name', 'unknown')
        
        if features.get('is_suspicious') == 1:
            parts.append(f"suspicious process: {process_name}")
        
        if features.get('suspicious_parent_child') == 1:
            parent = features.get('parent_process', 'unknown')
            parts.append(f"unusual parent-child relationship: {parent} -> {process_name}")
        
        if features.get('has_encoded_arguments') == 1:
            parts.append("encoded command line arguments")
            
        if features.get('has_suspicious_flags') == 1:
            parts.append("suspicious command line flags")
        
        hour = features.get('hour_of_day')
        if hour is not None and (hour < 6 or hour > 20):
            parts.append(f"unusual execution time ({hour}:00)")
        
        if not parts:
            return f"Unusual process execution pattern (confidence: {score:.2f})"
            
        return f"Anomalous process execution: {', '.join(parts)} (confidence: {score:.2f})"
