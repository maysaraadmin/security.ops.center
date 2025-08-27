"""
DLP Manager - Coordinates DLP components and provides a unified interface.
"""
import os
import time
import logging
from typing import Dict, List, Optional, Callable, Any, Set
from datetime import datetime
from pathlib import Path
import threading
import queue

from .detection_engine import DLPDetectionEngine
from .file_monitor import DLPFileMonitor

class DLPManager:
    """
    Main DLP manager class that coordinates detection and monitoring.
    """
    
    def __init__(self, alert_callback: Callable[[Dict], None] = None):
        """
        Initialize the DLP manager.
        
        Args:
            alert_callback: Function to call when a DLP alert is generated
        """
        self.detection_engine = DLPDetectionEngine()
        self.file_monitor = DLPFileMonitor(scan_callback=self._scan_file_callback)
        self.alert_callback = alert_callback
        self.logger = logging.getLogger(__name__)
        self.running = False
        self.stats = {
            'start_time': None,
            'files_scanned': 0,
            'alerts_triggered': 0,
            'last_alert': None,
            'rules_loaded': len(self.detection_engine.rules)
        }
        
        # For thread-safe operations
        self.lock = threading.Lock()
        
        # Alert queue for processing in the main thread
        self.alert_queue = queue.Queue()
    
    def start(self) -> None:
        """Start the DLP monitoring service."""
        with self.lock:
            if not self.running:
                self.running = True
                self.stats['start_time'] = datetime.utcnow()
                self.file_monitor.start()
                
                # Start alert processing thread
                self._start_alert_processor()
                
                self.logger.info("DLP service started")
    
    def stop(self) -> None:
        """Stop the DLP monitoring service."""
        with self.lock:
            if self.running:
                self.running = False
                self.file_monitor.stop()
                self.logger.info("DLP service stopped")
    
    def add_watch_directory(self, path: str, recursive: bool = True) -> None:
        """
        Add a directory to monitor for sensitive data.
        
        Args:
            path: Directory path to monitor
            recursive: Whether to monitor subdirectories
        """
        self.file_monitor.add_watch_directory(path, recursive)
    
    def remove_watch_directory(self, path: str) -> None:
        """
        Remove a directory from being monitored.
        
        Args:
            path: Directory path to stop monitoring
        """
        self.file_monitor.remove_watch_directory(path)
    
    def get_watch_directories(self) -> List[str]:
        """
        Get the list of currently monitored directories.
        
        Returns:
            List of directory paths being monitored
        """
        return list(self.file_monitor.watched_paths.keys())
    
    def scan_file(self, filepath: str) -> List[Dict]:
        """
        Manually scan a file for sensitive data.
        
        Args:
            filepath: Path to the file to scan
            
        Returns:
            List of DLP matches found in the file
        """
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            return self.scan_content(content, source=filepath)
        except Exception as e:
            self.logger.error(f"Error scanning file {filepath}: {e}", exc_info=True)
            return []
    
    def scan_content(self, content: bytes, source: str = None, 
                    content_type: str = None) -> List[Dict]:
        """
        Scan content for sensitive data.
        
        Args:
            content: Content to scan (bytes)
            source: Optional source identifier (e.g., file path)
            content_type: Optional content type hint
            
        Returns:
            List of DLP matches found in the content
        """
        matches = self.detection_engine.scan_content(content, content_type)
        
        # Update stats
        with self.lock:
            self.stats['files_scanned'] += 1
            
            if matches:
                self.stats['alerts_triggered'] += len(matches)
                self.stats['last_alert'] = datetime.utcnow().isoformat()
                
                # Queue alerts for processing
                for match in matches:
                    alert = self._create_alert(match, source)
                    self.alert_queue.put(alert)
        
        return matches
    
    def _scan_file_callback(self, filepath: str, content: bytes) -> None:
        """
        Callback function for file monitor to scan files.
        
        Args:
            filepath: Path to the file being scanned
            content: File content as bytes
        """
        self.scan_content(content, source=filepath)
    
    def _create_alert(self, match: Dict, source: str = None) -> Dict:
        """
        Create a DLP alert from a match.
        
        Args:
            match: DLP match details from the detection engine
            source: Optional source of the content
            
        Returns:
            Alert dictionary
        """
        alert = {
            'timestamp': datetime.utcnow().isoformat(),
            'rule_id': match['rule_id'],
            'rule_name': match['name'],
            'severity': match['severity'],
            'confidence': match['confidence'],
            'source': source,
            'description': match['description'],
            'content_preview': match.get('content_preview', ''),
            'patterns': match.get('patterns', []),
            'keywords': match.get('keywords', []),
            'action': match.get('action', 'alert')
        }
        
        return alert
    
    def _start_alert_processor(self) -> None:
        """Start the alert processing thread."""
        def process_alerts():
            while self.running:
                try:
                    # Process all pending alerts
                    while True:
                        try:
                            alert = self.alert_queue.get_nowait()
                            
                            # Call the alert callback if set
                            if self.alert_callback:
                                try:
                                    self.alert_callback(alert)
                                except Exception as e:
                                    self.logger.error(
                                        f"Error in alert callback: {e}", 
                                        exc_info=True
                                    )
                            
                            # Log the alert
                            self.logger.warning(
                                f"DLP Alert - {alert['rule_name']} ({alert['severity']}): "
                                f"{alert['description']} in {alert.get('source', 'unknown')}"
                            )
                            
                        except queue.Empty:
                            break
                    
                    # Sleep briefly to avoid high CPU usage
                    time.sleep(0.1)
                    
                except Exception as e:
                    self.logger.error(f"Error in alert processor: {e}", exc_info=True)
                    time.sleep(1)  # Prevent tight loop on errors
        
        # Start the alert processor thread
        thread = threading.Thread(
            target=process_alerts,
            name="DLPAlertProcessor",
            daemon=True
        )
        thread.start()
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get the current status of the DLP service.
        
        Returns:
            Dictionary with status information
        """
        with self.lock:
            uptime = 0
            if self.stats['start_time']:
                uptime = (datetime.utcnow() - self.stats['start_time']).total_seconds()
            
            return {
                'running': self.running,
                'uptime_seconds': uptime,
                'files_scanned': self.stats['files_scanned'],
                'alerts_triggered': self.stats['alerts_triggered'],
                'last_alert': self.stats['last_alert'],
                'rules_loaded': len(self.detection_engine.rules),
                'watch_directories': self.get_watch_directories()
            }
    
    def get_rules(self) -> List[Dict]:
        """
        Get information about all DLP rules.
        
        Returns:
            List of rule dictionaries
        """
        rules = []
        for rule_id, rule in self.detection_engine.rules.items():
            rules.append({
                'id': rule.rule_id,
                'name': rule.name,
                'description': rule.description,
                'severity': rule.severity,
                'enabled': rule.enabled,
                'action': rule.action,
                'pattern_count': len(rule.patterns),
                'keyword_count': len(rule.keywords),
                'min_confidence': rule.min_confidence
            })
        return rules
    
    def toggle_rule(self, rule_id: str, enabled: bool = None) -> bool:
        """
        Enable or disable a DLP rule.
        
        Args:
            rule_id: ID of the rule to toggle
            enabled: True to enable, False to disable, None to toggle
            
        Returns:
            New enabled state of the rule, or None if rule not found
        """
        if rule_id in self.detection_engine.rules:
            rule = self.detection_engine.rules[rule_id]
            if enabled is None:
                rule.enabled = not rule.enabled
            else:
                rule.enabled = bool(enabled)
            return rule.enabled
        return None
