"""
DLP (Data Loss Prevention) Service

This module provides data protection, policy enforcement, and user education capabilities.
"""
import os
import re
import time
import threading
import hashlib
from typing import Dict, Any, List, Optional, Set, Tuple, Pattern
from pathlib import Path

from src.core.base_service import BaseService

class DLPService(BaseService):
    """DLP Service Manager."""
    
    def __init__(self, config_path: str = None):
        """Initialize the DLP service."""
        super().__init__("DLP", config_path)
        self.policy_engine = None
        self.scanner = None
        self.reporting = None
        self._scan_thread = None
        self._stop_event = threading.Event()
        self._policies = self._load_default_policies()
        self._sensitive_data_cache: Dict[str, Set[Tuple[str, str]]] = {}  # {file_path: set((pattern_name, matched_text))}
        self._stats = {
            'files_scanned': 0,
            'violations_found': 0,
            'last_scan_time': 0,
            'data_classified': 0  # in bytes
        }
    
    def _load_default_policies(self) -> Dict[str, Dict]:
        """Load default DLP policies."""
        return {
            'credit_card': {
                'name': 'Credit Card Numbers',
                'description': 'Detects credit card numbers',
                'severity': 'high',
                'patterns': [
                    r'\b(?:4[0-9]{12}(?:[0-9]{3})?|(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b'
                ],
                'action': 'alert',
                'enabled': True
            },
            'ssn': {
                'name': 'Social Security Numbers',
                'description': 'Detects US Social Security numbers',
                'severity': 'high',
                'patterns': [
                    r'\b\d{3}[-.]?\d{2}[-.]?\d{4}\b'
                ],
                'action': 'alert',
                'enabled': True
            },
            'api_key': {
                'name': 'API Keys',
                'description': 'Detects common API key patterns',
                'severity': 'high',
                'patterns': [
                    r'\b[A-Za-z0-9]{32}\b',
                    r'\b[A-Za-z0-9]{40}\b',
                    r'\b[A-Za-z0-9]{64}\b',
                    r'\b[A-Za-z0-9]{20,80}\.[A-Za-z0-9_\-]{20,100}\.?[A-Za-z0-9_\-]{20,100}\b'
                ],
                'action': 'alert',
                'enabled': True
            }
        }
    
    def start(self):
        """Start the DLP service."""
        if self._running:
            self.logger.warning("DLP service is already running")
            return True
            
        super().start()
        self.logger.info("Initializing DLP service components...")
        
        try:
            # Initialize policy engine
            self.logger.info("Initializing policy engine...")
            # self.policy_engine = PolicyEngine(self.config.get('policies', {}))
            
            # Initialize scanner
            self.logger.info("Initializing file scanner...")
            # self.scanner = FileScanner(self.config.get('scanner', {}))
            
            # Initialize reporting
            self.logger.info("Initializing reporting module...")
            # self.reporting = ReportingEngine(self.config.get('reporting', {}))
            
            # Start background scanning
            self._stop_event.clear()
            self._scan_thread = threading.Thread(
                target=self._scan_loop,
                daemon=True
            )
            self._scan_thread.start()
            
            self.logger.info("DLP service started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start DLP service: {e}")
            self.stop()
            return False
    
    def stop(self):
        """Stop the DLP service."""
        if not self._running:
            return
            
        self.logger.info("Stopping DLP service...")
        
        # Signal scan thread to stop
        self._stop_event.set()
        
        try:
            # Stop components
            # if self.policy_engine:
            #     self.policy_engine.cleanup()
            # if self.scanner:
            #     self.scanner.cleanup()
            # if self.reporting:
            #     self.reporting.cleanup()
            
            # Wait for scan thread to finish
            if self._scan_thread and self._scan_thread.is_alive():
                self._scan_thread.join(timeout=5.0)
                
            super().stop()
            self.logger.info("DLP service stopped")
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping DLP service: {e}")
            return False
    
    def _scan_loop(self):
        """Background scanning loop."""
        self.logger.info("Starting DLP background scanning")
        
        # Example: Scan common directories for sensitive data
        scan_dirs = [
            str(Path.home() / "Documents"),
            str(Path.home() / "Downloads"),
            "/etc"
        ]
        
        while not self._stop_event.is_set():
            try:
                for scan_dir in scan_dirs:
                    if not os.path.isdir(scan_dir):
                        continue
                        
                    for root, _, files in os.walk(scan_dir):
                        if self._stop_event.is_set():
                            break
                            
                        for file in files:
                            if self._stop_event.is_set():
                                break
                                
                            file_path = os.path.join(root, file)
                            try:
                                self._scan_file(file_path)
                            except Exception as e:
                                self.logger.error(f"Error scanning {file_path}: {e}")
                
                # Sleep for a while before the next scan
                for _ in range(60):  # Check every second for stop event
                    if self._stop_event.is_set():
                        break
                    time.sleep(1)
                    
            except Exception as e:
                self.logger.error(f"Error in DLP scan loop: {e}")
                time.sleep(5)  # Prevent tight error loops
        
        self.logger.info("DLP background scanning stopped")
    
    def _scan_file(self, file_path: str):
        """Scan a file for sensitive data."""
        if not os.path.isfile(file_path):
            return
            
        # Skip binary files and large files (over 10MB)
        if os.path.getsize(file_path) > 10 * 1024 * 1024:
            return
            
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except (IOError, UnicodeDecodeError):
            return
            
        self._stats['files_scanned'] += 1
        violations = set()
        
        # Check each policy
        for policy_id, policy in self._policies.items():
            if not policy['enabled']:
                continue
                
            for pattern in policy['patterns']:
                try:
                    matches = re.finditer(pattern, content, re.MULTILINE)
                    for match in matches:
                        matched_text = match.group()
                        violations.add((policy_id, matched_text))
                        
                        # Log the violation
                        self._log_violation(
                            policy_id=policy_id,
                            policy_name=policy['name'],
                            severity=policy['severity'],
                            file_path=file_path,
                            matched_text=matched_text
                        )
                        
                except re.error as e:
                    self.logger.error(f"Invalid regex pattern in policy {policy_id}: {e}")
        
        # Update cache
        if violations:
            self._sensitive_data_cache[file_path] = violations
            self._stats['violations_found'] += len(violations)
            self._stats['data_classified'] += len(content)
    
    def _log_violation(self, policy_id: str, policy_name: str, severity: str, 
                      file_path: str, matched_text: str):
        """Log a DLP policy violation."""
        # Create a hash of the matched text for logging (to avoid logging actual sensitive data)
        text_hash = hashlib.sha256(matched_text.encode()).hexdigest()[:12]
        
        log_message = (
            f"DLP Violation - {policy_name} (Severity: {severity.upper()})\n"
            f"  File: {file_path}\n"
            f"  Matched: {matched_text[:50]}... [hash:{text_hash}]\n"
            f"  Policy: {policy_id}"
        )
        
        if severity == 'high':
            self.logger.error(log_message)
        elif severity == 'medium':
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
    
    def get_violations(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get all DLP violations."""
        violations = {}
        for file_path, matches in self._sensitive_data_cache.items():
            violations[file_path] = [
                {
                    'policy_id': policy_id,
                    'policy_name': self._policies.get(policy_id, {}).get('name', 'Unknown'),
                    'severity': self._policies.get(policy_id, {}).get('severity', 'medium'),
                    'matched_text': text[:100] + '...' if len(text) > 100 else text
                }
                for policy_id, text in matches
            ]
        return violations
    
    def add_policy(self, policy_id: str, policy: Dict[str, Any]) -> bool:
        """Add or update a DLP policy."""
        required_fields = ['name', 'description', 'severity', 'patterns', 'action']
        if not all(field in policy for field in required_fields):
            self.logger.error(f"Invalid policy: missing required fields")
            return False
            
        self._policies[policy_id] = policy
        self.logger.info(f"Updated policy: {policy_id}")
        return True
    
    def remove_policy(self, policy_id: str) -> bool:
        """Remove a DLP policy."""
        if policy_id in self._policies:
            del self._policies[policy_id]
            self.logger.info(f"Removed policy: {policy_id}")
            return True
        return False
    
    def status(self) -> Dict[str, Any]:
        """Get the current status of the DLP service."""
        status = super().status()
        status.update({
            'scan_active': self._scan_thread.is_alive() if self._scan_thread else False,
            'policies_loaded': len(self._policies),
            'stats': {
                'files_scanned': self._stats['files_scanned'],
                'violations_found': self._stats['violations_found'],
                'data_classified': self._stats['data_classified'],
                'last_scan_time': self._stats['last_scan_time']
            }
        })
        return status
