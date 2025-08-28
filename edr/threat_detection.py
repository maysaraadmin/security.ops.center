"""
Advanced Threat Detection for EDR
Implements fileless attack detection, LOTL techniques, and behavioral analysis.
"""
from typing import Dict, Any, List, Optional, Callable, Set
import logging
from datetime import datetime

class ThreatDetectionEngine:
    """Advanced threat detection engine for EDR."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the threat detection engine.
        
        Args:
            config: Configuration dictionary for the engine
        """
        self.config = config or {}
        self.logger = logging.getLogger("edr.threat_detection")
        self.detectors = []
        self.rules = {}
        self.running = False
        self._setup()
    
    def _setup(self) -> None:
        """Setup the detection engine with default configurations."""
        self.logger.info("Initializing Threat Detection Engine")
        # Initialize default detection rules
        self._load_default_rules()
    
    def _load_default_rules(self) -> None:
        """Load default detection rules."""
        self.rules = {
            'suspicious_processes': {
                'enabled': True,
                'processes': ['mimikatz.exe', 'procdump.exe', 'psexec.exe']
            },
            'suspicious_commands': {
                'enabled': True,
                'patterns': [
                    r'powershell.*-nop.*-w\s+hidden',
                    r'powershell.*-enc',
                    r'Invoke-Expression',
                    r'iex\s+\('
                ]
            }
        }
    
    def add_detector(self, detector: Any) -> bool:
        """Add a detector to the engine.
        
        Args:
            detector: Detector instance to add
            
        Returns:
            bool: True if added successfully
        """
        try:
            self.detectors.append(detector)
            self.logger.info(f"Added detector: {detector.__class__.__name__}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to add detector: {e}")
            return False
    
    def start(self) -> None:
        """Start the detection engine."""
        if self.running:
            self.logger.warning("Detection engine is already running")
            return
            
        self.running = True
        self.logger.info("Starting threat detection engine")
        
        # Start all detectors
        for detector in self.detectors:
            try:
                if hasattr(detector, 'start'):
                    detector.start()
            except Exception as e:
                self.logger.error(f"Error starting detector {detector.__class__.__name__}: {e}")
    
    def stop(self) -> None:
        """Stop the detection engine."""
        if not self.running:
            return
            
        self.logger.info("Stopping threat detection engine")
        self.running = False
        
        # Stop all detectors
        for detector in self.detectors:
            try:
                if hasattr(detector, 'stop'):
                    detector.stop()
            except Exception as e:
                self.logger.error(f"Error stopping detector {detector.__class__.__name__}: {e}")
    
    def analyze(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze an event for potential threats.
        
        Args:
            event: Event data to analyze
            
        Returns:
            List of detected threats (empty if none found)
        """
        threats = []
        
        # Check against all rules
        if self.rules['suspicious_processes']['enabled']:
            process_name = event.get('process_name', '').lower()
            for proc in self.rules['suspicious_processes']['processes']:
                if proc.lower() in process_name:
                    threats.append({
                        'type': 'suspicious_process',
                        'process': process_name,
                        'rule': 'Suspicious process execution',
                        'severity': 'high',
                        'timestamp': datetime.utcnow().isoformat()
                    })
        
        return threats

import os
import re
import json
import hashlib
import psutil
import threading
import time
from datetime import datetime
from typing import Dict, List, Set, Optional, Callable, Any
import winreg

class ThreatDetector:
    def __init__(self, alert_callback: Optional[Callable[[Dict[str, Any]], None]] = None):
        """Initialize the threat detector with detection rules and callbacks."""
        self.alert_callback = alert_callback
        self.running = False
        self.thread = None
        
        # Detection rules
        self.rules = self._load_detection_rules()
        
        # Known threats
        self.known_threats = {
            'hashes': set(),
            'ips': set(),
            'domains': set()
        }
        
        # Load threat intelligence
        self._load_threat_intel()
    
    def _load_detection_rules(self) -> Dict:
        """Load detection rules from file or use defaults."""
        default_rules = {
            'suspicious_processes': [
                'powershell.exe -nop -exec bypass',
                'cmd.exe /c',
                'regsvr32.exe /s',
                'mshta.exe',
                'certutil.exe -urlcache',
                'bitsadmin.exe /transfer'
            ],
            'suspicious_paths': [
                '\\temp\\',
                '\\appdata\\',
                '\\windows\\temp\\',
                '\\programdata\\',
                '\\users\\public\\'
            ],
            'suspicious_registry': [
                '\\Run(Once)?\\\\',
                '\\Winlogon\\\\Shell\\\\',
                '\\Policies\\\\System\\\\Scripts\\\\',
                '\\CurrentVersion\\\\Run(Once)?\\\\',
                '\\CurrentVersion\\\\RunServices(Once)?\\\\'
            ]
        }
        
        # Try to load from file
        try:
            if os.path.exists('detection_rules.json'):
                with open('detection_rules.json', 'r') as f:
                    return {**default_rules, **json.load(f)}
        except Exception as e:
            print(f"Error loading detection rules: {e}")
            
        return default_rules
    
    def _load_threat_intel(self):
        """Load threat intelligence data."""
        try:
            if os.path.exists('threat_intel.json'):
                with open('threat_intel.json', 'r') as f:
                    intel = json.load(f)
                    self.known_threats['hashes'].update(intel.get('hashes', []))
                    self.known_threats['ips'].update(intel.get('ips', []))
                    self.known_threats['domains'].update(intel.get('domains', []))
        except Exception as e:
            print(f"Error loading threat intel: {e}")
    
    def start(self):
        """Start the threat detection engine."""
        if self.running:
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._monitor, daemon=True)
        self.thread.start()
    
    def stop(self):
        """Stop the threat detection engine."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
    
    def _monitor(self):
        """Main monitoring loop."""
        while self.running:
            try:
                self._check_processes()
                self._check_network()
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                print(f"Monitoring error: {e}")
                time.sleep(10)
    
    def _check_processes(self):
        """Check running processes for suspicious activity."""
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
            try:
                self._analyze_process(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    
    def _analyze_process(self, proc):
        """Analyze a single process for threats."""
        try:
            info = proc.info
            pid = info['pid']
            cmdline = ' '.join(info['cmdline'] or [])
            
            # Check for suspicious command lines
            for pattern in self.rules['suspicious_processes']:
                if pattern.lower() in cmdline.lower():
                    self._raise_alert(
                        'suspicious_command',
                        f"Suspicious command line: {cmdline}",
                        'high',
                        process=info
                    )
            
            # Check process path
            try:
                exe = proc.exe()
                if any(path.lower() in exe.lower() for path in self.rules['suspicious_paths']):
                    self._raise_alert(
                        'suspicious_path',
                        f"Process running from suspicious location: {exe}",
                        'medium',
                        process=info
                    )
                
                # Check file hash
                file_hash = self._get_file_hash(exe)
                if file_hash in self.known_threats['hashes']:
                    self._raise_alert(
                        'known_malware',
                        f"Known malicious file hash: {file_hash}",
                        'critical',
                        process=info
                    )
                    
            except (psutil.AccessDenied, FileNotFoundError):
                pass
                
        except Exception as e:
            print(f"Error analyzing process {pid}: {e}")
    
    def _check_network(self):
        """Check network connections for suspicious activity."""
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    if not conn.raddr:
                        continue
                        
                    # Check known malicious IPs
                    if conn.raddr.ip in self.known_threats['ips']:
                        self._raise_alert(
                            'malicious_connection',
                            f"Connection to known malicious IP: {conn.raddr.ip}",
                            'high',
                            connection={
                                'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                                'remote': f"{conn.raddr.ip}:{conn.raddr.port}",
                                'status': conn.status,
                                'pid': conn.pid
                            }
                        )
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            print(f"Error checking network: {e}")
    
    def _get_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return ""
    
    def _raise_alert(self, alert_type: str, message: str, severity: str, **kwargs):
        """Raise an alert with the given details."""
        alert = {
            'timestamp': datetime.utcnow().isoformat(),
            'type': alert_type,
            'message': message,
            'severity': severity,
            **kwargs
        }
        
        if self.alert_callback:
            try:
                self.alert_callback(alert)
            except Exception as e:
                print(f"Error in alert callback: {e}")
        else:
            print(f"ALERT [{severity.upper()}] {message}")
