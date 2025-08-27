"""
Behavioral Threat Detection for EDR.
Detects fileless attacks, living-off-the-land (LOTL) techniques, and zero-day exploits
using behavioral analysis and anomaly detection.
"""
import os
import re
import json
import logging
import hashlib
from typing import Dict, Any, List, Set, Optional, Tuple, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import psutil

# Known suspicious patterns and indicators
SUSPICIOUS_PROCESS_NAMES = {
    'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe',
    'rundll32.exe', 'regsvr32.exe', 'msbuild.exe', 'installutil.exe', 'msxsl.exe'
}

SUSPICIOUS_CMDLINE_PATTERNS = [
    r'-nop\b', r'-noni\b', r'-w\s+hidden\b', r'-enc\b', r'-e\s+[A-Za-z0-9+/=]+',
    r'Invoke-Expression', r'DownloadString', r'WebClient', r'Net.WebClient',
    r'Start-Process', r'New-Object', r'FromBase64String', r'iex\b'
]

@dataclass
class ThreatFinding:
    """Represents a detected threat finding."""
    timestamp: str
    threat_type: str
    severity: str
    process_name: str
    process_id: int
    command_line: str
    indicators: List[str]
    confidence: float
    details: Dict[str, Any]

class BehavioralThreatDetector:
    """
    Detects advanced threats using behavioral analysis and anomaly detection.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the threat detector with configuration."""
        self.config = config
        self.logger = logging.getLogger('edr.threat_detector')
        self.suspicious_activities: Dict[int, List[Dict]] = {}
        self.known_hashes: Set[str] = set()
        self._load_known_hashes()
        
        # Configure detection sensitivity
        self.suspicious_score_threshold = float(config.get('suspicious_score_threshold', 0.7))
        self.malicious_score_threshold = float(config.get('malicious_score_threshold', 0.9))
        
        # Initialize detection rules
        self.detection_rules = [
            self._detect_suspicious_process_creation,
            self._detect_obfuscated_commands,
            self._detect_process_hollowing,
            self._detect_suspicious_child_processes,
            self._detect_credential_dumping,
            self._detect_suspicious_network_connections,
        ]
    
    def analyze_process(self, process_info: Dict[str, Any]) -> Optional[ThreatFinding]:
        """
        Analyze a process for potential threats.
        Returns a ThreatFinding if a threat is detected, None otherwise.
        """
        findings = []
        
        # Run all detection rules
        for rule in self.detection_rules:
            try:
                finding = rule(process_info)
                if finding:
                    findings.append(finding)
            except Exception as e:
                self.logger.error(f"Error in detection rule {rule.__name__}: {e}")
        
        # If we have findings, return the highest severity one
        if findings:
            # Sort by severity (high to low) and confidence (high to low)
            findings.sort(key=lambda x: (
                self._severity_to_score(x.severity),
                x.confidence
            ), reverse=True)
            
            return findings[0]
        
        return None
    
    def _severity_to_score(self, severity: str) -> int:
        """Convert severity string to a numerical score for comparison."""
        severity_levels = {
            'info': 1,
            'low': 2,
            'medium': 3,
            'high': 4,
            'critical': 5
        }
        return severity_levels.get(severity.lower(), 0)
    
    def _detect_suspicious_process_creation(self, process_info: Dict[str, Any]) -> Optional[ThreatFinding]:
        """Detect suspicious process creation patterns."""
        indicators = []
        score = 0.0
        
        # Check process name against known suspicious processes
        process_name = process_info.get('name', '').lower()
        if process_name in SUSPICIOUS_PROCESS_NAMES:
            indicators.append(f"Suspicious process name: {process_name}")
            score += 0.3
        
        # Check command line for suspicious patterns
        cmdline = process_info.get('command_line', '').lower()
        for pattern in SUSPICIOUS_CMDLINE_PATTERNS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                indicators.append(f"Suspicious command line pattern: {pattern}")
                score += 0.4
        
        # Check for process injection patterns
        if any(inj in cmdline for inj in ['CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx']):
            indicators.append("Potential process injection detected")
            score += 0.5
        
        if score >= self.malicious_score_threshold:
            return ThreatFinding(
                timestamp=datetime.utcnow().isoformat() + 'Z',
                threat_type="MaliciousProcessCreation",
                severity="high",
                process_name=process_name,
                process_id=process_info.get('pid', 0),
                command_line=cmdline,
                indicators=indicators,
                confidence=min(score, 1.0),
                details={
                    'parent_process': process_info.get('parent_name', ''),
                    'integrity_level': process_info.get('integrity_level', '')
                }
            )
        elif score >= self.suspicious_score_threshold:
            return ThreatFinding(
                timestamp=datetime.utcnow().isoformat() + 'Z',
                threat_type="SuspiciousProcessCreation",
                severity="medium",
                process_name=process_name,
                process_id=process_info.get('pid', 0),
                command_line=cmdline,
                indicators=indicators,
                confidence=score,
                details={
                    'parent_process': process_info.get('parent_name', '')
                }
            )
        
        return None
    
    def _detect_obfuscated_commands(self, process_info: Dict[str, Any]) -> Optional[ThreatFinding]:
        """Detect obfuscated or encoded commands."""
        cmdline = process_info.get('command_line', '')
        indicators = []
        
        # Check for base64 encoded commands
        if re.search(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', cmdline):
            indicators.append("Potential base64 encoded command detected")
        
        # Check for hex encoded commands
        if re.search(r'(?:\b[0-9a-fA-F]{2}\s*){10,}', cmdline):
            indicators.append("Potential hex encoded command detected")
        
        # Check for long command lines with many special characters
        if len(cmdline) > 1000 and sum(1 for c in cmdline if not c.isalnum()) > len(cmdline) * 0.3:
            indicators.append("Suspiciously long command with many special characters")
        
        if indicators:
            return ThreatFinding(
                timestamp=datetime.utcnow().isoformat() + 'Z',
                threat_type="ObfuscatedCommand",
                severity="high",
                process_name=process_info.get('name', ''),
                process_id=process_info.get('pid', 0),
                command_line=cmdline[:500] + ('...' if len(cmdline) > 500 else ''),
                indicators=indicators,
                confidence=0.8,
                details={
                    'command_length': len(cmdline),
                    'parent_process': process_info.get('parent_name', '')
                }
            )
        
        return None
    
    def _detect_process_hollowing(self, process_info: Dict[str, Any]) -> Optional[ThreatFinding]:
        """Detect potential process hollowing techniques."""
        # This is a simplified example - in a real implementation, you would
        # check for mismatches between the PE header and memory, unusual
        # memory regions, etc.
        
        process_name = process_info.get('name', '').lower()
        parent_name = process_info.get('parent_name', '').lower()
        
        # Suspicious parent-child process relationships
        suspicious_pairs = [
            ('services.exe', 'cmd.exe'),
            ('svchost.exe', 'regsvr32.exe'),
            ('explorer.exe', 'powershell.exe'),
            ('msiexec.exe', 'cmd.exe')
        ]
        
        for parent, child in suspicious_pairs:
            if parent in parent_name and child in process_name:
                return ThreatFinding(
                    timestamp=datetime.utcnow().isoformat() + 'Z',
                    threat_type="PotentialProcessHollowing",
                    severity="high",
                    process_name=process_name,
                    process_id=process_info.get('pid', 0),
                    command_line=process_info.get('command_line', ''),
                    indicators=[
                        f"Suspicious parent-child process relationship: {parent} -> {child}",
                        "This could indicate process hollowing or other code injection techniques"
                    ],
                    confidence=0.7,
                    details={
                        'parent_process': parent_name,
                        'process_path': process_info.get('path', '')
                    }
                )
        
        return None
    
    def _detect_suspicious_child_processes(self, process_info: Dict[str, Any]) -> Optional[ThreatFinding]:
        """Detect suspicious child process relationships."""
        # This would be implemented to monitor for processes spawning unexpected children
        # For example, word.exe spawning cmd.exe or powershell.exe
        return None
    
    def _detect_credential_dumping(self, process_info: Dict[str, Any]) -> Optional[ThreatFinding]:
        """Detect potential credential dumping activities."""
        # This would check for processes accessing LSASS memory, registry hives, etc.
        return None
    
    def _detect_suspicious_network_connections(self, process_info: Dict[str, Any]) -> Optional[ThreatFinding]:
        """Detect suspicious network connection patterns."""
        # This would analyze network connections for C2 patterns, suspicious domains, etc.
        return None
    
    def _load_known_hashes(self) -> None:
        """Load known good file hashes from disk."""
        try:
            # In a real implementation, load from a database or file
            pass
        except Exception as e:
            self.logger.error(f"Error loading known hashes: {e}")
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            self.logger.error(f"Error calculating hash for {file_path}: {e}")
            return ""

def create_threat_detector(config: Dict[str, Any] = None) -> BehavioralThreatDetector:
    """Factory function to create a threat detector instance."""
    if config is None:
        config = {}
    return BehavioralThreatDetector(config)
