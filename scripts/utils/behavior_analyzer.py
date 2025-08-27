"""
Behavior Analyzer Module

This module provides behavioral analysis capabilities for the HIPS system,
detecting suspicious patterns in process behavior that may indicate malware
or other malicious activity.
"""

import os
import re
import time
import logging
import hashlib
import threading
from typing import Dict, List, Optional, Set, Tuple, Callable, Any, Pattern
from dataclasses import dataclass, field
from datetime import datetime
import json

import psutil

# Import platform-specific modules
try:
    import win32api
    import win32process
    import win32con
    import win32security
    WINDOWS = True
except ImportError:
    WINDOWS = False

# Import local modules
from ..utils.helpers import calculate_entropy, is_suspicious_file_extension

logger = logging.getLogger('hips.behavior_analyzer')

@dataclass
class BehaviorRule:
    """Defines a behavior rule for detecting suspicious activities."""
    name: str
    description: str
    severity: str  # 'low', 'medium', 'high', 'critical'
    condition: Callable[[Dict[str, Any]], bool]
    action: str  # 'alert', 'block', 'terminate', 'quarantine'
    tags: List[str] = field(default_factory=list)
    enabled: bool = True

@dataclass
class DetectedThreat:
    """Represents a detected behavioral threat."""
    rule_name: str
    description: str
    severity: str
    process_id: int
    process_name: str
    details: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    action_taken: str = ""

class BehaviorAnalyzer:
    """Analyzes process behavior to detect suspicious activities."""
    
    def __init__(
        self,
        config: Dict[str, Any],
        event_logger: 'EventLogger',
        response_engine: 'ResponseEngine'
    ):
        """Initialize the behavior analyzer.
        
        Args:
            config: Configuration dictionary
            event_logger: Event logger instance
            response_engine: Response engine for taking actions
        """
        self.config = config
        self.enabled = config.get('enabled', True)
        self.scan_interval = config.get('scan_interval', 10.0)
        self.rules: List[BehaviorRule] = []
        self.suspicious_activities = config.get('suspicious_activities', {})
        
        self.event_logger = event_logger
        self.response_engine = response_engine
        
        self.running = False
        self._stop_event = threading.Event()
        self._analyzer_thread = None
        self._process_cache: Dict[int, Dict] = {}
        self._detected_threats: Dict[int, List[DetectedThreat]] = {}
        self._lock = threading.RLock()
        
        # Initialize behavior rules
        self._init_behavior_rules()
        
        logger.info("Behavior analyzer initialized")
    
    def _init_behavior_rules(self) -> None:
        """Initialize default behavior rules."""
        # Memory process injection detection
        self.add_rule(BehaviorRule(
            name="memory_injection",
            description="Detects potential code injection into another process",
            severity="high",
            condition=self._check_memory_injection,
            action="terminate",
            tags=["injection", "malware"]
        ))
        
        # Suspicious process spawning
        self.add_rule(BehaviorRule(
            name="suspicious_process_spawn",
            description="Detects processes spawning from suspicious locations",
            severity="medium",
            condition=self._check_suspicious_process_spawn,
            action="alert",
            tags=["execution", "malware"]
        ))
        
        # High entropy process (potential packed/obfuscated code)
        self.add_rule(BehaviorRule(
            name="high_entropy_process",
            description="Detects processes with high entropy (potential packed/obfuscated code)",
            severity="medium",
            condition=self._check_high_entropy,
            action="alert",
            tags=["obfuscation", "malware"]
        ))
        
        # Suspicious command line arguments
        self.add_rule(BehaviorRule(
            name="suspicious_cmdline",
            description="Detects suspicious command line arguments",
            severity="low",
            condition=self._check_suspicious_cmdline,
            action="alert",
            tags=["execution", "malware"]
        ))
        
        # Unusual process behavior (e.g., process hollowing)
        self.add_rule(BehaviorRule(
            name="process_hollowing",
            description="Detects process hollowing techniques",
            severity="critical",
            condition=self._check_process_hollowing,
            action="terminate",
            tags=["injection", "malware"]
        ))
        
        # Load additional rules from config if any
        self._load_rules_from_config()
    
    def _load_rules_from_config(self) -> None:
        """Load additional behavior rules from configuration."""
        for rule_name, rule_config in self.suspicious_activities.items():
            if not rule_config.get('enabled', True):
                continue
                
            try:
                condition_func = self._create_condition_from_config(rule_config)
                if not condition_func:
                    continue
                    
                self.add_rule(BehaviorRule(
                    name=rule_name,
                    description=rule_config.get('description', 'Custom behavior rule'),
                    severity=rule_config.get('severity', 'medium'),
                    condition=condition_func,
                    action=rule_config.get('action', 'alert'),
                    tags=rule_config.get('tags', []),
                    enabled=True
                ))
                logger.debug(f"Loaded custom behavior rule: {rule_name}")
                
            except Exception as e:
                logger.error(f"Error loading behavior rule {rule_name}: {e}", exc_info=True)
    
    def _create_condition_from_config(self, rule_config: Dict) -> Optional[Callable[[Dict], bool]]:
        """Create a condition function from configuration."""
        rule_type = rule_config.get('type')
        
        if rule_type == 'process_name':
            patterns = rule_config.get('patterns', [])
            if not patterns:
                return None
                
            def condition(process_info: Dict) -> bool:
                return any(re.search(p, process_info.get('name', ''), re.IGNORECASE) 
                         for p in patterns)
            return condition
            
        elif rule_type == 'cmdline':
            patterns = rule_config.get('patterns', [])
            if not patterns:
                return None
                
            def condition(process_info: Dict) -> bool:
                cmdline = ' '.join(process_info.get('cmdline', []))
                return any(re.search(p, cmdline, re.IGNORECASE) for p in patterns)
            return condition
            
        elif rule_type == 'file_access':
            paths = rule_config.get('paths', [])
            access_types = rule_config.get('access_types', ['read', 'write', 'execute'])
            
            def condition(process_info: Dict) -> bool:
                # This would need integration with a file system monitor
                return False  # Placeholder
            return condition
            
        elif rule_type == 'registry_access':
            if not WINDOWS:
                return None
                
            keys = rule_config.get('keys', [])
            access_types = rule_config.get('access_types', ['read', 'write'])
            
            def condition(process_info: Dict) -> bool:
                # This would need integration with a registry monitor
                return False  # Placeholder
            return condition
            
        return None
    
    def add_rule(self, rule: BehaviorRule) -> None:
        """Add a behavior rule to the analyzer."""
        with self._lock:
            self.rules.append(rule)
    
    def remove_rule(self, rule_name: str) -> bool:
        """Remove a behavior rule by name."""
        with self._lock:
            for i, rule in enumerate(self.rules):
                if rule.name == rule_name:
                    del self.rules[i]
                    return True
        return False
    
    def enable_rule(self, rule_name: str) -> bool:
        """Enable a behavior rule by name."""
        with self._lock:
            for rule in self.rules:
                if rule.name == rule_name:
                    rule.enabled = True
                    return True
        return False
    
    def disable_rule(self, rule_name: str) -> bool:
        """Disable a behavior rule by name."""
        with self._lock:
            for rule in self.rules:
                if rule.name == rule_name:
                    rule.enabled = False
                    return True
        return False
    
    def start(self) -> None:
        """Start the behavior analyzer."""
        if not self.enabled:
            logger.info("Behavior analyzer is disabled in configuration")
            return
            
        if self.running:
            logger.warning("Behavior analyzer is already running")
            return
            
        logger.info("Starting behavior analyzer...")
        self.running = True
        self._stop_event.clear()
        self._analyzer_thread = threading.Thread(
            target=self._analyzer_loop,
            name="BehaviorAnalyzer",
            daemon=True
        )
        self._analyzer_thread.start()
        logger.info("Behavior analyzer started")
    
    def stop(self) -> None:
        """Stop the behavior analyzer."""
        if not self.running:
            return
            
        logger.info("Stopping behavior analyzer...")
        self.running = False
        self._stop_event.set()
        
        if self._analyzer_thread:
            self._analyzer_thread.join(timeout=5.0)
            if self._analyzer_thread.is_alive():
                logger.warning("Behavior analyzer thread did not stop gracefully")
            self._analyzer_thread = None
        
        logger.info("Behavior analyzer stopped")
    
    def _analyzer_loop(self) -> None:
        """Main analysis loop."""
        logger.debug("Behavior analyzer loop started")
        
        while not self._stop_event.is_set():
            try:
                start_time = time.monotonic()
                
                # Analyze running processes
                self._analyze_processes()
                
                # Check for threats that need follow-up
                self._check_detected_threats()
                
                # Sleep for the remaining interval
                elapsed = time.monotonic() - start_time
                sleep_time = max(0, self.scan_interval - elapsed)
                self._stop_event.wait(timeout=sleep_time)
                
            except Exception as e:
                logger.error(f"Error in behavior analyzer loop: {e}", exc_info=True)
                time.sleep(1)  # Prevent tight loop on errors
    
    def _analyze_processes(self) -> None:
        """Analyze running processes for suspicious behavior."""
        try:
            current_pids = set()
            
            # Get all running processes
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'create_time']):
                try:
                    pid = proc.info['pid']
                    current_pids.add(pid)
                    
                    # Skip if we've already analyzed this process recently
                    if pid in self._process_cache:
                        last_check = self._process_cache[pid].get('last_check', 0)
                        if time.time() - last_check < 60:  # Check at most once per minute
                            continue
                    
                    # Get process info
                    process_info = self._get_process_info(proc)
                    if not process_info:
                        continue
                    
                    # Check against behavior rules
                    self._check_behavior_rules(process_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as e:
                    logger.error(f"Error analyzing process {proc.pid}: {e}", exc_info=True)
            
            # Clean up old process cache entries
            dead_pids = set(self._process_cache.keys()) - current_pids
            for pid in dead_pids:
                self._process_cache.pop(pid, None)
                
        except Exception as e:
            logger.error(f"Error analyzing processes: {e}", exc_info=True)
    
    def _get_process_info(self, proc: psutil.Process) -> Optional[Dict]:
        """Get process information for behavior analysis."""
        try:
            with proc.oneshot():
                pid = proc.pid
                ppid = proc.ppid()
                name = proc.name()
                exe = proc.exe()
                cmdline = proc.cmdline()
                username = proc.username()
                create_time = proc.create_time()
                
                # Get memory info
                try:
                    mem_info = proc.memory_info()
                    mem_rss = mem_info.rss
                    mem_vms = mem_info.vms
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    mem_rss = mem_vms = 0
                
                # Get CPU usage
                try:
                    cpu_percent = proc.cpu_percent(interval=0.1)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    cpu_percent = 0.0
                
                # Get open files and connections
                try:
                    open_files = [f.path for f in proc.open_files()]
                except (psutil.AccessDenied, psutil.AccessDenied):
                    open_files = []
                
                try:
                    connections = [
                        f"{c.laddr.ip}:{c.laddr.port} -> {c.raddr.ip}:{c.raddr.port}" 
                        for c in proc.connections() 
                        if c.status == 'ESTABLISHED'
                    ]
                except (psutil.AccessDenied, psutil.AccessDenied):
                    connections = []
                
                # Calculate command line entropy
                cmdline_str = ' '.join(cmdline) if cmdline else ""
                cmdline_entropy = calculate_entropy(cmdline_str)
                
                # Check if process is signed (Windows)
                is_signed = False
                signer = ""
                
                if WINDOWS and exe and os.path.exists(exe):
                    try:
                        # This is a simplified check - in a real implementation, 
                        # you'd use the Windows CryptoAPI or a library like python-certvalidator
                        is_signed = os.path.getsize(exe) > 0  # Placeholder
                        signer = "Microsoft" if "windows" in exe.lower() else "Unknown"
                    except Exception:
                        pass
                
                # Create process info dictionary
                process_info = {
                    'pid': pid,
                    'ppid': ppid,
                    'name': name,
                    'exe': exe,
                    'cmdline': cmdline,
                    'username': username,
                    'create_time': create_time,
                    'memory_rss': mem_rss,
                    'memory_vms': mem_vms,
                    'cpu_percent': cpu_percent,
                    'open_files': open_files,
                    'connections': connections,
                    'cmdline_entropy': cmdline_entropy,
                    'is_signed': is_signed,
                    'signer': signer,
                    'last_check': time.time()
                }
                
                # Cache the process info
                self._process_cache[pid] = process_info
                
                return process_info
                
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        except Exception as e:
            logger.error(f"Error getting process info for {proc.pid}: {e}", exc_info=True)
            return None
    
    def _check_behavior_rules(self, process_info: Dict) -> None:
        """Check process against all behavior rules."""
        with self._lock:
            for rule in self.rules:
                if not rule.enabled:
                    continue
                    
                try:
                    if rule.condition(process_info):
                        self._handle_rule_match(rule, process_info)
                except Exception as e:
                    logger.error(
                        f"Error in behavior rule '{rule.name}': {e}", 
                        exc_info=True
                    )
    
    def _handle_rule_match(
        self, 
        rule: BehaviorRule, 
        process_info: Dict
    ) -> None:
        """Handle a rule match for a process."""
        # Create threat details
        threat = DetectedThreat(
            rule_name=rule.name,
            description=rule.description,
            severity=rule.severity,
            process_id=process_info['pid'],
            process_name=process_info['name'],
            details={
                'exe': process_info.get('exe', ''),
                'cmdline': process_info.get('cmdline', []),
                'username': process_info.get('username', ''),
                'memory_usage': f"{process_info.get('memory_rss', 0) / 1024 / 1024:.2f} MB"
            }
        )
        
        # Log the threat
        self._log_threat(threat)
        
        # Take action based on rule
        action_taken = False
        
        if rule.action == 'terminate':
            if self._terminate_process(process_info['pid']):
                threat.action_taken = "process_terminated"
                action_taken = True
        elif rule.action == 'quarantine' and process_info.get('exe'):
            if self.response_engine.quarantine_file(process_info['exe']):
                threat.action_taken = "file_quarantined"
                if self._terminate_process(process_info['pid']):
                    threat.action_taken += ", process_terminated"
                action_taken = True
        elif rule.action == 'block':
            # This would involve blocking network access or other resources
            threat.action_taken = "access_blocked"
            action_taken = True
        
        # Always alert, even if no action was taken
        if not action_taken and rule.action == 'alert':
            threat.action_taken = "alerted"
            action_taken = True
        
        # Store the threat for follow-up
        with self._lock:
            if process_info['pid'] not in self._detected_threats:
                self._detected_threats[process_info['pid']] = []
            self._detected_threats[process_info['pid']].append(threat)
    
    def _check_detected_threats(self) -> None:
        """Check for threats that need follow-up actions."""
        current_time = time.time()
        to_remove = []
        
        with self._lock:
            for pid, threats in list(self._detected_threats.items()):
                # Remove old threats (older than 1 hour)
                recent_threats = [
                    t for t in threats 
                    if current_time - t.timestamp < 3600
                ]
                
                if not recent_threats:
                    to_remove.append(pid)
                else:
                    self._detected_threats[pid] = recent_threats
            
            # Clean up old entries
            for pid in to_remove:
                if pid in self._detected_threats:
                    del self._detected_threats[pid]
    
    def _terminate_process(self, pid: int) -> bool:
        """Terminate a process."""
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            logger.warning(f"Terminated suspicious process {pid}")
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
        except Exception as e:
            logger.error(f"Failed to terminate process {pid}: {e}")
            return False
    
    def _log_threat(self, threat: DetectedThreat) -> None:
        """Log a detected threat."""
        event_data = {
            'event_type': 'behavior_threat',
            'rule_name': threat.rule_name,
            'description': threat.description,
            'severity': threat.severity,
            'process_id': threat.process_id,
            'process_name': threat.process_name,
            'details': threat.details,
            'timestamp': threat.timestamp,
            'action_taken': threat.action_taken
        }
        
        self.event_logger.log('behavior', event_data)
    
    # Behavior rule condition functions
    
    def _check_memory_injection(self, process_info: Dict) -> bool:
        """Check for potential code injection into another process."""
        if not WINDOWS:
            return False
            
        try:
            # Check for suspicious API calls or memory operations
            # This is a simplified check - in a real implementation, you'd use API hooking
            suspicious_apis = [
                'WriteProcessMemory', 'CreateRemoteThread', 'VirtualAllocEx',
                'NtCreateThreadEx', 'QueueUserAPC', 'SetWindowsHookEx'
            ]
            
            # Check if process is performing suspicious memory operations
            # This would require integration with API monitoring
            
            # For now, use a simple heuristic based on process behavior
            if (process_info.get('memory_rss', 0) > 500 * 1024 * 1024 and  # High memory usage
                len(process_info.get('connections', [])) > 10 and           # Many connections
                process_info.get('cmdline_entropy', 0) > 6.0):              # High entropy in cmdline
                return True
                
        except Exception as e:
            logger.debug(f"Error checking for memory injection: {e}")
            
        return False
    
    def _check_suspicious_process_spawn(self, process_info: Dict) -> bool:
        """Check for processes spawned from suspicious locations."""
        exe = process_info.get('exe', '').lower()
        
        # Check common suspicious locations
        suspicious_paths = [
            '/tmp/', '/dev/shm/', '/var/tmp/', '/tmp/.X11-unix/',
            'appdata\\local\\temp\\', 'appdata\\roaming\\',
            'c:\\windows\\tasks\\', 'c:\\windows\\temp\\'
        ]
        
        if any(p in exe for p in suspicious_paths):
            return True
            
        # Check for double extensions (e.g., document.pdf.exe)
        if re.search(r'\.[a-z0-9]{3,4}\.[a-z]{2,4}$', exe, re.IGNORECASE):
            return True
            
        return False
    
    def _check_high_entropy(self, process_info: Dict) -> bool:
        """Check for high entropy in process memory or command line."""
        # Check command line entropy
        if process_info.get('cmdline_entropy', 0) > 6.5:
            return True
            
        # Check for base64-encoded strings in command line
        cmdline = ' '.join(process_info.get('cmdline', []))
        if re.search(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', cmdline):
            return True
            
        return False
    
    def _check_suspicious_cmdline(self, process_info: Dict) -> bool:
        """Check for suspicious command line arguments."""
        if not process_info.get('cmdline'):
            return False
            
        cmdline = ' '.join(process_info['cmdline']).lower()
        
        # Check for common suspicious patterns
        suspicious_patterns = [
            r'-enc\b',                      # PowerShell encoded command
            r'iex\b',                       # Invoke-Expression
            r'invoke-',                     # PowerShell invocation
            r'powershell.*-nop.*-w\s+hidden', # Hidden PowerShell window
            r'powershell.*-e\s+',           # Encoded command
            r'powershell.*-enc\s+',         # Encoded command
            r'powershell.*-c\s+"\$',       # Inline script
            r'certutil.*-decode',            # CertUtil for decoding
            r'bitsadmin.*/transfer',        # BITSAdmin download
            r'reg\s+add\b.*/f',            # Silent registry modifications
            r'net\s+user\s+\w+\s+\S+\s+/add',  # User creation
            r'schtasks.*/create',            # Scheduled task creation
            r'wmic.*process.*call',          # WMI process creation
            r'vssadmin\s+delete\s+shadows', # Volume shadow copy deletion
            r'wevtutil\s+cl\s+',           # Event log clearing
            r'fsutil\s+usn\s+deletejournal', # USN journal deletion
            r'bcdedit\s+/set\s+\{.*\}\s+recoveryenabled\s+no', # Disable recovery
            r'wmic\s+shadowcopy\s+delete', # Shadow copy deletion via WMI
            r'vssadmin\s+resize\s+shadowstorage' # Resize shadow storage
        ]
        
        return any(re.search(p, cmdline) for p in suspicious_patterns)
    
    def _check_process_hollowing(self, process_info: Dict) -> bool:
        """Detect process hollowing techniques."""
        if not WINDOWS:
            return False
            
        try:
            # Check for signs of process hollowing:
            # 1. Process with a window station but no visible window
            # 2. Process with threads in a suspended state
            # 3. Process with memory regions that are both writable and executable
            
            # This is a simplified check - in a real implementation, you'd use 
            # more sophisticated detection techniques
            
            pid = process_info['pid']
            proc = psutil.Process(pid)
            
            # Check for suspended threads
            try:
                if WINDOWS:
                    import ctypes
                    from ctypes import wintypes
                    
                    kernel32 = ctypes.windll.kernel32
                    
                    # Get process handle
                    PROCESS_QUERY_INFORMATION = 0x0400
                    PROCESS_VM_READ = 0x0010
                    h_process = kernel32.OpenProcess(
                        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                        False,
                        pid
                    )
                    
                    if h_process:
                        # Check for suspended threads
                        class THREADENTRY32(ctypes.Structure):
                            _fields_ = [
                                ('dwSize', wintypes.DWORD),
                                ('cntUsage', wintypes.DWORD),
                                ('th32ThreadID', wintypes.DWORD),
                                ('th32OwnerProcessID', wintypes.DWORD),
                                ('tpBasePri', wintypes.LONG),
                                ('tpDeltaPri', wintypes.LONG),
                                ('dwFlags', wintypes.DWORD)
                            ]
                        
                        # Create snapshot of all threads in the system
                        TH32CS_SNAPTHREAD = 0x00000004
                        h_snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
                        
                        if h_snapshot != -1:
                            try:
                                thread_entry = THREADENTRY32()
                                thread_entry.dwSize = ctypes.sizeof(THREADENTRY32)
                                
                                if kernel32.Thread32First(h_snapshot, ctypes.byref(thread_entry)):
                                    while True:
                                        if thread_entry.th32OwnerProcessID == pid:
                                            # Open the thread
                                            THREAD_SUSPEND_RESUME = 0x0002
                                            h_thread = kernel32.OpenThread(
                                                THREAD_SUSPEND_RESUME,
                                                False,
                                                thread_entry.th32ThreadID
                                            )
                                            
                                            if h_thread:
                                                # Check if thread is suspended
                                                suspend_count = kernel32.SuspendThread(h_thread)
                                                if suspend_count > 0:
                                                    # Thread was already suspended
                                                    kernel32.ResumeThread(h_thread)  # Resume it
                                                    kernel32.CloseHandle(h_thread)
                                                    
                                                    # Check if this is suspicious
                                                    if suspend_count == 1:  # Suspended once
                                                        # Look for other indicators of process hollowing
                                                        try:
                                                            # Check for RWX memory regions
                                                            # This is a simplified check
                                                            mem_maps = proc.memory_maps()
                                                            for m in mem_maps:
                                                                if 'x' in m.perms and 'w' in m.perms:
                                                                    return True
                                                        except (psutil.AccessDenied, AttributeError):
                                                            pass
                                                        
                                                        return False  # Not enough evidence
                                                else:
                                                    kernel32.ResumeThread(h_thread)  # Ensure it's running
                                                    kernel32.CloseHandle(h_thread)
                                            
                                        # Move to next thread
                                        thread_entry = THREADENTRY32()
                                        thread_entry.dwSize = ctypes.sizeof(THREADENTRY32)
                                        if not kernel32.Thread32Next(h_snapshot, ctypes.byref(thread_entry)):
                                            break
                            finally:
                                kernel32.CloseHandle(h_snapshot)
                        
                        kernel32.CloseHandle(h_process)
            except Exception as e:
                logger.debug(f"Error checking for suspended threads: {e}")
                
        except Exception as e:
            logger.error(f"Error in process hollowing detection: {e}", exc_info=True)
            
        return False

    # Public API methods
    
    def get_detected_threats(self) -> List[Dict]:
        """Get a list of all detected threats."""
        with self._lock:
            return [
                {
                    'rule_name': t.rule_name,
                    'description': t.description,
                    'severity': t.severity,
                    'process_id': t.process_id,
                    'process_name': t.process_name,
                    'timestamp': t.timestamp,
                    'action_taken': t.action_taken,
                    'details': t.details
                }
                for threats in self._detected_threats.values()
                for t in threats
            ]
    
    def get_process_behavior(self, pid: int) -> Dict:
        """Get behavior information for a specific process."""
        with self._lock:
            # Get process info
            process_info = self._process_cache.get(pid, {})
            
            # Get related threats
            threats = [
                {
                    'rule_name': t.rule_name,
                    'description': t.description,
                    'severity': t.severity,
                    'timestamp': t.timestamp,
                    'action_taken': t.action_taken
                }
                for t in self._detected_threats.get(pid, [])
            ]
            
            return {
                'process_info': process_info,
                'threats': threats,
                'behavior_score': self._calculate_behavior_score(pid)
            }
    
    def _calculate_behavior_score(self, pid: int) -> float:
        """Calculate a behavior risk score for a process (0-100)."""
        score = 0.0
        
        # Get process info and threats
        with self._lock:
            process_info = self._process_cache.get(pid, {})
            threats = self._detected_threats.get(pid, [])
        
        # Add points based on threats
        for threat in threats:
            if threat.severity == 'critical':
                score += 40
            elif threat.severity == 'high':
                score += 25
            elif threat.severity == 'medium':
                score += 10
            else:
                score += 5
        
        # Add points based on process behavior
        if process_info.get('cmdline_entropy', 0) > 6.0:
            score += 10
            
        if not process_info.get('is_signed', False):
            score += 5
            
        if len(process_info.get('connections', [])) > 10:
            score += 10
            
        if process_info.get('memory_rss', 0) > 500 * 1024 * 1024:  # > 500MB
            score += 10
        
        # Cap the score at 100
        return min(100.0, score)
