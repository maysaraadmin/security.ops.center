"""
Host-based Intrusion Prevention System (HIPS) - Process Monitor

Provides real-time monitoring and protection against malicious processes,
including detection of code injection, privilege escalation, and other
suspicious activities.
"""

import os
import sys
import time
import os
import time
import hashlib
import logging
import platform
import threading
import re
import json
import zlib
from collections import deque, defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Callable, Set, Any, Union, Deque, Tuple
from datetime import datetime, timedelta
import psutil

# For Windows-specific checks
if platform.system() == 'Windows':
    import win32api
    import win32con
    import win32process
    import win32security
    from win32com.client import GetObject

# Behavioral analysis thresholds (in seconds)
BEHAVIOR_WINDOW = 300  # 5 minutes
SUSPICIOUS_ACTIVITY_THRESHOLD = 10  # Number of suspicious activities in window

class ProcessState(Enum):
    """Possible states of a monitored process."""
    NORMAL = auto()
    SUSPICIOUS = auto()
    MALICIOUS = auto()
    WHITELISTED = auto()

class ThreatType(Enum):
    """Types of process-related threats."""
    CODE_INJECTION = auto()
    PRIVILEGE_ESCALATION = auto()
    SHELLCODE_EXECUTION = auto()
    PROCESS_HOLLOWING = auto()
    PROCESS_DOUBLE_PID = auto()
    SUSPICIOUS_ACTIVITY = auto()
    UNKNOWN_BINARY = auto()
    REPLACED_BINARY = auto()

@dataclass
class ProcessInfo:
    """Information about a running process."""
    pid: int
    name: str
    exe: str
    cmdline: List[str]
    username: str
    create_time: float
    parent_pid: int
    state: ProcessState = ProcessState.NORMAL
    threat_score: int = 0
    detected_threats: List[ThreatType] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ThreatAlert:
    """Represents a detected security threat."""
    threat_type: ThreatType
    description: str
    severity: str  # 'low', 'medium', 'high', 'critical'
    process: ProcessInfo
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

class BehavioralAnalyzer:
    """Analyzes process behavior for anomalies and fileless attack patterns."""
    
    def __init__(self):
        self.process_activities = defaultdict(lambda: {
            'command_execs': deque(maxlen=100),
            'network_connections': deque(maxlen=50),
            'file_operations': deque(maxlen=100),
            'registry_access': deque(maxlen=50) if platform.system() == 'Windows' else None,
            'last_alert': 0
        })
        
        # Suspicious patterns for command-line analysis
        self.suspicious_patterns = {
            'powershell': [
                r'-[eE]xecutionpolicy\s+bypass',
                r'-[eE]nc\s+',
                r'-[eE]ncodedcommand\s+',
                r'iex\s*\\(|\s)new-object\s+net\\.webclient\\)\\.downloadstring',
                r'invoke-expression',
                r'new-object\\s+system\\..*\\.net\\.webclient',
                r'downloadstring\\s*\\('
            ],
            'wmic': [
                r'process\\s+call\\s+create',
                r'shadowcopy',
                r'shadowstorage'
            ],
            'cmd': [
                r'\\^echo\\s+[A-Za-z0-9+/]{100,}={0,2}\\s+\\|\\s*[a-z0-9]+\\.exe',
                r'certutil\\s+-decode',
                r'bitsadmin\\s+/transfer',
                r'reg\\s+(add|delete|save)',
                r'schtasks\\s+/create',
                r'wmic\\s+process'
            ]
        }
    
    def analyze_command_line(self, process_info: 'ProcessInfo') -> List[str]:
        """Analyze command line for suspicious patterns."""
        if not process_info.cmdline:
            return []
            
        cmdline = ' '.join(process_info.cmdline).lower()
        detected = []
        
        # Check for suspicious patterns in command line
        for tool, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                if re.search(pattern, cmdline, re.IGNORECASE):
                    detected.append(f"Suspicious {tool} pattern: {pattern}")
        
        return detected
    
    def analyze_behavior(self, process_info: 'ProcessInfo') -> List[str]:
        """Analyze process behavior for anomalies."""
        findings = []
        pid = process_info.pid
        
        # Record this activity
        self.process_activities[pid]['command_execs'].append({
            'time': time.time(),
            'cmdline': process_info.cmdline,
            'exe': process_info.exe
        })
        
        # Check for suspicious patterns in command line
        findings.extend(self.analyze_command_line(process_info))
        
        # Check for process injection
        if self._check_process_injection(process_info):
            findings.append("Possible process injection detected")
        
        # Check for memory anomalies
        if self._check_memory_anomalies(process_info):
            findings.append("Suspicious memory usage pattern detected")
        
        return findings
    
    def _check_process_injection(self, process_info: 'ProcessInfo') -> bool:
        """Check for signs of process injection."""
        try:
            process = psutil.Process(process_info.pid)
            
            # Check for RWX memory regions (common in process injection)
            if platform.system() == 'Windows':
                return self._check_windows_injection(process)
            else:
                return self._check_linux_injection(process)
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
    
    def _check_windows_injection(self, process) -> bool:
        """Windows-specific injection detection."""
        try:
            from win32process import EnumProcessModules, GetModuleFileNameEx
            
            # Get list of loaded modules
            modules = EnumProcessModules(process.pid)
            for module in modules:
                try:
                    module_name = GetModuleFileNameEx(process.pid, module).lower()
                    if any(x in module_name for x in ['inject', 'hook', 'reflective']):
                        return True
                except:
                    continue
                    
        except Exception as e:
            logger.debug(f"Error checking Windows injection: {e}")
            
        return False
    
    def _check_linux_injection(self, process) -> bool:
        """Linux-specific injection detection."""
        try:
            # Check for suspicious memory mappings
            maps_path = f"/proc/{process.pid}/maps"
            if os.path.exists(maps_path):
                with open(maps_path, 'r') as f:
                    for line in f:
                        if 'rwxp' in line or 'rwx' in line:
                            # Check if it's not a standard library or executable
                            if not any(x in line for x in ['/lib/', '/usr/lib/', process.exe]):
                                return True
        except Exception as e:
            logger.debug(f"Error checking Linux injection: {e}")
            
        return False
    
    def _check_memory_anomalies(self, process_info: 'ProcessInfo') -> bool:
        """Check for unusual memory patterns."""
        try:
            process = psutil.Process(process_info.pid)
            mem_info = process.memory_info()
            
            # Check for unusually high private bytes
            if mem_info.private_bytes > (1 * 1024 * 1024 * 1024):  # 1GB
                return True
                
            # Check for rapid memory growth
            if hasattr(process_info, 'last_memory') and process_info.last_memory:
                growth_rate = (mem_info.rss - process_info.last_memory) / process_info.last_memory
                if growth_rate > 10.0:  # 1000% growth
                    return True
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
        return False

class ProcessMonitor:
    """
    Monitors system processes for suspicious and malicious activities.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the process monitor."""
        self.config = config or {}
        self.running = False
        self._lock = threading.RLock()
        self.behavior_analyzer = BehavioralAnalyzer()
        self.alert_handlers = []
        self._processes: Dict[int, ProcessInfo] = {}
        self._whitelist: Set[str] = set()
        self._blacklist: Set[str] = set()
        self._suspicious_commands: Set[str] = self._get_suspicious_commands()
        self._alert_handlers: List[Callable[[ThreatAlert], None]] = []
        
        # Platform-specific initialization
        self.platform = platform.system().lower()
        self._init_platform()
        
        # Load whitelist and blacklist
        self._load_whitelist()
        self._load_blacklist()
    
    def _init_platform(self) -> None:
        """Initialize platform-specific components."""
        if self.platform == 'windows':
            self._init_windows()
        elif self.platform == 'linux':
            self._init_linux()
        else:
            logger.warning(f"Unsupported platform: {self.platform}")
    
    def _init_windows(self) -> None:
        """Windows-specific initialization."""
        try:
            import win32api
            import win32process
            import win32security
            self._has_win32 = True
        except ImportError:
            self._has_win32 = False
            logger.warning("pywin32 not available, some Windows-specific features will be disabled")
    
    def _init_linux(self) -> None:
        """Linux-specific initialization."""
        # Check for required capabilities
        try:
            # Check if we can read /proc
            if not os.access('/proc/self/status', os.R_OK):
                logger.warning("Cannot read /proc, some features may be limited")
        except Exception as e:
            logger.warning(f"Error initializing Linux features: {e}")
    
    def _get_suspicious_commands(self) -> Set[str]:
        """Get a set of suspicious command patterns."""
        return {
            'chmod +s', 'chmod u+s', 'chmod 4777', 'chmod 6777',
            'chown root', 'chgrp root', 'passwd', 'usermod', 'useradd',
            'adduser', 'visudo', 'su ', 'sudo ', 'chkconfig', 'systemctl',
            'iptables', 'ufw ', 'firewall-cmd', 'nc ', 'netcat', 'ncat',
            'wget ', 'curl ', 'python -c', 'perl -e', 'bash -c', 'sh -c',
            'echo ', 'base64 -d', 'openssl ', 'ssh-keygen', 'ssh-copy-id',
            'crontab ', 'at ', 'anacron ', 'atd', 'cron', 'anacron', 'atrun'
        }
    
    def _load_whitelist(self) -> None:
        """Load whitelisted processes from configuration."""
        whitelist = self.config.get('whitelist', [])
        self._whitelist.update(whitelist)
        
        # Add common system binaries to whitelist
        common_binaries = [
            'systemd', 'init', 'upstart', 'launchd', 'wininit', 'services',
            'lsass', 'csrss', 'winlogon', 'explorer', 'dwm', 'taskhost',
            'svchost', 'lsm', 'smss', 'spoolsv', 'taskhostw', 'dwm', 'wmiprvse'
        ]
        self._whitelist.update(common_binaries)
    
    def _load_blacklist(self) -> None:
        """Load blacklisted processes from configuration."""
        blacklist = self.config.get('blacklist', [])
        self._blacklist.update(blacklist)
        
        # Add known malicious processes to blacklist
        malicious_processes = [
            'mimikatz', 'procdump', 'psexec', 'psexesvc', 'psexecsvc',
            'cain', 'john', 'hashcat', 'mimikittenz', 'invoke-mimikatz',
            'powersploit', 'empire', 'covenant', 'metasploit', 'beacon',
            'cobaltstrike', 'sliver', 'mimipenguin', 'linpeas', 'linenum',
            'linux_exploit_suggester', 'unix-privesc-check', 'linuxprivchecker',
            'windows-privesc-check', 'winpeas', 'sherlock', 'watson', 'seatbelt',
            'sharpup', 'juicypotato', 'printspoofer', 'roguepotato', 'sweetpotato',
            'godpotato', 'juicypotato', 'printspoofer', 'roguepotato', 'sweetpotato',
            'juicypotato', 'printspoofer', 'roguepotato', 'sweetpotato', 'godpotato'
        ]
        self._blacklist.update(malicious_processes.lower() for malicious_processes in malicious_processes)
    
    def start(self) -> None:
        """Start the process monitor."""
        if self.running:
            return
            
        self.running = True
        logger.info("Starting process monitor...")
        
        # Start the monitoring thread
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        
        logger.info("Process monitor started")
    
    def stop(self) -> None:
        """Stop the process monitor."""
        if not self.running:
            return
            
        self.running = False
        logger.info("Stopping process monitor...")
        
        if hasattr(self, '_monitor_thread') and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5.0)
        
        logger.info("Process monitor stopped")
    
    def add_alert_handler(self, handler: Callable[[ThreatAlert], None]) -> None:
        """Add a handler for threat alerts."""
        with self._lock:
            if handler not in self._alert_handlers:
                self._alert_handlers.append(handler)
    
    def remove_alert_handler(self, handler: Callable[[ThreatAlert], None]) -> None:
        """Remove a threat alert handler."""
        with self._lock:
            if handler in self._alert_handlers:
                self._alert_handlers.remove(handler)
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop that runs in a background thread."""
        while self.running:
            try:
                self._scan_processes()
                time.sleep(5)  # Adjust based on performance needs
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}", exc_info=True)
                time.sleep(10)  # Prevent tight loop on error
    
    def _scan_processes(self) -> None:
        """Scan all running processes for suspicious activity."""
        current_pids = set()
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'create_time', 'ppid']):
            try:
                process_info = self._get_process_info(proc)
                if not process_info:
                    continue
                    
                pid = process_info.pid
                current_pids.add(pid)
                
                # Check if we've seen this process before
                if pid in self._processes:
                    # Process already being monitored, check for changes
                    self._check_process_changes(self._processes[pid], process_info)
                else:
                    # New process, check if it's suspicious
                    self._analyze_process(process_info)
                
                # Update the process in our tracking
                self._processes[pid] = process_info
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.error(f"Error scanning process {proc.pid}: {e}", exc_info=True)
        
        # Clean up dead processes
        dead_pids = set(self._processes.keys()) - current_pids
        for pid in dead_pids:
            self._processes.pop(pid, None)
    
    def _get_process_info(self, proc: psutil.Process) -> Optional[ProcessInfo]:
        """Get process information from a psutil.Process object."""
        try:
            # Skip kernel threads and system processes
            if not proc.info['exe'] or not proc.info['name']:
                return None
                
            return ProcessInfo(
                pid=proc.info['pid'],
                name=proc.info['name'],
                exe=proc.info['exe'],
                cmdline=proc.info['cmdline'] or [],
                username=proc.info['username'],
                create_time=proc.info['create_time'],
                parent_pid=proc.info['ppid'],
                metadata={
                    'cpu_percent': proc.cpu_percent(),
                    'memory_percent': proc.memory_percent(),
                    'num_threads': proc.num_threads(),
                    'status': proc.status()
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        except Exception as e:
            logger.error(f"Error getting process info for {getattr(proc, 'pid', 'unknown')}: {e}")
            return None
    
    def _analyze_process(self, process_info: ProcessInfo) -> None:
        """Analyze a process for suspicious behavior."""
        # Check blacklist
        if self._is_blacklisted(process_info):
            self._handle_threat(
                process_info,
                ThreatType.MALICIOUS,
                f"Blacklisted process detected: {process_info.name}",
                'critical'
            )
            return
        
        # Check whitelist (skip further checks if whitelisted)
        if self._is_whitelisted(process_info):
            process_info.state = ProcessState.WHITELISTED
            return
        
        # Check for suspicious command line arguments
        self._check_suspicious_commands(process_info)
        
        # Check for code injection
        self._check_code_injection(process_info)
        
        # Check for privilege escalation
        self._check_privilege_escalation(process_info)
        
        # Check for process hollowing
        self._check_process_hollowing(process_info)
        
        # Check for suspicious parent-child relationships
        self._check_parent_process(process_info)
        
        # If we've detected any threats, handle them
        if process_info.detected_threats:
            process_info.state = ProcessState.MALICIOUS
            self._handle_threat(
                process_info,
                ThreatType.SUSPICIOUS_ACTIVITY,
                f"Suspicious activity detected in process {process_info.name} (PID: {process_info.pid})",
                'high',
                {'threats': [t.name for t in process_info.detected_threats]}
            )
        else:
            process_info.state = ProcessState.NORMAL
    
    def _is_blacklisted(self, process_info: ProcessInfo) -> bool:
        """Check if a process is in the blacklist."""
        name_lower = process_info.name.lower()
        exe_lower = process_info.exe.lower() if process_info.exe else ""
        
        for pattern in self._blacklist:
            if (pattern.lower() in name_lower or 
                (process_info.exe and pattern.lower() in exe_lower)):
                return True
        return False
    
    def _is_whitelisted(self, process_info: ProcessInfo) -> bool:
        """Check if a process is in the whitelist."""
        name_lower = process_info.name.lower()
        exe_lower = process_info.exe.lower() if process_info.exe else ""
        
        for pattern in self._whitelist:
            if (pattern.lower() in name_lower or 
                (process_info.exe and pattern.lower() in exe_lower)):
                return True
        return False
    
    def _check_suspicious_commands(self, process_info: ProcessInfo) -> None:
        """Check for suspicious command line arguments."""
        if not process_info.cmdline:
            return
            
        cmdline = ' '.join(process_info.cmdline).lower()
        
        for pattern in self._suspicious_commands:
            if pattern.lower() in cmdline:
                process_info.detected_threats.append(ThreatType.SUSPICIOUS_ACTIVITY)
                process_info.metadata['suspicious_command'] = cmdline
                break
    
    def _check_code_injection(self, process_info: ProcessInfo) -> None:
        """Check for signs of code injection."""
        if self.platform == 'windows':
            self._check_windows_code_injection(process_info)
        else:
            self._check_linux_code_injection(process_info)
    
    def _check_windows_code_injection(self, process_info: ProcessInfo) -> None:
        """Windows-specific code injection checks."""
        try:
            # Check for common injection techniques
            process = psutil.Process(process_info.pid)
            
            # Check for suspicious memory regions
            try:
                import win32api
                import win32con
                from win32process import EnumProcessModules
                from win32api import GetModuleFileName
                
                hProcess = None
                try:
                    hProcess = win32api.OpenProcess(
                        win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                        False,
                        process_info.pid
                    )
                    
                    modules = EnumProcessModules(hProcess)
                    for module in modules:
                        module_name = GetModuleFileName(hProcess, module).lower()
                        if any(suspect in module_name for suspect in ['inject', 'hook', 'reflective']):
                            process_info.detected_threats.append(ThreatType.CODE_INJECTION)
                            process_info.metadata['suspicious_module'] = module_name
                            break
                            
                finally:
                    if hProcess:
                        win32api.CloseHandle(hProcess)
                        
            except Exception as e:
                logger.debug(f"Could not check Windows modules for process {process_info.pid}: {e}")
            
            # Check for suspicious thread contexts
            try:
                from win32process import GetProcessMemoryInfo
                
                mem_info = GetProcessMemoryInfo(process_info.pid)
                if mem_info and mem_info.get('PageFaultCount', 0) > 1000:  # Arbitrary threshold
                    process_info.detected_threats.append(ThreatType.CODE_INJECTION)
                    process_info.metadata['high_page_faults'] = mem_info['PageFaultCount']
                    
            except Exception as e:
                logger.debug(f"Could not check memory info for process {process_info.pid}: {e}")
                
        except Exception as e:
            logger.error(f"Error in Windows code injection check: {e}", exc_info=True)
    
    def _check_linux_code_injection(self, process_info: ProcessInfo) -> None:
        """Linux-specific code injection checks."""
        try:
            # Check for suspicious memory mappings
            maps_path = f"/proc/{process_info.pid}/maps"
            if os.path.exists(maps_path):
                with open(maps_path, 'r') as f:
                    for line in f:
                        # Look for executable stack/heap
                        if 'rwxp' in line and ('[stack]' in line or '[heap]' in line):
                            process_info.detected_threats.append(ThreatType.CODE_INJECTION)
                            process_info.metadata['executable_memory'] = line.strip()
                            break
                            
                # Check for suspicious libraries
                libs_path = f"/proc/{process_info.pid}/maps"
                suspicious_libs = ['libinject', 'libhook', 'libreflective']
                with open(libs_path, 'r') as f:
                    for line in f:
                        if any(lib in line.lower() for lib in suspicious_libs):
                            process_info.detected_threats.append(ThreatType.CODE_INJECTION)
                            process_info.metadata['suspicious_library'] = line.strip()
                            break
                            
        except Exception as e:
            logger.error(f"Error in Linux code injection check: {e}", exc_info=True)
    
    def _check_privilege_escalation(self, process_info: ProcessInfo) -> None:
        """Check for signs of privilege escalation."""
        try:
            # Check if process is running as root/Administrator when it shouldn't be
            if self._is_high_privilege(process_info):
                # Check if parent process is lower privilege
                try:
                    parent = psutil.Process(process_info.parent_pid)
                    parent_info = self._get_process_info(parent)
                    
                    if parent_info and not self._is_high_privilege(parent_info):
                        process_info.detected_threats.append(ThreatType.PRIVILEGE_ESCALATION)
                        process_info.metadata['parent_username'] = parent_info.username
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                    
                # Check for setuid/setgid binaries on Linux
                if self.platform == 'linux' and process_info.exe:
                    try:
                        st = os.stat(process_info.exe)
                        if st.st_mode & 0o4000 or st.st_mode & 0o2000:  # setuid or setgid bit set
                            process_info.detected_threats.append(ThreatType.PRIVILEGE_ESCALATION)
                            process_info.metadata['setuid_setgid'] = True
                    except OSError:
                        pass
                        
        except Exception as e:
            logger.error(f"Error in privilege escalation check: {e}", exc_info=True)
    
    def _is_high_privilege(self, process_info: ProcessInfo) -> bool:
        """Check if a process is running with high privileges."""
        if not process_info.username:
            return False
            
        if self.platform == 'windows':
            return any(privileged_user in process_info.username.lower() 
                     for privileged_user in ['nt authority\\system', 'local system', 'administrator'])
        else:  # Linux/Unix
            return process_info.username == 'root' or os.geteuid() == 0
    
    def _check_process_hollowing(self, process_info: ProcessInfo) -> None:
        """Check for signs of process hollowing."""
        if not process_info.exe or not os.path.exists(process_info.exe):
            return
            
        try:
            # Check if the on-disk binary matches the running process
            with open(process_info.exe, 'rb') as f:
                disk_hash = hashlib.sha256(f.read()).hexdigest()
                
            # Get the hash of the running process memory
            # This is a simplified check - real detection would be more sophisticated
            process = psutil.Process(process_info.pid)
            memory_maps = process.memory_maps(grouped=False)
            
            # Look for mismatches between the on-disk and in-memory content
            for m in memory_maps:
                if m.path == process_info.exe and hasattr(m, 'rss') and m.rss > 0:
                    # This is a simplified check - in reality, you'd need to read the process memory
                    # and compare it with the on-disk file
                    process_info.metadata['process_hollowing_check'] = 'suspicious'
                    process_info.detected_threats.append(ThreatType.PROCESS_HOLLOWING)
                    break
                    
        except (psutil.AccessDenied, FileNotFoundError, PermissionError):
            # Can't access the process or file, skip
            pass
        except (psutil.AccessDenied, FileNotFoundError, PermissionError):
            # Can't access the process or file, skip
            pass
        except Exception as e:
            logger.error(f"Error in process hollowing check: {e}", exc_info=True)
    
    def _check_parent_process(self, process_info: ProcessInfo) -> None:
        """Check for suspicious parent-child process relationships."""
        try:
            if not process_info.parent_pid or process_info.parent_pid == 1:
                return  # Skip init/systemd
                
            parent = psutil.Process(process_info.parent_pid)
            parent_info = self._get_process_info(parent)
            
            if not parent_info:
                return
                
            # Check for suspicious parent processes
            suspicious_parents = ['bash', 'sh', 'cmd', 'powershell', 'wscript', 'cscript', 'mshta']
            if any(p in parent_info.name.lower() for p in suspicious_parents):
                # Check if the parent is running a suspicious command
                cmdline = ' '.join(parent_info.cmdline).lower() if parent_info.cmdline else ''
                if any(cmd in cmdline for cmd in ['curl', 'wget', 'powershell -nop', 'iex', 'invoke-']):
                    process_info.detected_threats.append(ThreatType.SUSPICIOUS_ACTIVITY)
                    process_info.metadata['suspicious_parent'] = f"{parent_info.name} (PID: {parent_info.pid})"
                    process_info.metadata['parent_cmdline'] = cmdline
        
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception as e:
            logger.error(f"Error in parent process check: {e}", exc_info=True)
    
    def _check_process_changes(self, old_info: ProcessInfo, new_info: ProcessInfo) -> None:
        """Check for suspicious changes in a process."""
        # Check if the executable path has changed
        if old_info.exe and new_info.exe and old_info.exe.lower() != new_info.exe.lower():
            self._handle_threat(
                new_info,
                ThreatType.REPLACED_BINARY,
                f"Process binary changed from {old_info.exe} to {new_info.exe}",
                'high',
                {'old_exe': old_info.exe, 'new_exe': new_info.exe}
            )
        
        # Check for privilege escalation
        if (not self._is_high_privilege(old_info) and 
            self._is_high_privilege(new_info)):
            self._handle_threat(
                new_info,
                ThreatType.PRIVILEGE_ESCALATION,
                f"Process escalated privileges: {new_info.username}",
                'critical',
                {'old_user': old_info.username, 'new_user': new_info.username}
            )
    
    def _handle_threat(self, 
                      process_info: ProcessInfo, 
                      threat_type: ThreatType, 
                      description: str, 
                      severity: str,
                      metadata: Optional[Dict[str, Any]] = None) -> None:
        """Handle a detected threat."""
        # Update process state
        process_info.state = ProcessState.MALICIOUS
        if threat_type not in process_info.detected_threats:
            process_info.detected_threats.append(threat_type)
        
        # Create alert
        alert = ThreatAlert(
            threat_type=threat_type,
            description=description,
            severity=severity,
            process=process_info,
            metadata=metadata or {}
        )
        
        # Log the alert
        logger.warning(f"{severity.upper()} - {description}")
        
        # Notify handlers
        with self._lock:
            for handler in self._alert_handlers:
                try:
                    handler(alert)
                except Exception as e:
                    logger.error(f"Error in alert handler: {e}", exc_info=True)
    
    def terminate_process(self, pid: int) -> bool:
        """Terminate a potentially malicious process."""
        try:
            process = psutil.Process(pid)
            process.terminate()
            
            # Give it a moment to terminate gracefully
            try:
                process.wait(timeout=5)
            except (psutil.TimeoutExpired, psutil.NoSuchProcess):
                pass
                
            # If still running, force kill
            if process.is_running():
                process.kill()
                
            logger.warning(f"Terminated process {pid}")
            return True
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.error(f"Could not terminate process {pid}: {e}")
            return False
        except Exception as e:
            logger.error(f"Error terminating process {pid}: {e}", exc_info=True)
            return False
    
    def quarantine_file(self, file_path: str) -> bool:
        """Quarantine a potentially malicious file."""
        try:
            if not os.path.exists(file_path):
                logger.warning(f"File not found: {file_path}")
                return False
                
            # Create quarantine directory if it doesn't exist
            quarantine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'quarantine')
            os.makedirs(quarantine_dir, exist_ok=True)
            
            # Generate a unique name for the quarantined file
            import uuid
            file_name = os.path.basename(file_path)
            quarantine_path = os.path.join(quarantine_dir, f"{uuid.uuid4()}_{file_name}")
            
            # Move the file to quarantine
            import shutil
            shutil.move(file_path, quarantine_path)
            
            # Set restrictive permissions
            os.chmod(quarantine_path, 0o600)
            
            logger.warning(f"Quarantined {file_path} to {quarantine_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error quarantining file {file_path}: {e}", exc_info=True)
            return False
    
    def get_process_info(self, pid: int) -> Optional[ProcessInfo]:
        """Get information about a specific process."""
        with self._lock:
            return self._processes.get(pid)
    
    def get_suspicious_processes(self) -> List[ProcessInfo]:
        """Get a list of suspicious processes."""
        with self._lock:
            return [
                p for p in self._processes.values()
                if p.state in [ProcessState.SUSPICIOUS, ProcessState.MALICIOUS]
            ]
    
    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()

# Example usage
if __name__ == "__main__":
    import json
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Define an alert handler
    def handle_alert(alert: ThreatAlert) -> None:
        print(f"\n[!] ALERT: {alert.description}")
        print(f"    Type: {alert.threat_type.name}")
        print(f"    Severity: {alert.severity.upper()}")
        print(f"    Process: {alert.process.name} (PID: {alert.process.pid})")
        if alert.metadata:
            print(f"    Metadata: {json.dumps(alert.metadata, indent=4)}")
    
    # Create and start the monitor
    with ProcessMonitor() as monitor:
        monitor.add_alert_handler(handle_alert)
        print("Process monitor started. Press Ctrl+C to stop.")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping process monitor...")
