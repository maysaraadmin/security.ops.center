"""
HIPS Detection Engine - Monitors system activities for potential intrusions.
"""
import os
import sys
import logging
import threading
import time
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Callable, Tuple
import win32api
import win32con
import win32security
import win32file
import win32process
import win32event
import win32service
import win32serviceutil
import winerror
import psutil

class HIPSDetectionEngine:
    """Monitors system activities for potential intrusions."""
    
    def __init__(self, alert_callback: Callable[[Dict], None] = None):
        """
        Initialize the HIPS detection engine.
        
        Args:
            alert_callback: Function to call when an alert is generated
        """
        self.logger = logging.getLogger(__name__)
        self.alert_callback = alert_callback
        self.running = False
        self.monitoring_thread = None
        self.rules = self._load_default_rules()
        self.whitelist = self._load_whitelist()
        self.suspicious_activities = []
        self.lock = threading.Lock()
        
        # Initialize monitoring flags
        self.monitor_file_system = True
        self.monitor_registry = True
        self.monitor_processes = True
        self.monitor_network = True
        self.monitor_services = True
        
        # Initialize monitoring threads
        self.threads = []
        self.stop_event = threading.Event()
    
    def _load_default_rules(self) -> List[Dict]:
        """Load default detection rules."""
        default_rules = [
            # File system rules
            {
                'id': 'fs-001',
                'name': 'Suspicious File Creation',
                'description': 'Detects creation of potentially malicious files',
                'type': 'file_system',
                'patterns': [r'\.(exe|dll|sys|bat|ps1|vbs|js)$'],
                'paths': [r'%TEMP%', r'%APPDATA%', r'%PROGRAMDATA%', r'%WINDIR%\\Temp'],
                'severity': 'high',
                'action': 'alert',
                'enabled': True
            },
            # Registry rules
            {
                'id': 'reg-001',
                'name': 'Startup Program Modification',
                'description': 'Detects modifications to startup programs',
                'type': 'registry',
                'keys': [
                    r'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                    r'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                    r'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
                    r'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
                ],
                'severity': 'high',
                'action': 'alert',
                'enabled': True
            },
            # Process rules
            {
                'id': 'proc-001',
                'name': 'Suspicious Process Creation',
                'description': 'Detects potentially malicious processes',
                'type': 'process',
                'process_names': ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe'],
                'command_line_patterns': [
                    r'\-nop\b',  # No profile
                    r'\-w\s+hidden',  # Window style hidden
                    r'\-e(?:xecutionpolicy|p)\s+bypass',  # Bypass execution policy
                    r'\-e(?:ncodedcommand|ec)\s+',  # Encoded command
                    r'iex\s+\('  # Invoke-Expression
                ],
                'severity': 'high',
                'action': 'alert',
                'enabled': True
            },
            # Network rules
            {
                'id': 'net-001',
                'name': 'Suspicious Network Connection',
                'description': 'Detects connections to known malicious IPs/domains',
                'type': 'network',
                'dest_ips': [],  # Would be populated from threat intel
                'dest_ports': [4444, 5555, 6666, 7777, 8888],  # Common malware ports
                'severity': 'high',
                'action': 'alert',
                'enabled': True
            },
            # Service rules
            {
                'id': 'svc-001',
                'name': 'Suspicious Service Installation',
                'description': 'Detects installation of potentially malicious services',
                'type': 'service',
                'service_names': ['.*'],
                'severity': 'high',
                'action': 'alert',
                'enabled': True
            }
        ]
        return default_rules
    
    def _load_whitelist(self) -> Dict[str, List[str]]:
        """Load whitelisted items (safe files, processes, etc.)."""
        return {
            'paths': [
                r'C:\\Windows\\',
                r'C:\\Program Files\\',
                r'C:\\Program Files (x86)\\',
                r'C:\\ProgramData\\',
                r'%SYSTEMROOT%\\',
                r'%PROGRAMFILES%\\',
                r'%PROGRAMFILES(X86)%\\'
            ],
            'processes': [
                'svchost.exe',
                'explorer.exe',
                'winlogon.exe',
                'csrss.exe',
                'wininit.exe',
                'services.exe',
                'lsass.exe',
                'lsm.exe',
                'taskhost.exe',
                'dwm.exe',
                'spoolsv.exe',
                'taskeng.exe',
                'taskhostw.exe',
                'SearchIndexer.exe',
                'SearchUI.exe',
                'RuntimeBroker.exe',
                'dllhost.exe',
                'WmiPrvSE.exe',
                'sihost.exe',
                'ctfmon.exe',
                'conhost.exe',
                'msmpeng.exe',  # Windows Defender
                'NisSrv.exe',   # Windows Defender Network Inspection
                'MpCmdRun.exe',  # Windows Defender Command Line
                'smartscreen.exe',
                'SecurityHealthService.exe',
                'SecurityHealthSystray.exe',
                'msedge.exe',
                'chrome.exe',
                'firefox.exe',
                'iexplore.exe',
                'notepad.exe',
                'wordpad.exe',
                'calc.exe',
                'mspaint.exe',
                'explorer.exe',
                'cmd.exe',
                'powershell.exe',
                'pwsh.exe',
                'wsl.exe',
                'bash.exe',
                'git-bash.exe',
                'git-cmd.exe',
                'python.exe',
                'pythonw.exe',
                'javaw.exe',
                'java.exe',
                'javacpl.exe',
                'javaws.exe',
                'javac.exe',
                'node.exe',
                'npm.cmd',
                'npx.cmd',
                'yarn.cmd',
                'yarnpkg.cmd',
                'code.exe',
                'vscode.exe',
                'devenv.exe',
                'msbuild.exe',
                'dotnet.exe',
                'dotnet-watch.exe',
                'dotnet-watch.dll',
                'dotnet-watch.pdb',
                'dotnet-watch.runtimeconfig.json',
                'dotnet-watch.deps.json',
            ],
            'signed_by': [
                'Microsoft Windows',
                'Microsoft Corporation',
                'Google LLC',
                'Mozilla Corporation',
                'Oracle America, Inc.',
                'The OpenSSL Project',
                'OpenSSL Software Foundation',
                'DigiCert Inc',
                'VeriSign, Inc.',
                'GlobalSign nv-sa',
                'COMODO CA Limited',
                'Sectigo Limited',
                'Let\'s Encrypt',
                'Cloudflare, Inc.',
                'Amazon',
                'Amazon Web Services, Inc.'
            ]
        }
    
    def start(self):
        """Start the HIPS detection engine."""
        if self.running:
            self.logger.warning("HIPS detection engine is already running")
            return
        
        self.running = True
        self.stop_event.clear()
        
        # Start monitoring threads based on enabled features
        if self.monitor_file_system:
            t = threading.Thread(target=self._monitor_file_system, daemon=True)
            t.start()
            self.threads.append(t)
        
        if self.monitor_processes:
            t = threading.Thread(target=self._monitor_processes, daemon=True)
            t.start()
            self.threads.append(t)
        
        if self.monitor_network:
            t = threading.Thread(target=self._monitor_network, daemon=True)
            t.start()
            self.threads.append(t)
        
        if self.monitor_services:
            t = threading.Thread(target=self._monitor_services, daemon=True)
            t.start()
            self.threads.append(t)
        
        self.logger.info("HIPS detection engine started")
    
    def stop(self):
        """Stop the HIPS detection engine."""
        if not self.running:
            return
        
        self.running = False
        self.stop_event.set()
        
        # Wait for threads to finish
        for t in self.threads:
            if t.is_alive():
                t.join(timeout=5)
        
        self.threads = []
        self.logger.info("HIPS detection engine stopped")
    
    def _monitor_file_system(self):
        """Monitor file system for suspicious activities."""
        self.logger.debug("Starting file system monitoring")
        
        while self.running and not self.stop_event.is_set():
            try:
                # Check for new files in monitored locations
                for rule in [r for r in self.rules if r['type'] == 'file_system' and r['enabled']]:
                    for path_pattern in rule.get('paths', []):
                        # Expand environment variables in path
                        expanded_path = os.path.expandvars(path_pattern)
                        
                        # Skip if path doesn't exist
                        if not os.path.exists(expanded_path):
                            continue
                        
                        # Check files in path
                        for root, _, files in os.walk(expanded_path):
                            for file in files:
                                file_path = os.path.join(root, file)
                                
                                # Check against file patterns
                                for pattern in rule.get('patterns', []):
                                    if re.search(pattern, file, re.IGNORECASE):
                                        # Check if file is whitelisted
                                        if not self._is_whitelisted(file_path, 'paths'):
                                            self._trigger_alert(
                                                rule_id=rule['id'],
                                                rule_name=rule['name'],
                                                severity=rule['severity'],
                                                description=f"Suspicious file detected: {file_path}",
                                                details={
                                                    'file_path': file_path,
                                                    'pattern': pattern,
                                                    'rule': rule
                                                }
                                            )
                
                # Sleep for a bit to prevent high CPU usage
                time.sleep(5)
                
            except Exception as e:
                self.logger.error(f"Error in file system monitoring: {e}", exc_info=True)
                time.sleep(10)  # Prevent tight loop on error
    
    def _monitor_processes(self):
        """Monitor process creation for suspicious activities."""
        self.logger.debug("Starting process monitoring")
        
        # Track processes we've already alerted on to avoid duplicates
        alerted_pids = set()
        
        while self.running and not self.stop_event.is_set():
            try:
                current_pids = set()
                
                # Get all running processes
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
                    try:
                        pid = proc.info['pid']
                        name = proc.info['name']
                        cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
                        
                        current_pids.add(pid)
                        
                        # Skip if we've already alerted on this process
                        if pid in alerted_pids:
                            continue
                        
                        # Check against process rules
                        for rule in [r for r in self.rules if r['type'] == 'process' and r['enabled']]:
                            # Check process name
                            if not any(re.search(p, name, re.IGNORECASE) for p in rule.get('process_names', [])):
                                continue
                            
                            # Check command line patterns
                            if 'command_line_patterns' in rule:
                                if not any(re.search(p, cmdline, re.IGNORECASE) for p in rule['command_line_patterns']):
                                    continue
                            
                            # Check if process is whitelisted
                            if self._is_whitelisted(name, 'processes'):
                                continue
                            
                            # Check if process is signed by a trusted publisher
                            if self._is_trusted_publisher(pid):
                                continue
                            
                            # Trigger alert
                            self._trigger_alert(
                                rule_id=rule['id'],
                                rule_name=rule['name'],
                                severity=rule['severity'],
                                description=f"Suspicious process detected: {name} (PID: {pid})",
                                details={
                                    'pid': pid,
                                    'name': name,
                                    'cmdline': cmdline,
                                    'username': proc.info['username'],
                                    'rule': rule
                                }
                            )
                            
                            # Add to alerted processes
                            alerted_pids.add(pid)
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                
                # Clean up old PIDs
                alerted_pids = {pid for pid in alerted_pids if pid in current_pids}
                
                # Sleep for a bit
                time.sleep(2)
                
            except Exception as e:
                self.logger.error(f"Error in process monitoring: {e}", exc_info=True)
                time.sleep(10)  # Prevent tight loop on error
    
    def _monitor_network(self):
        """Monitor network connections for suspicious activities."""
        self.logger.debug("Starting network monitoring")
        
        # Track connections we've already alerted on to avoid duplicates
        alerted_connections = set()
        
        while self.running and not self.stop_event.is_set():
            try:
                current_connections = set()
                
                # Get all network connections
                for conn in psutil.net_connections(kind='inet'):
                    try:
                        if not conn.raddr:  # Skip listening sockets
                            continue
                        
                        # Create connection identifier
                        conn_id = f"{conn.pid}:{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}"
                        current_connections.add(conn_id)
                        
                        # Skip if we've already alerted on this connection
                        if conn_id in alerted_connections:
                            continue
                        
                        # Get process info
                        try:
                            proc = psutil.Process(conn.pid)
                            proc_name = proc.name()
                            proc_cmdline = ' '.join(proc.cmdline()) if proc.cmdline() else ''
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            proc_name = 'unknown'
                            proc_cmdline = ''
                        
                        # Check against network rules
                        for rule in [r for r in self.rules if r['type'] == 'network' and r['enabled']]:
                            # Check destination IPs
                            if rule.get('dest_ips') and conn.raddr.ip not in rule['dest_ips']:
                                continue
                            
                            # Check destination ports
                            if rule.get('dest_ports') and conn.raddr.port not in rule['dest_ports']:
                                continue
                            
                            # Skip if process is whitelisted
                            if self._is_whitelisted(proc_name, 'processes'):
                                continue
                            
                            # Check if process is signed by a trusted publisher
                            if self._is_trusted_publisher(conn.pid):
                                continue
                            
                            # Trigger alert
                            self._trigger_alert(
                                rule_id=rule['id'],
                                rule_name=rule['name'],
                                severity=rule['severity'],
                                description=f"Suspicious network connection from {proc_name} (PID: {conn.pid}) to {conn.raddr.ip}:{conn.raddr.port}",
                                details={
                                    'pid': conn.pid,
                                    'process_name': proc_name,
                                    'cmdline': proc_cmdline,
                                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
                                    'status': conn.status,
                                    'rule': rule
                                }
                            )
                            
                            # Add to alerted connections
                            alerted_connections.add(conn_id)
                            
                    except Exception as e:
                        self.logger.error(f"Error processing network connection: {e}", exc_info=True)
                        continue
                
                # Clean up old connections
                alerted_connections = {conn_id for conn_id in alerted_connections if conn_id in current_connections}
                
                # Sleep for a bit
                time.sleep(5)
                
            except Exception as e:
                self.logger.error(f"Error in network monitoring: {e}", exc_info=True)
                time.sleep(10)  # Prevent tight loop on error
    
    def _monitor_services(self):
        """Monitor Windows services for suspicious activities."""
        self.logger.debug("Starting service monitoring")
        
        # Track services we've already seen
        known_services = set()
        
        while self.running and not self.stop_event.is_set():
            try:
                current_services = set()
                
                # Get all services
                scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
                
                try:
                    services = win32service.EnumServicesStatus(scm, win32service.SERVICE_WIN32, win32service.SERVICE_STATE_ALL)
                    
                    for service in services:
                        service_name = service[0]
                        display_name = service[1]
                        status = service[2][1]
                        
                        current_services.add(service_name)
                        
                        # Skip if we've already seen this service
                        if service_name in known_services:
                            continue
                        
                        # Check against service rules
                        for rule in [r for r in self.rules if r['type'] == 'service' and r['enabled']]:
                            # Check service name against patterns
                            if not any(re.search(p, service_name, re.IGNORECASE) for p in rule.get('service_names', [])):
                                continue
                            
                            try:
                                # Get service details
                                h_service = win32service.OpenService(scm, service_name, win32service.SERVICE_QUERY_CONFIG)
                                try:
                                    config = win32service.QueryServiceConfig2(h_service, win32service.SERVICE_CONFIG_DESCRIPTION)
                                    bin_path = config[1]
                                    
                                    # Check if service binary is whitelisted
                                    if self._is_whitelisted(bin_path, 'paths'):
                                        continue
                                    
                                    # Get process ID if running
                                    pid = None
                                    try:
                                        status = win32service.QueryServiceStatusEx(h_service)
                                        if status['ProcessId'] != 0:
                                            pid = status['ProcessId']
                                            
                                            # Check if process is signed by a trusted publisher
                                            if self._is_trusted_publisher(pid):
                                                continue
                                    except Exception:
                                        pass
                                    
                                    # Trigger alert
                                    self._trigger_alert(
                                        rule_id=rule['id'],
                                        rule_name=rule['name'],
                                        severity=rule['severity'],
                                        description=f"Suspicious service detected: {display_name} ({service_name})",
                                        details={
                                            'service_name': service_name,
                                            'display_name': display_name,
                                            'binary_path': bin_path,
                                            'pid': pid,
                                            'status': status,
                                            'rule': rule
                                        }
                                    )
                                    
                                    # Add to known services
                                    known_services.add(service_name)
                                    
                                finally:
                                    win32service.CloseServiceHandle(h_service)
                                    
                            except Exception as e:
                                self.logger.error(f"Error querying service {service_name}: {e}", exc_info=True)
                                continue
                
                finally:
                    win32service.CloseServiceHandle(scm)
                
                # Clean up old services
                known_services = {s for s in known_services if s in current_services}
                
                # Sleep for a bit
                time.sleep(30)  # Services don't change often, so we can check less frequently
                
            except Exception as e:
                self.logger.error(f"Error in service monitoring: {e}", exc_info=True)
                time.sleep(60)  # Prevent tight loop on error
    
    def _is_whitelisted(self, item: str, list_type: str) -> bool:
        """Check if an item is whitelisted."""
        if list_type not in self.whitelist:
            return False
        
        item_lower = item.lower()
        
        for pattern in self.whitelist[list_type]:
            try:
                # Handle environment variables in paths
                expanded_pattern = os.path.expandvars(pattern).lower()
                
                # Check if the pattern is a regex
                if re.search(expanded_pattern, item_lower, re.IGNORECASE):
                    return True
                
                # Also check for direct path matching
                if os.path.isabs(expanded_pattern) and item_lower.startswith(expanded_pattern.lower()):
                    return True
                    
            except re.error:
                # If pattern is not a valid regex, do a simple string check
                if pattern.lower() in item_lower:
                    return True
        
        return False
    
    def _is_trusted_publisher(self, pid: int) -> bool:
        """Check if a process is signed by a trusted publisher."""
        try:
            # Get process executable path
            proc = psutil.Process(pid)
            exe_path = proc.exe()
            
            if not exe_path or not os.path.exists(exe_path):
                return False
            
            # Get file version info
            info = win32api.GetFileVersionInfo(exe_path, '\\')
            
            # Check company name
            company_name = info.get('CompanyName', '').lower()
            if any(p.lower() in company_name for p in self.whitelist.get('signed_by', [])):
                return True
            
            # Check file description
            file_desc = info.get('FileDescription', '').lower()
            if any(p.lower() in file_desc for p in self.whitelist.get('signed_by', [])):
                return True
            
            # Check internal name
            internal_name = info.get('InternalName', '').lower()
            if any(p.lower() in internal_name for p in self.whitelist.get('signed_by', [])):
                return True
            
            # Check original filename
            orig_filename = info.get('OriginalFilename', '').lower()
            if any(p.lower() in orig_filename for p in self.whitelist.get('signed_by', [])):
                return True
            
            # Check product name
            product_name = info.get('ProductName', '').lower()
            if any(p.lower() in product_name for p in self.whitelist.get('signed_by', [])):
                return True
            
        except Exception as e:
            self.logger.debug(f"Error checking trusted publisher for PID {pid}: {e}")
            return False
        
        return False
    
    def _trigger_alert(self, rule_id: str, rule_name: str, severity: str, description: str, details: Dict):
        """Trigger an alert."""
        alert = {
            'timestamp': time.time(),
            'rule_id': rule_id,
            'rule_name': rule_name,
            'severity': severity,
            'description': description,
            'details': details
        }
        
        # Add to suspicious activities
        with self.lock:
            self.suspicious_activities.append(alert)
            
            # Keep only the last 1000 alerts
            if len(self.suspicious_activities) > 1000:
                self.suspicious_activities = self.suspicious_activities[-1000:]
        
        # Log the alert
        self.logger.warning(f"HIPS Alert - {severity.upper()}: {description}")
        
        # Call the alert callback if set
        if self.alert_callback:
            try:
                self.alert_callback(alert)
            except Exception as e:
                self.logger.error(f"Error in alert callback: {e}", exc_info=True)
    
    def get_alerts(self, limit: int = 100) -> List[Dict]:
        """Get recent alerts."""
        with self.lock:
            return self.suspicious_activities[-limit:]
    
    def clear_alerts(self):
        """Clear all alerts."""
        with self.lock:
            self.suspicious_activities = []
    
    def get_status(self) -> Dict:
        """Get the current status of the HIPS engine."""
        return {
            'running': self.running,
            'monitoring': {
                'file_system': self.monitor_file_system,
                'registry': self.monitor_registry,
                'processes': self.monitor_processes,
                'network': self.monitor_network,
                'services': self.monitor_services
            },
            'alerts_count': len(self.suspicious_activities),
            'threads': len([t for t in self.threads if t.is_alive()])
        }
