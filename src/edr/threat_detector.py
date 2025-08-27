import psutil
import hashlib
import json
from datetime import datetime
from typing import Dict, List, Optional, Set
import requests
import threading
import time

class ThreatDetector:
    def __init__(self):
        self.suspicious_patterns = {
            'processes': [
                'powershell -nop -exec bypass',
                'cmd /c',
                'regsvr32',
                'mshta',
                'certutil',
                'bitsadmin'
            ],
            'network': [
                'tor2web',
                'i2p',
                'torrent',
                'mirai',
                'c2'
            ]
        }
        self.known_threats = self._load_threat_intel()
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_system, daemon=True)
        
    def start(self):
        """Start the threat detection engine."""
        self.monitor_thread.start()
    
    def stop(self):
        """Stop the threat detection engine."""
        self.running = False
        if self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2)
    
    def _load_threat_intel(self) -> Dict:
        """Load threat intelligence feeds."""
        try:
            # Load local threat intel
            try:
                with open('threat_intel.json', 'r') as f:
                    return json.load(f)
            except FileNotFoundError:
                return {
                    'hashes': {},
                    'ips': {},
                    'domains': {}
                }
        except Exception as e:
            print(f"Error loading threat intel: {e}")
            return {'hashes': {}, 'ips': {}, 'domains': {}}
    
    def _monitor_system(self):
        """Continuously monitor system for threats."""
        while self.running:
            try:
                self.check_processes()
                self.check_network_connections()
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                print(f"Monitoring error: {e}")
    
    def check_processes(self) -> List[dict]:
        """Check running processes for suspicious activity."""
        threats = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
            try:
                proc_info = proc.info
                cmdline = ' '.join(proc_info['cmdline'] or []).lower()
                
                # Check for suspicious command line patterns
                for pattern in self.suspicious_patterns['processes']:
                    if pattern.lower() in cmdline:
                        threat = {
                            'type': 'suspicious_process',
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'cmdline': cmdline,
                            'severity': 'high',
                            'timestamp': datetime.utcnow().isoformat(),
                            'mitre_tactics': ['Execution', 'Persistence'],
                            'mitre_techniques': ['T1059', 'T1053'],
                            'recommendation': 'Investigate this process for potential malicious activity.'
                        }
                        threats.append(threat)
                        self._alert(threat)
                        break
                
                # Check file hashes against known threats
                try:
                    file_hash = self._get_file_hash(proc.exe())
                    if file_hash in self.known_threats.get('hashes', {}):
                        threat = {
                            'type': 'known_malware',
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'file_hash': file_hash,
                            'severity': 'critical',
                            'timestamp': datetime.utcnow().isoformat(),
                            'mitre_tactics': ['Execution'],
                            'mitre_techniques': ['T1204'],
                            'recommendation': 'Terminate this process and remove the associated file.'
                        }
                        threats.append(threat)
                        self._alert(threat)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return threats
    
    def check_network_connections(self) -> List[dict]:
        """Check network connections for suspicious activity."""
        threats = []
        for conn in psutil.net_connections(kind='inet'):
            try:
                if not conn.raddr:
                    continue
                    
                ip = conn.raddr.ip
                port = conn.raddr.port
                
                # Check against known malicious IPs
                if ip in self.known_threats.get('ips', {}):
                    threat = self.known_threats['ips'][ip]
                    threat.update({
                        'type': 'malicious_connection',
                        'local_port': conn.laddr.port,
                        'remote_ip': ip,
                        'remote_port': port,
                        'pid': conn.pid,
                        'status': conn.status,
                        'timestamp': datetime.utcnow().isoformat(),
                        'severity': 'high',
                        'recommendation': 'Terminate this connection and investigate the process.'
                    })
                    threats.append(threat)
                    self._alert(threat)
                
                # Check for suspicious ports
                if port in [4444, 31337, 6667, 8080]:  # Common malware ports
                    threat = {
                        'type': 'suspicious_port',
                        'local_port': conn.laddr.port,
                        'remote_ip': ip,
                        'remote_port': port,
                        'pid': conn.pid,
                        'status': conn.status,
                        'severity': 'medium',
                        'timestamp': datetime.utcnow().isoformat(),
                        'mitre_tactics': ['Command and Control'],
                        'mitre_techniques': ['T1071'],
                        'recommendation': 'Investigate this connection for potential C2 activity.'
                    }
                    threats.append(threat)
                    self._alert(threat)
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return threats
    
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
    
    def _alert(self, threat: dict):
        """Handle threat alerts."""
        # Log the threat
        print(f"[!] Threat Detected: {threat['type']} - {threat.get('name', 'Unknown')}")
        
        # TODO: Send alert to SIEM or other monitoring systems
        # self._send_to_siem(threat)
        
        # Take automated response actions based on severity
        if threat.get('severity') == 'critical':
            self._take_mitigation_action(threat)
    
    def _take_mitigation_action(self, threat: dict):
        """Take automated response actions for critical threats."""
        try:
            if 'pid' in threat:
                proc = psutil.Process(threat['pid'])
                proc.terminate()
                print(f"[+] Terminated malicious process: {threat['pid']}")
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"[-] Failed to terminate process {threat.get('pid')}: {e}")
    
    def add_threat_intel(self, intel_type: str, value: str, metadata: dict):
        """Add threat intelligence data."""
        if intel_type not in self.known_threats:
            self.known_threats[intel_type] = {}
        self.known_threats[intel_type][value] = metadata
        self._save_threat_intel()
    
    def _save_threat_intel(self):
        """Save threat intelligence to file."""
        try:
            with open('threat_intel.json', 'w') as f:
                json.dump(self.known_threats, f, indent=2)
        except Exception as e:
            print(f"Error saving threat intel: {e}")

# Example usage
if __name__ == "__main__":
    detector = ThreatDetector()
    detector.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        detector.stop()
