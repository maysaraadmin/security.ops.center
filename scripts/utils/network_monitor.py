"""
Network monitoring and analysis for the EDR system.
"""

import os
import re
import sys
import socket
import logging
import ipaddress
import threading
import subprocess
from typing import Dict, List, Optional, Callable, Any, Set
from datetime import datetime
import time

logger = logging.getLogger('edr.network_monitor')

class NetworkMonitor:
    """Monitor and analyze network traffic."""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self._stop_event = threading.Event()
        self._monitor_thread = None
        self._load_config()
    
    def _load_config(self) -> None:
        """Load monitoring configuration."""
        self.suspicious_ips = set(self.config.get('suspicious_ips', []))
        self.suspicious_domains = set(self.config.get('suspicious_domains', []))
        self.suspicious_ports = set(self.config.get('suspicious_ports', []))
        self.allowed_ports = set(self.config.get('allowed_ports', [80, 443, 53, 22, 3389]))
        self.update_interval = self.config.get('update_interval', 60)
    
    def start(self, callback: Callable[[Dict], None]) -> None:
        """Start network monitoring."""
        if self._monitor_thread and self._monitor_thread.is_alive():
            logger.warning("Monitoring already running")
            return
        
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor,
            args=(callback,),
            daemon=True
        )
        self._monitor_thread.start()
    
    def stop(self) -> None:
        """Stop network monitoring."""
        self._stop_event.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
    
    def _monitor(self, callback: Callable[[Dict], None]) -> None:
        """Monitor network connections."""
        while not self._stop_event.is_set():
            try:
                connections = self._get_connections()
                for conn in connections:
                    if self._is_suspicious(conn):
                        callback({
                            'type': 'suspicious_connection',
                            'data': conn,
                            'timestamp': datetime.utcnow().isoformat()
                        })
                
                self._stop_event.wait(self.update_interval)
                
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                self._stop_event.wait(5)  # Wait before retry
    
    def _get_connections(self) -> List[Dict]:
        """Get active network connections."""
        if sys.platform == 'win32':
            return self._get_windows_connections()
        elif sys.platform == 'linux':
            return self._get_linux_connections()
        elif sys.platform == 'darwin':
            return self._get_darwin_connections()
        else:
            logger.warning(f"Unsupported platform: {sys.platform}")
            return []
    
    def _get_windows_connections(self) -> List[Dict]:
        """Get connections on Windows."""
        try:
            cmd = 'Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ConvertTo-Json'
            result = subprocess.run(
                ['powershell', '-Command', cmd],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                logger.error(f"Failed to get connections: {result.stderr}")
                return []
            
            import json
            connections = json.loads(result.stdout)
            if not isinstance(connections, list):
                connections = [connections]
                
            return [{
                'local_ip': str(c.get('LocalAddress', '')),
                'local_port': int(c.get('LocalPort', 0)),
                'remote_ip': str(c.get('RemoteAddress', '')),
                'remote_port': int(c.get('RemotePort', 0)),
                'state': str(c.get('State', '')),
                'pid': int(c.get('OwningProcess', 0)),
                'protocol': 'tcp'
            } for c in connections if c]
            
        except Exception as e:
            logger.error(f"Error getting Windows connections: {e}")
            return []
    
    def _get_linux_connections(self) -> List[Dict]:
        """Get connections on Linux."""
        connections = []
        
        # Read /proc/net/tcp
        try:
            with open('/proc/net/tcp', 'r') as f:
                for line in f.readlines()[1:]:  # Skip header
                    parts = line.strip().split()
                    if len(parts) < 10:
                        continue
                        
                    local = parts[1].split(':')
                    remote = parts[2].split(':')
                    
                    connections.append({
                        'local_ip': self._hex_to_ip(local[0]),
                        'local_port': int(local[1], 16),
                        'remote_ip': self._hex_to_ip(remote[0]),
                        'remote_port': int(remote[1], 16),
                        'state': int(parts[3], 16),
                        'inode': int(parts[9]),
                        'protocol': 'tcp'
                    })
        except Exception as e:
            logger.error(f"Error reading /proc/net/tcp: {e}")
        
        return connections
    
    def _get_darwin_connections(self) -> List[Dict]:
        """Get connections on macOS."""
        try:
            result = subprocess.run(
                ['lsof', '-i', '-n', '-P'],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                logger.error(f"Failed to get connections: {result.stderr}")
                return []
            
            connections = []
            for line in result.stdout.split('\n')[1:]:  # Skip header
                parts = line.split()
                if len(parts) < 9:
                    continue
                
                # Parse connection info (e.g., 192.168.1.1:443->8.8.8.8:12345)
                name = parts[8]
                if '->' in name:  # Outgoing
                    local, remote = name.split('->')
                else:  # Listening
                    local, remote = name, '*:*'
                
                # Parse IP:port
                local_parts = local.rsplit(':', 1)
                remote_parts = remote.rsplit(':', 1)
                
                connections.append({
                    'local_ip': local_parts[0] if local_parts[0] != '*' else '0.0.0.0',
                    'local_port': int(local_parts[1]) if len(local_parts) > 1 else 0,
                    'remote_ip': remote_parts[0] if remote_parts[0] != '*' else '0.0.0.0',
                    'remote_port': int(remote_parts[1]) if len(remote_parts) > 1 else 0,
                    'pid': int(parts[1]),
                    'protocol': parts[7].lower()
                })
            
            return connections
            
        except Exception as e:
            logger.error(f"Error getting macOS connections: {e}")
            return []
    
    def _is_suspicious(self, conn: Dict) -> bool:
        """Check if a connection is suspicious."""
        # Check suspicious IPs
        if conn.get('remote_ip') in self.suspicious_ips:
            return True
            
        # Check suspicious ports
        if conn.get('remote_port') in self.suspicious_ports:
            return True
            
        # Check non-standard ports
        if (conn.get('remote_port') not in self.allowed_ports and 
                not self._is_private_ip(conn.get('remote_ip', ''))):
            return True
            
        return False
    
    @staticmethod
    def _hex_to_ip(hex_str: str) -> str:
        """Convert hex IP to dotted decimal."""
        try:
            # Handle IPv4
            if len(hex_str) == 8:
                return '.'.join([
                    str(int(hex_str[i:i+2], 16)) 
                    for i in range(6, -1, -2)
                ])
            # Handle IPv6 (simplified)
            elif len(hex_str) == 32:
                return ':'.join([
                    hex_str[i:i+4] 
                    for i in range(0, 32, 4)
                ])
            return hex_str
        except Exception:
            return hex_str
    
    @staticmethod
    def _is_private_ip(ip_str: str) -> bool:
        """Check if an IP is in private ranges."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False

def monitor_network(callback: Callable[[Dict], None], 
                   config: Optional[Dict] = None) -> 'NetworkMonitor':
    """
    Start network monitoring with a callback.
    
    Args:
        callback: Function to call with suspicious connections
        config: Optional configuration
        
    Returns:
        NetworkMonitor instance
    """
    monitor = NetworkMonitor(config or {})
    monitor.start(callback)
    return monitor
