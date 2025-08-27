"""
Network Monitor Module

This module provides network monitoring capabilities for the HIPS system,
tracking network connections, monitoring traffic, and enforcing network policies.
"""

import os
import re
import time
import socket
import struct
import logging
import ipaddress
import threading
import subprocess
from typing import Dict, List, Optional, Set, Tuple, Callable, Any, Union
from dataclasses import dataclass, field

import psutil

# Platform-specific imports
try:
    import win32com.client
    WINDOWS = True
except ImportError:
    WINDOWS = False

logger = logging.getLogger('hips.network_monitor')

@dataclass
class NetworkConnection:
    """Represents a network connection."""
    proto: str
    laddr: str
    lport: int
    raddr: str
    rport: int
    status: str
    pid: int
    process_name: str
    username: str
    create_time: float
    last_seen: float = field(default_factory=time.time)
    bytes_sent: int = 0
    bytes_recv: int = 0

class NetworkMonitor:
    """Monitors network connections and traffic."""
    
    def __init__(self, config: Dict, event_logger: 'EventLogger', 
                 response_engine: 'ResponseEngine', policy_manager: 'PolicyManager'):
        self.config = config
        self.enabled = config.get('enabled', True)
        self.scan_interval = config.get('scan_interval', 5.0)
        
        self.event_logger = event_logger
        self.response_engine = response_engine
        self.policy_manager = policy_manager
        
        self.running = False
        self._stop_event = threading.Event()
        self._monitor_thread = None
        self._connections: Dict[Tuple, NetworkConnection] = {}
        self._connection_lock = threading.RLock()
        
        # Threat intelligence
        self._threat_intel = {
            'malicious_ips': set(),
            'suspicious_domains': set(),
            'last_updated': 0
        }
        
        self._load_threat_intel()
        logger.info("Network monitor initialized")
    
    def start(self):
        """Start the network monitor."""
        if not self.enabled:
            logger.info("Network monitor is disabled")
            return
            
        if self.running:
            logger.warning("Network monitor is already running")
            return
            
        logger.info("Starting network monitor...")
        self.running = True
        self._stop_event.clear()
        
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="NetworkMonitor",
            daemon=True
        )
        self._monitor_thread.start()
        
        self._setup_firewall()
        logger.info("Network monitor started")
    
    def stop(self):
        """Stop the network monitor."""
        if not self.running:
            return
            
        logger.info("Stopping network monitor...")
        self.running = False
        self._stop_event.set()
        
        if self._monitor_thread:
            self._monitor_thread.join(5.0)
            
        self._cleanup_firewall()
        logger.info("Network monitor stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while not self._stop_event.is_set():
            try:
                self._scan_connections()
                self._check_suspicious_activities()
                self._update_threat_intel()
                self._stop_event.wait(self.scan_interval)
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}", exc_info=True)
                time.sleep(1)
    
    def _scan_connections(self):
        """Scan and update network connections."""
        current_conns = set()
        
        for conn in psutil.net_connections(kind='inet'):
            try:
                if not conn.raddr or not conn.laddr:
                    continue
                    
                proto = 'tcp' if conn.type == socket.SOCK_STREAM else 'udp'
                conn_key = (proto, conn.laddr.ip, conn.laddr.port, 
                           conn.raddr.ip, conn.raddr.port, conn.pid)
                
                current_conns.add(conn_key)
                
                if conn_key not in self._connections:
                    try:
                        proc = psutil.Process(conn.pid)
                        process_name = proc.name()
                        username = proc.username()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        process_name = "unknown"
                        username = "unknown"
                    
                    new_conn = NetworkConnection(
                        proto=proto,
                        laddr=conn.laddr.ip,
                        lport=conn.laddr.port,
                        raddr=conn.raddr.ip,
                        rport=conn.raddr.port,
                        status=conn.status,
                        pid=conn.pid,
                        process_name=process_name,
                        username=username,
                        create_time=time.time()
                    )
                    
                    with self._connection_lock:
                        self._connections[conn_key] = new_conn
                    
                    self._log_connection(new_conn, 'connection_opened')
                    self._check_connection(new_conn)
                
            except Exception as e:
                logger.error(f"Error processing connection: {e}")
        
        self._check_closed_connections(current_conns)
    
    def _check_connection(self, conn: NetworkConnection):
        """Check if a connection is suspicious."""
        if conn.raddr in self._threat_intel['malicious_ips']:
            self._handle_malicious_connection(conn, 'malicious_ip')
        elif self._is_suspicious_domain(conn.raddr):
            self._handle_malicious_connection(conn, 'suspicious_domain')
    
    def _is_suspicious_domain(self, ip: str) -> bool:
        """Check if an IP resolves to a suspicious domain."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return any(d in hostname for d in self._threat_intel['suspicious_domains'])
        except (socket.herror, socket.gaierror):
            return False
    
    def _handle_malicious_connection(self, conn: NetworkConnection, reason: str):
        """Handle connection to malicious destination."""
        self._log_security_event(
            conn,
            'malicious_connection',
            f"Connection to {reason}: {conn.raddr}",
            'high'
        )
        
        if self.config.get('block_malicious_ips', True):
            self._block_connection(conn)
    
    def _block_connection(self, conn: NetworkConnection):
        """Block a network connection."""
        if WINDOWS:
            self._block_windows(conn)
        else:
            self._block_linux(conn)
    
    def _block_linux(self, conn: NetworkConnection):
        """Block connection on Linux using iptables."""
        try:
            cmd = [
                'iptables',
                '-A', 'OUTPUT',
                '-p', conn.proto,
                '-d', conn.raddr,
                '--dport', str(conn.rport),
                '-j', 'DROP'
            ]
            subprocess.run(cmd, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block connection: {e.stderr.decode()}")
    
    def _block_windows(self, conn: NetworkConnection):
        """Block connection on Windows using Windows Firewall."""
        try:
            fw_mgr = win32com.client.Dispatch("HNetCfg.FwMgr")
            profile = fw_mgr.LocalPolicy.CurrentProfile
            
            fw_rule = win32com.client.Dispatch("HNetCfg.FWRule")
            rule_name = f"Block {conn.raddr}:{conn.rport}"
            
            fw_rule.Name = rule_name
            fw_rule.Protocol = 6 if conn.proto == 'tcp' else 17
            fw_rule.RemoteAddresses = conn.raddr
            fw_rule.RemotePorts = str(conn.rport)
            fw_rule.Direction = 2  # Outbound
            fw_rule.Enabled = True
            fw_rule.Action = 0  # Block
            
            profile.Rules.Add(fw_rule)
        except Exception as e:
            logger.error(f"Failed to create Windows Firewall rule: {e}")
    
    def _log_connection(self, conn: NetworkConnection, event_type: str):
        """Log a connection event."""
        event = {
            'event_type': event_type,
            'timestamp': time.time(),
            'local': f"{conn.laddr}:{conn.lport}",
            'remote': f"{conn.raddr}:{conn.rport}",
            'proto': conn.proto,
            'pid': conn.pid,
            'process': conn.process_name,
            'user': conn.username
        }
        self.event_logger.log('network', event)
    
    def _log_security_event(self, conn: NetworkConnection, event_type: str, 
                          message: str, severity: str):
        """Log a security event."""
        event = {
            'event_type': event_type,
            'timestamp': time.time(),
            'severity': severity,
            'message': message,
            'local': f"{conn.laddr}:{conn.lport}",
            'remote': f"{conn.raddr}:{conn.rport}",
            'proto': conn.proto,
            'pid': conn.pid,
            'process': conn.process_name
        }
        self.event_logger.log('security', event)
        
        if severity in ['high', 'critical']:
            self.response_engine.handle_security_event(event)
    
    def _load_threat_intel(self):
        """Load threat intelligence data."""
        # In a real implementation, this would load from a file or API
        self._threat_intel['malicious_ips'].update([
            '1.1.1.1',  # Example malicious IPs
            '2.2.2.2',
        ])
        
        self._threat_intel['suspicious_domains'].update([
            'malicious-domain.com',
            'c2-server.net'
        ])
    
    def _update_threat_intel(self):
        """Periodically update threat intelligence."""
        if time.time() - self._threat_intel['last_updated'] > 3600:  # 1 hour
            logger.info("Updating threat intelligence...")
            self._load_threat_intel()
            self._threat_intel['last_updated'] = time.time()
    
    def _check_closed_connections(self, current_conns: set):
        """Check for and handle closed connections."""
        with self._connection_lock:
            closed = set(self._connections.keys()) - current_conns
            for conn_key in closed:
                conn = self._connections[conn_key]
                self._log_connection(conn, 'connection_closed')
                del self._connections[conn_key]
    
    def _setup_firewall(self):
        """Set up firewall rules for monitoring."""
        if not WINDOWS:
            self._setup_linux_firewall()
    
    def _setup_linux_firewall(self):
        """Set up Linux firewall rules."""
        try:
            # Create HIPS chain if it doesn't exist
            subprocess.run(
                ['iptables', '-N', 'HIPS'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
            
            # Add HIPS chain to OUTPUT chain if not present
            result = subprocess.run(
                ['iptables', '-C', 'OUTPUT', '-j', 'HIPS'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            if result.returncode != 0:
                subprocess.run(
                    ['iptables', '-A', 'OUTPUT', '-j', 'HIPS'],
                    check=True
                )
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to set up firewall: {e}")
    
    def _cleanup_firewall(self):
        """Clean up firewall rules."""
        if not WINDOWS:
            self._cleanup_linux_firewall()
    
    def _cleanup_linux_firewall(self):
        """Clean up Linux firewall rules."""
        try:
            # Flush and remove HIPS chain
            subprocess.run(
                ['iptables', '-F', 'HIPS'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
            
            subprocess.run(
                ['iptables', '-D', 'OUTPUT', '-j', 'HIPS'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
            
            subprocess.run(
                ['iptables', '-X', 'HIPS'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
            
        except Exception as e:
            logger.error(f"Error cleaning up firewall: {e}")
    
    def get_active_connections(self) -> List[Dict]:
        """Get a list of active network connections."""
        with self._connection_lock:
            return [
                {
                    'local': f"{conn.laddr}:{conn.lport}",
                    'remote': f"{conn.raddr}:{conn.rport}",
                    'proto': conn.proto,
                    'status': conn.status,
                    'pid': conn.pid,
                    'process': conn.process_name,
                    'user': conn.username,
                    'start_time': conn.create_time
                }
                for conn in self._connections.values()
            ]
    
    def block_ip(self, ip: str, reason: str = '') -> bool:
        """Block all connections to/from a specific IP address."""
        try:
            if WINDOWS:
                return self._block_ip_windows(ip, reason)
            else:
                return self._block_ip_linux(ip, reason)
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False
    
    def _block_ip_linux(self, ip: str, reason: str) -> bool:
        """Block IP on Linux using iptables."""
        try:
            # Block incoming
            subprocess.run(
                ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                check=True
            )
            
            # Block outgoing
            subprocess.run(
                ['iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'],
                check=True
            )
            
            # Add to malicious IPs
            with self._connection_lock:
                self._threat_intel['malicious_ips'].add(ip)
                
            logger.info(f"Blocked IP: {ip} - {reason}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False
    
    def _block_ip_windows(self, ip: str, reason: str) -> bool:
        """Block IP on Windows using Windows Firewall."""
        try:
            fw_mgr = win32com.client.Dispatch("HNetCfg.FwMgr")
            profile = fw_mgr.LocalPolicy.CurrentProfile
            
            # Create inbound rule
            fw_rule = win32com.client.Dispatch("HNetCfg.FWRule")
            fw_rule.Name = f"Block {ip} (Inbound)"
            fw_rule.Description = f"Block inbound from {ip}. Reason: {reason}"
            fw_rule.Protocol = 256  # Any protocol
            fw_rule.RemoteAddresses = ip
            fw_rule.Direction = 1  # Inbound
            fw_rule.Enabled = True
            fw_rule.Action = 0  # Block
            profile.Rules.Add(fw_rule)
            
            # Create outbound rule
            fw_rule = win32com.client.Dispatch("HNetCfg.FWRule")
            fw_rule.Name = f"Block {ip} (Outbound)"
            fw_rule.Description = f"Block outbound to {ip}. Reason: {reason}"
            fw_rule.Protocol = 256  # Any protocol
            fw_rule.RemoteAddresses = ip
            fw_rule.Direction = 2  # Outbound
            fw_rule.Enabled = True
            fw_rule.Action = 0  # Block
            profile.Rules.Add(fw_rule)
            
            # Add to malicious IPs
            with self._connection_lock:
                self._threat_intel['malicious_ips'].add(ip)
                
            logger.info(f"Blocked IP: {ip} - {reason}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False
