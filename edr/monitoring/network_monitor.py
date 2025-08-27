"""
Network monitoring for EDR.
Tracks network connections, listening ports, and network activities.
"""
import socket
import time
import psutil
import ipaddress
from typing import Dict, Any, List, Set, Tuple, Optional
from datetime import datetime
import threading

from .base_monitor import BaseMonitor

class NetworkMonitor(BaseMonitor):
    """Monitors network connections and activities."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the network monitor."""
        super().__init__(config)
        self.scan_interval = float(self.config.get('scan_interval', 5.0))
        self.monitor_listening = self.config.get('monitor_listening_ports', True)
        self.monitor_established = self.config.get('monitor_established_connections', True)
        self.alert_on_suspicious = self.config.get('alert_on_suspicious_ports', True)
        self.suspicious_ports = set(self.config.get('suspicious_ports', []))
        self.private_networks = self._init_private_networks()
        
        # Track known connections
        self.known_connections: Set[Tuple] = set()
        self.known_listeners: Set[Tuple] = set()
    
    def _init_private_networks(self) -> List[ipaddress.IPv4Network]:
        """Initialize list of private network ranges."""
        return [
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12'),
            ipaddress.IPv4Network('192.168.0.0/16'),
            ipaddress.IPv4Network('127.0.0.0/8'),
            ipaddress.IPv4Network('169.254.0.0/16')  # Link-local
        ]
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop for network activities."""
        while self.running:
            try:
                current_connections = set()
                current_listeners = set()
                
                # Get all network connections
                try:
                    connections = psutil.net_connections(kind='inet')
                except (psutil.AccessDenied, psutil.Error) as e:
                    self.logger.error(f"Error getting network connections: {e}")
                    time.sleep(5)  # Wait before retrying
                    continue
                
                for conn in connections:
                    try:
                        # Skip if no address info
                        if not hasattr(conn, 'laddr') or not conn.laddr:
                            continue
                            
                        local_addr, local_port = conn.laddr
                        
                        # Handle listening ports
                        if conn.status == 'LISTEN':
                            if not self.monitor_listening:
                                continue
                                
                            conn_key = ('listen', local_addr, local_port, conn.type)
                            current_listeners.add(conn_key)
                            
                            if conn_key not in self.known_listeners:
                                self._handle_new_listener(conn)
                        
                        # Handle established connections
                        elif hasattr(conn, 'raddr') and conn.raddr:
                            if not self.monitor_established:
                                continue
                                
                            remote_addr, remote_port = conn.raddr
                            conn_key = ('conn', local_addr, local_port, remote_addr, remote_port, conn.type)
                            current_connections.add(conn_key)
                            
                            if conn_key not in self.known_connections:
                                self._handle_new_connection(conn)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError) as e:
                        self.logger.debug(f"Skipping connection due to error: {e}")
                        continue
                
                # Check for closed connections
                for conn_key in self.known_connections - current_connections:
                    self._handle_closed_connection(conn_key)
                
                # Check for closed listeners
                for listen_key in self.known_listeners - current_listeners:
                    self._handle_closed_listener(listen_key)
                
                # Update known connections and listeners
                self.known_connections = current_connections
                self.known_listeners = current_listeners
                
                # Sleep before next scan
                time.sleep(self.scan_interval)
                
            except Exception as e:
                self.logger.error(f"Error in network monitor: {e}", exc_info=True)
                time.sleep(10)  # Avoid tight loop on error
    
    def _handle_new_connection(self, conn: psutil._common.sconn) -> None:
        """Handle a new network connection."""
        try:
            local_addr, local_port = conn.laddr
            remote_addr, remote_port = conn.raddr
            
            # Get process info
            pid = conn.pid or 0
            process_name = ''
            cmdline = ''
            
            if pid > 0:
                try:
                    proc = psutil.Process(pid)
                    with proc.oneshot():
                        process_name = proc.name()
                        cmdline = ' '.join(proc.cmdline())
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            # Check if connection is suspicious
            is_suspicious = self._is_suspicious_connection(conn)
            
            # Create connection event
            event = self._create_event(
                event_type='network_connection',
                data={
                    'local_address': local_addr,
                    'local_port': local_port,
                    'remote_address': remote_addr,
                    'remote_port': remote_port,
                    'protocol': conn.type.upper(),
                    'status': conn.status,
                    'pid': pid,
                    'process_name': process_name,
                    'command_line': cmdline,
                    'is_suspicious': is_suspicious,
                    'is_private': self._is_private_address(remote_addr),
                    'dns_name': self._resolve_dns(remote_addr)
                }
            )
            
            self._notify_handlers(event)
            
            # Generate alert for suspicious connections
            if is_suspicious and self.alert_on_suspicious:
                self._generate_alert('suspicious_connection', {
                    'connection': f"{remote_addr}:{remote_port} -> {local_addr}:{local_port}",
                    'protocol': conn.type.upper(),
                    'process': f"{process_name} (PID: {pid})",
                    'reason': f"Connection to suspicious port {remote_port}"
                })
                
        except Exception as e:
            self.logger.error(f"Error handling new connection: {e}", exc_info=True)
    
    def _handle_closed_connection(self, conn_key: Tuple) -> None:
        """Handle a closed network connection."""
        try:
            _, local_addr, local_port, remote_addr, remote_port, conn_type = conn_key
            
            event = self._create_event(
                event_type='network_connection_closed',
                data={
                    'local_address': local_addr,
                    'local_port': local_port,
                    'remote_address': remote_addr,
                    'remote_port': remote_port,
                    'protocol': conn_type.upper()
                }
            )
            
            self._notify_handlers(event)
            
        except Exception as e:
            self.logger.error(f"Error handling closed connection: {e}", exc_info=True)
    
    def _handle_new_listener(self, conn: psutil._common.sconn) -> None:
        """Handle a new listening port."""
        try:
            local_addr, local_port = conn.laddr
            
            # Get process info
            pid = conn.pid or 0
            process_name = ''
            cmdline = ''
            
            if pid > 0:
                try:
                    proc = psutil.Process(pid)
                    with proc.oneshot():
                        process_name = proc.name()
                        cmdline = ' '.join(proc.cmdline())
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            # Check if listener is suspicious
            is_suspicious = self._is_suspicious_listener(conn)
            
            # Create listener event
            event = self._create_event(
                event_type='network_listener',
                data={
                    'address': local_addr,
                    'port': local_port,
                    'protocol': conn.type.upper(),
                    'pid': pid,
                    'process_name': process_name,
                    'command_line': cmdline,
                    'is_suspicious': is_suspicious
                }
            )
            
            self._notify_handlers(event)
            
            # Generate alert for suspicious listeners
            if is_suspicious and self.alert_on_suspicious:
                self._generate_alert('suspicious_listener', {
                    'listener': f"{local_addr}:{local_port}",
                    'protocol': conn.type.upper(),
                    'process': f"{process_name} (PID: {pid})",
                    'reason': f"Listening on suspicious port {local_port}"
                })
                
        except Exception as e:
            self.logger.error(f"Error handling new listener: {e}", exc_info=True)
    
    def _handle_closed_listener(self, listen_key: Tuple) -> None:
        """Handle a closed listening port."""
        try:
            _, addr, port, conn_type = listen_key
            
            event = self._create_event(
                event_type='network_listener_closed',
                data={
                    'address': addr,
                    'port': port,
                    'protocol': conn_type.upper()
                }
            )
            
            self._notify_handlers(event)
            
        except Exception as e:
            self.logger.error(f"Error handling closed listener: {e}", exc_info=True)
    
    def _is_suspicious_connection(self, conn: psutil._common.sconn) -> bool:
        """Check if a connection is suspicious."""
        if not hasattr(conn, 'raddr') or not conn.raddr:
            return False
            
        _, remote_port = conn.raddr
        return remote_port in self.suspicious_ports
    
    def _is_suspicious_listener(self, conn: psutil._common.sconn) -> bool:
        """Check if a listener is suspicious."""
        if not hasattr(conn, 'laddr') or not conn.laddr:
            return False
            
        _, port = conn.laddr
        return port in self.suspicious_ports
    
    def _is_private_address(self, ip: str) -> bool:
        """Check if an IP address is in a private network range."""
        try:
            addr = ipaddress.IPv4Address(ip)
            return any(addr in network for network in self.private_networks)
        except ipaddress.AddressValueError:
            return False
    
    def _resolve_dns(self, ip: str) -> str:
        """Resolve IP address to hostname."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return ip
    
    def _generate_alert(self, alert_type: str, details: Dict[str, Any]) -> None:
        """Generate a security alert."""
        alert = self._create_event(
            event_type=f'security_alert_{alert_type}',
            data={
                'severity': 'high',
                'details': details,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
        )
        
        self._notify_handlers(alert)
