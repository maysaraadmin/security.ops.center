"""
Syslog Collector for SIEM.
Collects logs from syslog servers.
"""
import socket
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import select

from .base import BaseCollector

class SyslogCollector(BaseCollector):
    """Collects logs from a syslog server."""
    
    def _setup(self) -> None:
        """Set up the syslog collector."""
        self.config.setdefault('host', '0.0.0.0')
        self.config.setdefault('port', 514)
        self.config.setdefault('protocol', 'udp')  # 'udp' or 'tcp'
        self.config.setdefault('timeout', 5)
        self.config.setdefault('max_buffer_size', 65535)
        
        self.socket = None
        self.running = False
        self._setup_socket()
    
    def _setup_socket(self) -> None:
        """Set up the syslog socket."""
        try:
            if self.config['protocol'].lower() == 'udp':
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.socket.bind((self.config['host'], self.config['port']))
            else:  # TCP
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.socket.bind((self.config['host'], self.config['port']))
                self.socket.listen(5)
            
            self.logger.info(f"Syslog server listening on {self.config['host']}:{self.config['port']} ({self.config['protocol'].upper()})")
            
        except Exception as e:
            self.logger.error(f"Failed to set up syslog server: {e}")
            raise
    
    def _parse_syslog(self, data: bytes, addr: Tuple[str, int]) -> Optional[Dict[str, Any]]:
        """Parse a syslog message into a structured format.
        
        Args:
            data: Raw syslog data
            addr: Tuple of (ip, port) of the sender
            
        Returns:
            Parsed log entry or None if parsing failed
        """
        try:
            # Basic syslog parsing - can be enhanced for specific formats
            message = data.decode('utf-8', errors='replace').strip()
            
            # Create a basic log entry
            entry = {
                "@timestamp": datetime.utcnow().isoformat() + "Z",
                "message": message,
                "source": {
                    "ip": addr[0],
                    "port": addr[1]
                },
                "event": {
                    "kind": "event",
                    "category": ["network"],
                    "type": ["connection", "protocol"],
                    "dataset": "syslog"
                },
                "log": {
                    "syslog": {
                        "facility": "user",
                        "severity": "info"
                    }
                }
            }
            
            # Try to extract priority, timestamp, hostname, etc. from the message
            # This is a simplified version - real implementation should handle RFC 3164/5424
            if message.startswith('<'):
                try:
                    # Extract priority
                    end_pri = message.index('>')
                    pri = int(message[1:end_pri])
                    entry['log']['syslog']['priority'] = pri
                    entry['log']['syslog']['facility'] = pri // 8
                    entry['log']['syslog']['severity'] = pri % 8
                    
                    # Rest of the message
                    message = message[end_pri+1:].strip()
                    entry['message'] = message
                    
                    # Try to extract timestamp and hostname
                    parts = message.split(' ', 2)
                    if len(parts) >= 2:
                        # This is a simplified timestamp parser
                        entry['@timestamp'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z')
                        entry['host'] = {"hostname": parts[1]}
                        entry['message'] = parts[2] if len(parts) > 2 else ''
                        
                except (ValueError, IndexError) as e:
                    self.logger.debug(f"Error parsing syslog message: {e}")
            
            return entry
            
        except Exception as e:
            self.logger.error(f"Error parsing syslog message: {e}")
            return None
    
    def collect(self) -> List[Dict[str, Any]]:
        """Collect logs from the syslog server."""
        entries = []
        
        try:
            # Set timeout for non-blocking operation
            self.socket.settimeout(self.config['timeout'])
            
            if self.config['protocol'].lower() == 'udp':
                # For UDP, just receive one packet
                try:
                    data, addr = self.socket.recvfrom(self.config['max_buffer_size'])
                    entry = self._parse_syslog(data, addr)
                    if entry:
                        entries.append(entry)
                except socket.timeout:
                    pass  # No data received, return empty list
                except Exception as e:
                    self.logger.error(f"Error receiving UDP data: {e}")
            
            else:  # TCP
                # Check for new connections
                ready, _, _ = select.select([self.socket], [], [], self.config['timeout'])
                if ready:
                    conn, addr = self.socket.accept()
                    try:
                        conn.settimeout(self.config['timeout'])
                        data = conn.recv(self.config['max_buffer_size'])
                        if data:
                            entry = self._parse_syslog(data, addr)
                            if entry:
                                entries.append(entry)
                    except Exception as e:
                        self.logger.error(f"Error handling TCP connection: {e}")
                    finally:
                        conn.close()
            
            return entries
            
        except Exception as e:
            self.logger.error(f"Error in syslog collection: {e}")
            return []
    
    def start(self) -> None:
        """Start the syslog collector."""
        if not self.running:
            super().start()
            self.running = True
    
    def stop(self) -> None:
        """Stop the syslog collector."""
        if self.running:
            self.running = False
            if self.socket:
                try:
                    self.socket.close()
                except Exception as e:
                    self.logger.error(f"Error closing socket: {e}")
            super().stop()
    
    def status(self) -> Dict[str, Any]:
        """Get the status of the collector."""
        status = super().status()
        status.update({
            'type': 'syslog',
            'running': self.running,
            'config': {
                'host': self.config['host'],
                'port': self.config['port'],
                'protocol': self.config['protocol']
            }
        })
        return status
