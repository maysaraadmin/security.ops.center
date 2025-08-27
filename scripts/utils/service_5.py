"""
Network Intrusion Prevention System (NIPS) Service.

This module provides the main NIPS service implementation that monitors and protects
network traffic by detecting and preventing malicious activities.
"""
import asyncio
import socket
import struct
import threading
import time
import signal
import logging
import platform
import os
import ctypes
import select
from typing import Dict, List, Optional, Any, Set, Tuple, Callable
from dataclasses import dataclass, field
from enum import IntEnum, auto
from ipaddress import ip_address, IPv4Address, IPv6Address

from src.common.logging_utils import setup_logger
from src.common.utils import RateLimiter, Timer, run_in_threadpool
from src.common.constants import Protocol, Action, Severity, Status

from src.core.base_service import BaseService
from src.core.interfaces import Service

from src.services.nips.models import NIPSRule, NIPSAlert, NIPSStats, NIPSRuleType
from .rules import NIPSRuleEngine

# Platform-specific constants
class IFF(IntEnum):
    """Network interface flags."""
    IFF_PROMISC = 0x100
    IFF_UP = 0x1

class SIOCGIFFLAGS(ctypes.Structure):
    """Structure for getting interface flags."""
    _fields_ = [
        ('ifr_name', ctypes.c_char * 16),
        ('ifr_flags', ctypes.c_short)
    ]

class SIOCSIFFLAGS(ctypes.Structure):
    """Structure for setting interface flags."""
    _fields_ = [
        ('ifr_name', ctypes.c_char * 16),
        ('ifr_flags', ctypes.c_short)
    ]

class NIPSConfig:
    """Configuration for the NIPS service."""
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize with default or provided configuration."""
        config = config or {}
        self.interface = config.get('interface', 'eth0')
        self.promiscuous = config.get('promiscuous', True)
        self.max_packet_size = config.get('max_packet_size', 65535)
        self.snapshot_length = config.get('snapshot_length', 65535)
        self.timeout = config.get('timeout', 1000)  # ms
        self.buffer_size = config.get('buffer_size', 10 * 1024 * 1024)  # 10MB
        self.default_rule_action = Action(config.get('default_rule_action', 'alert').upper())
        self.default_rule_severity = Severity[config.get('default_rule_severity', 'MEDIUM').upper()]
        self.rules_file = config.get('rules_file', 'config/nips_rules.json')
        self.enable_ipv6 = config.get('enable_ipv6', False)
        self.enable_tcp = config.get('enable_tcp', True)
        self.enable_udp = config.get('enable_udp', True)
        self.enable_icmp = config.get('enable_icmp', True)
        self.alert_threshold = config.get('alert_threshold', 10)  # Alerts per minute
        self.alert_interval = config.get('alert_interval', 60)  # seconds

class NIPSService(BaseService):
    """
    Network Intrusion Prevention System (NIPS) service.
    
    This service monitors network traffic in real-time, analyzes it for malicious
    activities, and takes appropriate actions based on defined rules.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, **kwargs):
        """Initialize the NIPS service."""
        super().__init__(name='nips', **kwargs)
        
        # Configuration
        self.config = NIPSConfig(config or {})
        
        # Network capture state
        self.socket = None
        self.interface = self.config.interface
        self.promiscuous = self.config.promiscuous
        self.running = False
        self.capture_thread = None
        self.stop_event = threading.Event()
        
        # Rule engine
        self.rule_engine = NIPSRuleEngine(logger=self.logger)
        
        # Alert management
        self.alert_callbacks = []
        self.alert_count = 0
        self.last_alert_reset = time.time()
        
        # Load default rules
        self._load_default_rules()
    
    def _load_default_rules(self) -> None:
        """Load default NIPS rules."""
        try:
            # Rule 1: Detect port scanning
            scan_rule = NIPSRule(
                id="nips-001",
                name="Port Scanning Detection",
                description="Detects potential port scanning activity",
                rule_type=NIPSRuleType.RATE,
                protocol=None,
                action=Action.ALERT,
                severity=Severity.HIGH,
                metadata={
                    'rate': 5,  # 5 packets per second
                    'burst': 10,
                    'rate_by_src_ip': True,
                    'rate_by_dst_port': True,
                    'window': 60  # 1 minute window
                }
            )
            self.rule_engine.add_rule(scan_rule)
            
            # Rule 2: Detect SYN flood
            syn_flood_rule = NIPSRule(
                id="nips-002",
                name="SYN Flood Detection",
                description="Detects potential SYN flood attacks",
                rule_type=NIPSRuleType.RATE,
                protocol=Protocol.TCP,
                action=Action.ALERT,
                severity=Severity.HIGH,
                metadata={
                    'rate': 100,  # 100 SYN packets per second
                    'burst': 200,
                    'rate_by_src_ip': True,
                    'tcp_flags': 'S',  # SYN flag set
                    'window': 1  # 1 second window
                }
            )
            self.rule_engine.add_rule(syn_flood_rule)
            
            # Rule 3: Detect DNS amplification
            dns_amp_rule = NIPSRule(
                id="nips-003",
                name="DNS Amplification Detection",
                description="Detects potential DNS amplification attacks",
                rule_type=NIPSRuleType.PROTOCOL,
                protocol=Protocol.UDP,
                destination_ports=[53],
                action=Action.ALERT,
                severity=Severity.HIGH,
                metadata={
                    'min_response_size': 512,  # Bytes
                    'ratio_threshold': 10.0  # Response/request size ratio
                }
            )
            self.rule_engine.add_rule(dns_amp_rule)
            
            self.logger.info(f"Loaded {len(self.rule_engine.rules)} default NIPS rules")
            
        except Exception as e:
            self.logger.error(f"Failed to load default NIPS rules: {e}")
    
    async def _start(self) -> bool:
        """Start the NIPS service."""
        if self.running:
            self.logger.warning("NIPS service is already running")
            return True
        
        try:
            # Initialize network capture
            if not self._init_network_capture():
                self.logger.error("Failed to initialize network capture")
                return False
            
            # Start the capture thread
            self.running = True
            self.stop_event.clear()
            self.capture_thread = threading.Thread(
                target=self._capture_loop,
                name=f"NIPS-Capture-{self.interface}",
                daemon=True
            )
            self.capture_thread.start()
            
            self.logger.info(f"NIPS service started on interface {self.interface}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start NIPS service: {e}", exc_info=True)
            self.running = False
            return False
    
    async def _stop(self) -> bool:
        """Stop the NIPS service."""
        if not self.running:
            return True
        
        try:
            # Signal the capture thread to stop
            self.running = False
            self.stop_event.set()
            
            # Wait for the capture thread to finish
            if self.capture_thread and self.capture_thread.is_alive():
                self.capture_thread.join(timeout=5.0)
                if self.capture_thread.is_alive():
                    self.logger.warning("Capture thread did not stop gracefully")
            
            # Close the socket
            if self.socket:
                try:
                    self.socket.close()
                except Exception as e:
                    self.logger.error(f"Error closing socket: {e}")
                finally:
                    self.socket = None
            
            self.logger.info("NIPS service stopped")
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping NIPS service: {e}", exc_info=True)
            return False
    
    def _init_network_capture(self) -> bool:
        """Initialize network capture on the specified interface."""
        try:
            # Create a raw socket
            if os.name == 'nt':
                # Windows
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.socket.bind((self.interface, 0))
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                # Unix-like systems
                self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
                
                # Set promiscuous mode if requested
                if self.promiscuous:
                    self._set_promiscuous_mode(True)
            
            # Set socket options
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.config.buffer_size)
            self.socket.settimeout(1.0)  # Non-blocking with timeout
            
            self.logger.debug(f"Initialized network capture on {self.interface}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize network capture: {e}")
            if self.socket:
                try:
                    self.socket.close()
                except (OSError, AttributeError) as e:
                    self.logger.debug(f"Error closing socket: {e}")
                finally:
                    self.socket = None
            return False
    
    def _set_promiscuous_mode(self, enable: bool) -> None:
        """Enable or disable promiscuous mode on the interface."""
        if os.name == 'nt':
            # Not supported on Windows
            return
            
        try:
            # Use ioctl to set promiscuous mode
            ifr = SIOCGIFFLAGS()
            ifr.ifr_name = self.interface.encode('utf-8')
            
            # Get current flags
            libc = ctypes.CDLL('libc.so.6')
            libc.ioctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p]
            libc.ioctl.restype = ctypes.c_int
            
            if libc.ioctl(self.socket.fileno(), 0x8913, ctypes.byref(ifr)) < 0:
                raise OSError("Failed to get interface flags")
            
            # Update flags
            if enable:
                ifr.ifr_flags |= IFF.PROMISC
            else:
                ifr.ifr_flags &= ~IFF.PROMISC
            
            # Set new flags
            ifr_set = SIOCSIFFLAGS()
            ifr_set.ifr_name = self.interface.encode('utf-8')
            ifr_set.ifr_flags = ifr.ifr_flags
            
            if libc.ioctl(self.socket.fileno(), 0x8914, ctypes.byref(ifr_set)) < 0:
                raise OSError("Failed to set interface flags")
            
            self.logger.debug(f"{'Enabled' if enable else 'Disabled'} promiscuous mode on {self.interface}")
            
        except Exception as e:
            self.logger.warning(f"Failed to {'enable' if enable else 'disable'} promiscuous mode: {e}")
    
    def _capture_loop(self) -> None:
        """Main packet capture loop."""
        self.logger.info(f"Starting packet capture on {self.interface}")
        
        try:
            while self.running and not self.stop_event.is_set():
                try:
                    # Wait for data with timeout
                    ready, _, _ = select.select([self.socket], [], [], 1.0)
                    if not ready:
                        continue
                    
                    # Receive packet
                    packet, _ = self.socket.recvfrom(self.config.max_packet_size)
                    if not packet:
                        continue
                    
                    # Process packet in a separate thread to avoid blocking
                    self._process_packet(packet)
                    
                except socket.timeout:
                    continue
                except OSError as e:
                    if e.errno == 10038:  # Socket operation on non-socket
                        break
                    self.logger.error(f"Socket error: {e}")
                    time.sleep(1)  # Prevent tight loop on errors
                except Exception as e:
                    self.logger.error(f"Error in capture loop: {e}", exc_info=True)
                    time.sleep(1)  # Prevent tight loop on errors
        
        except Exception as e:
            self.logger.critical(f"Fatal error in capture loop: {e}", exc_info=True)
            self.running = False
        
        finally:
            self.logger.info("Packet capture stopped")
    
    def _process_packet(self, packet: bytes) -> None:
        """Process a captured network packet."""
        try:
            # Parse packet headers (simplified example)
            packet_info = self._parse_packet(packet)
            if not packet_info:
                return
            
            # Process packet through rule engine
            alerts = self.rule_engine.process_packet(packet_info)
            
            # Handle alerts
            for alert in alerts:
                self._handle_alert(alert)
            
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}", exc_info=True)
    
    def _parse_packet(self, packet: bytes) -> Optional[Dict[str, Any]]:
        """Parse a raw network packet and extract relevant information."""
        if len(packet) < 20:  # Minimum IPv4 header size
            return None
        
        try:
            # Parse Ethernet header (if present)
            eth_header = packet[:14]
            eth_proto = struct.unpack('!H', eth_header[12:14])[0]
            
            # Skip to IP header (assume Ethernet II for simplicity)
            ip_header = packet[14:34]  # First 20 bytes of IP header
            
            # Parse IP header
            ip_ihl = (ip_header[0] & 0x0F) * 4  # Header length in bytes
            ip_proto = ip_header[9]  # Protocol (TCP=6, UDP=17, ICMP=1)
            src_ip = socket.inet_ntoa(ip_header[12:16])
            dst_ip = socket.inet_ntoa(ip_header[16:20])
            
            # Map protocol number to Protocol enum
            protocol_map = {
                1: Protocol.ICMP,
                6: Protocol.TCP,
                17: Protocol.UDP
            }
            protocol = protocol_map.get(ip_proto, Protocol.OTHER)
            
            # Parse transport layer (TCP/UDP) or ICMP
            src_port = 0
            dst_port = 0
            tcp_flags = 0
            payload_offset = 14 + ip_ihl  # Ethernet + IP header
            
            if protocol == Protocol.TCP and len(packet) >= payload_offset + 20:
                # Parse TCP header (first 20 bytes)
                tcp_header = packet[payload_offset:payload_offset+20]
                src_port = struct.unpack('!H', tcp_header[0:2])[0]
                dst_port = struct.unpack('!H', tcp_header[2:4])[0]
                data_offset = (tcp_header[12] >> 4) * 4  # TCP header length in bytes
                tcp_flags = tcp_header[13]  # TCP flags
                payload_offset += data_offset
            elif protocol == Protocol.UDP and len(packet) >= payload_offset + 8:
                # Parse UDP header (8 bytes)
                udp_header = packet[payload_offset:payload_offset+8]
                src_port = struct.unpack('!H', udp_header[0:2])[0]
                dst_port = struct.unpack('!H', udp_header[2:4])[0]
                payload_offset += 8
            
            # Extract payload
            payload = packet[payload_offset:] if len(packet) > payload_offset else b''
            
            return {
                'timestamp': time.time(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'length': len(packet),
                'tcp_flags': tcp_flags,
                'payload': payload,
                'raw': packet
            }
            
        except Exception as e:
            self.logger.debug(f"Error parsing packet: {e}")
            return None
    
    def _handle_alert(self, alert: NIPSAlert) -> None:
        """Handle a generated alert."""
        try:
            # Update alert count and check rate limiting
            current_time = time.time()
            if current_time - self.last_alert_reset > self.config.alert_interval:
                self.alert_count = 0
                self.last_alert_reset = current_time
            
            self.alert_count += 1
            
            # Log the alert
            self.logger.warning(
                f"NIPS Alert: {alert.rule_name} - {alert.packet_summary} "
                f"(Severity: {alert.severity.name}, Action: {alert.action_taken.value})"
            )
            
            # Execute alert callbacks
            for callback in self.alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    self.logger.error(f"Error in alert callback: {e}", exc_info=True)
            
            # Take action based on alert
            if alert.action_taken in (Action.DROP, Action.REJECT, Action.BLOCK):
                # In a real implementation, you would block the connection here
                # using iptables, Windows Filtering Platform, or similar
                self.logger.info(f"Blocking connection: {alert.packet_summary}")
            
        except Exception as e:
            self.logger.error(f"Error handling alert: {e}", exc_info=True)
    
    def add_alert_callback(self, callback: Callable[[NIPSAlert], None]) -> None:
        """Add a callback function to be called when an alert is generated."""
        if callback not in self.alert_callbacks:
            self.alert_callbacks.append(callback)
    
    def remove_alert_callback(self, callback: Callable[[NIPSAlert], None]) -> None:
        """Remove an alert callback function."""
        if callback in self.alert_callbacks:
            self.alert_callbacks.remove(callback)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current statistics about the NIPS service."""
        stats = self.rule_engine.get_statistics()
        return {
            'status': 'running' if self.running else 'stopped',
            'interface': self.interface,
            'packets_processed': stats.packets_processed,
            'packets_dropped': stats.packets_dropped,
            'alerts_triggered': stats.alerts_triggered,
            'rules_loaded': stats.rules_loaded,
            'rules_active': stats.rules_active,
            'network_throughput': stats.network_throughput,
            'cpu_usage': stats.cpu_usage,
            'memory_usage': stats.memory_usage,
            'timestamp': stats.timestamp.isoformat()
        }
    
    def get_recent_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get the most recent alerts."""
        alerts = self.rule_engine.get_recent_alerts(limit)
        return [alert.to_dict() for alert in alerts]
    
    def add_rule(self, rule: Dict[str, Any]) -> bool:
        """Add a new rule to the NIPS engine."""
        try:
            nips_rule = NIPSRule.from_dict(rule)
            return self.rule_engine.add_rule(nips_rule)
        except Exception as e:
            self.logger.error(f"Failed to add rule: {e}", exc_info=True)
            return False
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule from the NIPS engine."""
        return self.rule_engine.remove_rule(rule_id)
    
    def enable_rule(self, rule_id: str, enabled: bool = True) -> bool:
        """Enable or disable a rule."""
        return self.rule_engine.enable_rule(rule_id, enabled)
    
    def get_rules(self) -> List[Dict[str, Any]]:
        """Get all rules."""
        return [rule.to_dict() for rule in self.rule_engine.rules.values()]
    
    def get_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific rule by ID."""
        rule = self.rule_engine.rules.get(rule_id)
        return rule.to_dict() if rule else None
    
    def clear_rules(self) -> None:
        """Remove all rules."""
        for rule_id in list(self.rule_engine.rules.keys()):
            self.rule_engine.remove_rule(rule_id)
    
    def load_rules_from_file(self, file_path: str = None) -> bool:
        """Load rules from a JSON file."""
        file_path = file_path or self.config.rules_file
        
        try:
            with open(file_path, 'r') as f:
                rules_data = json.load(f)
            
            if not isinstance(rules_data, list):
                self.logger.error("Rules file should contain a list of rules")
                return False
            
            # Clear existing rules
            self.clear_rules()
            
            # Add new rules
            success_count = 0
            for rule_data in rules_data:
                try:
                    rule = NIPSRule.from_dict(rule_data)
                    if self.rule_engine.add_rule(rule):
                        success_count += 1
                except Exception as e:
                    self.logger.error(f"Failed to load rule: {e}")
            
            self.logger.info(f"Loaded {success_count}/{len(rules_data)} rules from {file_path}")
            return success_count > 0
            
        except Exception as e:
            self.logger.error(f"Failed to load rules from {file_path}: {e}")
            return False
    
    def save_rules_to_file(self, file_path: str = None) -> bool:
        """Save current rules to a JSON file."""
        file_path = file_path or self.config.rules_file
        
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
            
            # Convert rules to dicts
            rules_data = [rule.to_dict() for rule in self.rule_engine.rules.values()]
            
            # Write to file
            with open(file_path, 'w') as f:
                json.dump(rules_data, f, indent=2)
            
            self.logger.info(f"Saved {len(rules_data)} rules to {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save rules to {file_path}: {e}")
            return False
    
    def reset_statistics(self) -> None:
        """Reset all statistics counters."""
        self.rule_engine.reset_statistics()
        self.alert_count = 0
        self.last_alert_reset = time.time()
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the NIPS service."""
        stats = self.rule_engine.get_statistics()
        
        return {
            'status': 'running' if self.running else 'stopped',
            'interface': self.interface,
            'promiscuous': self.promiscuous,
            'rules_loaded': stats.rules_loaded,
            'rules_active': stats.rules_active,
            'alerts_triggered': stats.alerts_triggered,
            'packets_processed': stats.packets_processed,
            'packets_dropped': stats.packets_dropped,
            'network_throughput': stats.network_throughput,
            'cpu_usage': stats.cpu_usage,
            'memory_usage': stats.memory_usage,
            'uptime': (time.time() - self.start_time) if hasattr(self, 'start_time') else 0,
            'timestamp': stats.timestamp.isoformat()
        }
    
    def __del__(self):
        """Clean up resources."""
        if hasattr(self, 'running') and self.running:
            self.stop()
        
        if hasattr(self, 'socket') and self.socket:
            try:
                self.socket.close()
            except (OSError, AttributeError) as e:
                self.logger.debug(f"Error closing socket during cleanup: {e}")
            finally:
                self.socket = None

# Factory function for service registration
def create_nips_service(config: Optional[Dict[str, Any]] = None, **kwargs) -> NIPSService:
    """Create and return a new NIPS service instance."""
    return NIPSService(config=config, **kwargs)
