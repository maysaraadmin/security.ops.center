"""
Network Firewall for HIPS

Monitors and controls network traffic at the host level.
Blocks communication with malicious IPs, C2 servers, and suspicious domains.
"""

import socket
import struct
import logging
import threading
import time
import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple, Callable, Any
from datetime import datetime
import json

# Platform-specific imports
try:
    import pcapy
    import dpkt
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Windows specific
if os.name == 'nt':
    try:
        import pydivert
        PYDIVERT_AVAILABLE = True
    except ImportError:
        PYDIVERT_AVAILABLE = False
else:
    PYDIVERT_AVAILABLE = False

logger = logging.getLogger(__name__)

class Protocol(Enum):
    """Network protocols."""
    TCP = auto()
    UDP = auto()
    ICMP = auto()
    OTHER = auto()

class Direction(Enum):
    """Traffic direction."""
    INBOUND = auto()
    OUTBOUND = auto()
    BOTH = auto()

class Action(Enum):
    """Firewall actions."""
    ALLOW = auto()
    BLOCK = auto()
    ALERT = auto()
    QUARANTINE = auto()

@dataclass
class NetworkEvent:
    """Represents a network connection event."""
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: Protocol
    direction: Direction
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    size: int = 0
    payload: bytes = b''
    action: Action = Action.ALLOW
    reason: str = ''
    metadata: Dict[str, Any] = field(default_factory=dict)

class NetworkFirewall:
    """
    Host-based network firewall for monitoring and controlling network traffic.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the network firewall."""
        self.config = config or {}
        self.running = False
        self._lock = threading.RLock()
        self._rules: List[Dict] = []
        self._blocked_ips: Set[str] = set()
        self._blocked_domains: Set[str] = set()
        self._allowed_ips: Set[str] = set()
        self._allowed_domains: Set[str] = set()
        self._alert_handlers: List[Callable[[NetworkEvent], None]] = []
        self._process_cache: Dict[int, Tuple[str, str]] = {}  # pid -> (name, exe)
        
        # Load default rules
        self._load_default_rules()
        
        # Initialize platform-specific components
        self._init_platform()
    
    def _init_platform(self):
        """Initialize platform-specific components."""
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available. Some features may be limited.")
        
        if os.name == 'nt' and not PYDIVERT_AVAILABLE:
            logger.warning("pydivert not available. Windows packet filtering will be limited.")
    
    def _load_default_rules(self):
        """Load default firewall rules."""
        # Block known malicious IPs and domains
        self._load_threat_intel()
        
        # Add default allow rules for critical system processes
        self.add_rule({
            'name': 'Allow loopback',
            'src_ips': ['127.0.0.1', '::1'],
            'action': 'allow',
            'priority': 1000
        })
        
        # Block known malicious traffic
        self.add_rule({
            'name': 'Block known malicious IPs',
            'src_ips': list(self._blocked_ips),
            'action': 'block',
            'reason': 'Known malicious IP',
            'priority': 100
        })
        
        # Add more default rules as needed
    
    def _load_threat_intel(self):
        """Load threat intelligence data (IPs, domains, etc.)."""
        # In a real implementation, this would load from external threat feeds
        # For now, we'll use some example data
        self._blocked_ips.update([
            '1.1.1.1',  # Example malicious IP
            '2.2.2.2',
            '3.3.3.3'
        ])
        
        self._blocked_domains.update([
            'malicious-domain.com',
            'c2-server.org',
            'evil-hacker.net'
        ])
        
        # Load from file if configured
        threat_intel_file = self.config.get('threat_intel_file')
        if threat_intel_file and os.path.exists(threat_intel_file):
            self._load_threat_intel_from_file(threat_intel_file)
    
    def _load_threat_intel_from_file(self, file_path: str):
        """Load threat intelligence from a file."""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
                if 'ips' in data:
                    self._blocked_ips.update(data['ips'])
                if 'domains' in data:
                    self._blocked_domains.update(data['domains'])
                if 'rules' in data and isinstance(data['rules'], list):
                    for rule in data['rules']:
                        self.add_rule(rule)
                        
        except Exception as e:
            logger.error(f"Error loading threat intel from {file_path}: {e}")
    
    def add_rule(self, rule: Dict):
        """Add a firewall rule.
        
        Args:
            rule: Dictionary containing rule parameters:
                - name: Rule name
                - src_ips: List of source IPs/CIDRs
                - dst_ips: List of destination IPs/CIDRs
                - src_ports: List of source ports
                - dst_ports: List of destination ports
                - protocol: 'tcp', 'udp', 'icmp', or 'any'
                - direction: 'inbound', 'outbound', or 'both'
                - action: 'allow', 'block', 'alert', or 'quarantine'
                - priority: Rule priority (lower numbers = higher priority)
                - reason: Reason for the rule
        """
        with self._lock:
            # Set default values
            rule.setdefault('enabled', True)
            rule.setdefault('priority', 1000)
            rule.setdefault('action', 'block')
            rule.setdefault('direction', 'both')
            rule.setdefault('protocol', 'any')
            
            # Add the rule and sort by priority
            self._rules.append(rule)
            self._rules.sort(key=lambda x: x['priority'])
    
    def block_ip(self, ip: str, reason: str = '', duration: int = 0):
        """Block an IP address."""
        with self._lock:
            self._blocked_ips.add(ip)
            
        # Schedule unblock if duration is specified
        if duration > 0:
            def unblock():
                time.sleep(duration)
                self.unblock_ip(ip)
                
            threading.Thread(target=unblock, daemon=True).start()
    
    def unblock_ip(self, ip: str):
        """Unblock an IP address."""
        with self._lock:
            if ip in self._blocked_ips:
                self._blocked_ips.remove(ip)
    
    def block_domain(self, domain: str):
        """Block a domain."""
        with self._lock:
            self._blocked_domains.add(domain.lower())
    
    def unblock_domain(self, domain: str):
        """Unblock a domain."""
        with self._lock:
            domain = domain.lower()
            if domain in self._blocked_domains:
                self._blocked_domains.remove(domain)
    
    def add_alert_handler(self, handler: Callable[[NetworkEvent], None]):
        """Add a callback function to handle network events."""
        self._alert_handlers.append(handler)
    
    def start(self):
        """Start the network firewall."""
        if self.running:
            return
            
        self.running = True
        
        # Start packet capture thread
        self._capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._capture_thread.start()
        
        # Start Windows packet filtering if available
        if os.name == 'nt' and PYDIVERT_AVAILABLE:
            self._start_windows_filter()
        
        logger.info("Network Firewall started")
    
    def stop(self):
        """Stop the network firewall."""
        self.running = False
        
        # Stop Windows packet filtering if running
        if hasattr(self, '_win_filter') and self._win_filter:
            self._win_filter.stop()
            
        logger.info("Network Firewall stopped")
    
    def _start_windows_filter(self):
        """Start Windows packet filtering using WinDivert."""
        if not PYDIVERT_AVAILABLE:
            return
            
        def filter_loop():
            with pydivert.WinDivert("tcp or udp or icmp") as w:
                self._win_filter = w
                for packet in w:
                    if not self.running:
                        break
                        
                    # Process the packet
                    event = self._process_packet(packet)
                    
                    # Apply actions
                    if event.action == Action.BLOCK:
                        continue  # Drop the packet
                    elif event.action == Action.QUARANTINE:
                        # In a real implementation, we would quarantine the process
                        logger.warning(f"Quarantining connection: {event}")
                        continue
                    
                    # Forward the packet
                    w.send(packet)
        
        # Start the filter thread
        self._win_filter_thread = threading.Thread(target=filter_loop, daemon=True)
        self._win_filter_thread.start()
    
    def _capture_loop(self):
        """Main packet capture loop."""
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available. Network monitoring will be limited.")
            return
            
        # Use a simple packet capture approach with scapy
        def packet_callback(packet):
            if not self.running:
                return
                
            try:
                self._process_packet_scapy(packet)
            except Exception as e:
                logger.error(f"Error processing packet: {e}", exc_info=True)
        
        # Start capturing packets
        try:
            sniff(prn=packet_callback, store=0, stop_filter=lambda x: not self.running)
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
    
    def _process_packet_scapy(self, packet):
        """Process a packet captured by Scapy."""
        # Extract basic packet information
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Determine direction
            is_local = any(ipaddress.ip_address(src_ip) in iface['addrs'] 
                          for iface in self._get_network_interfaces().values())
            direction = Direction.OUTBOUND if is_local else Direction.INBOUND
            
            # Get protocol and ports
            proto = Protocol.OTHER
            src_port = None
            dst_port = None
            
            if TCP in packet:
                proto = Protocol.TCP
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                proto = Protocol.UDP
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif ICMP in packet:
                proto = Protocol.ICMP
            
            # Create network event
            event = NetworkEvent(
                timestamp=time.time(),
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=proto,
                direction=direction,
                size=len(packet),
                action=Action.ALLOW
            )
            
            # Apply rules to the event
            self._apply_rules(event)
            
            # Handle the event
            self._handle_network_event(event)
    
    def _process_packet(self, packet) -> NetworkEvent:
        """Process a network packet and return a NetworkEvent."""
        # This is a simplified version for WinDivert
        # In a real implementation, you would parse the packet and create a NetworkEvent
        # For now, we'll return a dummy event
        return NetworkEvent(
            timestamp=time.time(),
            src_ip='0.0.0.0',
            src_port=0,
            dst_ip='0.0.0.0',
            dst_port=0,
            protocol=Protocol.OTHER,
            direction=Direction.BOTH,
            action=Action.ALLOW
        )
    
    def _apply_rules(self, event: NetworkEvent):
        """Apply firewall rules to a network event."""
        with self._lock:
            for rule in self._rules:
                if not rule.get('enabled', True):
                    continue
                
                # Check if this rule matches the event
                if self._rule_matches(event, rule):
                    # Apply the rule action
                    action = rule.get('action', 'block').upper()
                    event.action = Action[action]
                    event.reason = rule.get('reason', 'Matched firewall rule')
                    
                    # Stop processing rules if this is a terminal action
                    if event.action in [Action.BLOCK, Action.QUARANTINE]:
                        break
    
    def _rule_matches(self, event: NetworkEvent, rule: Dict) -> bool:
        """Check if a rule matches a network event."""
        # Check direction
        if 'direction' in rule:
            rule_dir = rule['direction'].upper()
            if rule_dir != 'BOTH' and Direction[rule_dir] != event.direction:
                return False
        
        # Check protocol
        if 'protocol' in rule and rule['protocol'].lower() != 'any':
            if Protocol[rule['protocol'].upper()] != event.protocol:
                return False
        
        # Check source IP
        if 'src_ips' in rule and not self._ip_in_list(event.src_ip, rule['src_ips']):
            return False
        
        # Check destination IP
        if 'dst_ips' in rule and not self._ip_in_list(event.dst_ip, rule['dst_ips']):
            return False
        
        # Check source port
        if 'src_ports' in rule and event.src_port and event.src_port not in rule['src_ports']:
            return False
        
        # Check destination port
        if 'dst_ports' in rule and event.dst_port and event.dst_port not in rule['dst_ports']:
            return False
        
        # All checks passed
        return True
    
    def _ip_in_list(self, ip: str, ip_list) -> bool:
        """Check if an IP is in a list of IPs or CIDR ranges."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for item in ip_list:
                try:
                    if '/' in item:
                        # Handle CIDR notation
                        network = ipaddress.ip_network(item, strict=False)
                        if ip_obj in network:
                            return True
                    else:
                        # Handle single IP
                        if ip == item:
                            return True
                except ValueError:
                    continue
        except ValueError:
            pass
            
        return False
    
    def _handle_network_event(self, event: NetworkEvent):
        """Handle a network event (log, alert, etc.)."""
        # Log the event
        if event.action != Action.ALLOW:
            logger.warning(f"Network event: {event.action.name} {event.direction.name} "
                         f"{event.protocol.name} {event.src_ip}:{event.src_port} -> "
                         f"{event.dst_ip}:{event.dst_port} - {event.reason}")
        
        # Call alert handlers for non-allowed events
        if event.action != Action.ALLOW:
            for handler in self._alert_handlers:
                try:
                    handler(event)
                except Exception as e:
                    logger.error(f"Error in alert handler: {e}", exc_info=True)
    
    def _get_network_interfaces(self) -> Dict[str, Dict]:
        """Get information about network interfaces."""
        interfaces = {}
        
        if SCAPY_AVAILABLE:
            for iface, addrs in psutil.net_if_addrs().items():
                interfaces[iface] = {
                    'name': iface,
                    'addrs': []
                }
                
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        interfaces[iface]['addrs'].append(addr.address)
        
        return interfaces
    
    def get_connections(self) -> List[Dict]:
        """Get current network connections."""
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    continue
                    
                conn_info = {
                    'pid': conn.pid,
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'type': 'tcp' if conn.type == socket.SOCK_STREAM else 'udp'
                }
                
                # Get process info if available
                if conn.pid:
                    try:
                        p = psutil.Process(conn.pid)
                        conn_info['process'] = p.name()
                        conn_info['cmdline'] = ' '.join(p.cmdline())
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass
                
                connections.append(conn_info)
        except Exception as e:
            logger.error(f"Error getting connections: {e}")
        
        return connections

# Example usage
if __name__ == "__main__":
    import sys
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Create and start the firewall
    firewall = NetworkFirewall()
    
    # Add a simple alert handler
    def alert_handler(event):
        if event.action != Action.ALLOW:
            print(f"\n[!] NETWORK ALERT: {event.action.name} {event.protocol.name} "
                  f"{event.src_ip}:{event.src_port or ''} -> {event.dst_ip}:{event.dst_port or ''}")
            print(f"    Reason: {event.reason}")
    
    firewall.add_alert_handler(alert_handler)
    
    # Add some example rules
    firewall.add_rule({
        'name': 'Block SSH',
        'dst_ports': [22],
        'action': 'block',
        'reason': 'SSH access blocked',
        'priority': 100
    })
    
    firewall.add_rule({
        'name': 'Block RDP',
        'dst_ports': [3389],
        'action': 'block',
        'reason': 'RDP access blocked',
        'priority': 100
    })
    
    # Start the firewall
    firewall.start()
    
    print("Network Firewall started. Press Ctrl+C to stop.")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        firewall.stop()
        print("\nStopping firewall...")
