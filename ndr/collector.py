"""
Network Data Collection Module

Collects network traffic data from various sources including:
- Raw packet capture
- NetFlow/sFlow
- Host network statistics
- Network device logs
"""
import asyncio
import logging
import socket
import platform
from typing import Dict, List, Optional, Any, Callable, Set
from dataclasses import dataclass, field
from datetime import datetime
import json
from pathlib import Path

import psutil
import pyshark
from scapy.all import sniff, Packet, IP, TCP, UDP, ICMP, IPv6, ARP, Ether
from scapy.layers.inet6 import IPv6

from .models.flow import NetworkFlow
from .models.alert import NetworkAlert, AlertSeverity
from .protocols.dns import DNSAnalyzer
from .protocols.http import HTTPAnalyzer
from .protocols.tls import TLSAnalyzer

logger = logging.getLogger('edr.network.collector')

@dataclass
class CollectorConfig:
    """Configuration for network data collection."""
    interface: Optional[str] = None
    promiscuous: bool = True
    bpf_filter: Optional[str] = None
    buffer_size: int = 1024 * 1024  # 1MB buffer
    snapshot_length: int = 65535
    timeout: int = 30
    max_packets: int = 0  # 0 for unlimited
    decode_as: Dict[str, str] = field(default_factory=dict)
    protocols: Set[str] = field(default_factory=lambda: {'tcp', 'udp', 'icmp', 'dns', 'http', 'tls'})
    max_flows: int = 10000
    flow_timeout: int = 300  # seconds

class NetworkCollector:
    """
    Collects and processes network traffic data from various sources.
    """
    
    def __init__(self, config: Optional[CollectorConfig] = None):
        """Initialize the network collector."""
        self.config = config or CollectorConfig()
        self.active = False
        self.flows: Dict[str, NetworkFlow] = {}
        self.callbacks: List[Callable[[NetworkFlow], None]] = []
        self.alert_callbacks: List[Callable[[NetworkAlert], None]] = []
        self._packet_queue = asyncio.Queue()
        self._flow_cleanup_task = None
        
        # Protocol analyzers
        self.protocol_analyzers = {
            'dns': DNSAnalyzer(),
            'http': HTTPAnalyzer(),
            'tls': TLSAnalyzer()
        }
        
        # Initialize platform-specific settings
        self._init_platform()
    
    def _init_platform(self):
        """Initialize platform-specific settings."""
        system = platform.system().lower()
        if system == 'windows':
            self._init_windows()
        elif system == 'linux':
            self._init_linux()
        elif system == 'darwin':
            self._init_darwin()
    
    def _init_windows(self):
        """Windows-specific initialization."""
        if not self.config.interface:
            # Default to first non-loopback interface on Windows
            for iface, addrs in psutil.net_if_addrs().items():
                if not iface.startswith('Loopback'):
                    self.config.interface = iface
                    break
    
    def _init_linux(self):
        """Linux-specific initialization."""
        if not self.config.interface:
            # Default to first non-loopback interface on Linux
            for iface, addrs in psutil.net_if_addrs().items():
                if iface != 'lo':
                    self.config.interface = iface
                    break
    
    def _init_darwin(self):
        """macOS-specific initialization."""
        if not self.config.interface:
            # Default to first non-loopback interface on macOS
            for iface, addrs in psutil.net_if_addrs().items():
                if not iface.startswith('lo'):
                    self.config.interface = iface
                    break
    
    def register_flow_callback(self, callback: Callable[[NetworkFlow], None]):
        """Register a callback for new network flows."""
        self.callbacks.append(callback)
    
    def register_alert_callback(self, callback: Callable[[NetworkAlert], None]):
        """Register a callback for security alerts."""
        self.alert_callbacks.append(callback)
    
    async def start(self):
        """Start the network collector."""
        if self.active:
            logger.warning("Network collector is already running")
            return
            
        self.active = True
        logger.info(f"Starting network collector on interface {self.config.interface}")
        
        # Start packet capture in a separate thread
        loop = asyncio.get_event_loop()
        self._capture_task = loop.run_in_executor(
            None,
            self._start_packet_capture
        )
        
        # Start flow processing
        self._processing_task = asyncio.create_task(self._process_packets())
        
        # Start flow cleanup task
        self._flow_cleanup_task = asyncio.create_task(self._cleanup_flows())
    
    def _start_packet_capture(self):
        """Start packet capture using Scapy."""
        try:
            sniff(
                iface=self.config.interface,
                prn=self._packet_handler,
                store=False,
                filter=self.config.bpf_filter,
                promisc=self.config.promiscuous,
                count=self.config.max_packets
            )
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
            self.active = False
    
    def _packet_handler(self, packet: Packet):
        """Handle a captured network packet."""
        try:
            # Put packet in queue for async processing
            self._packet_queue.put_nowait(packet)
        except Exception as e:
            logger.error(f"Error handling packet: {e}")
    
    async def _process_packets(self):
        """Process captured packets asynchronously."""
        while self.active or not self._packet_queue.empty():
            try:
                packet = await self._packet_queue.get()
                if packet is None:
                    break
                    
                # Process packet and update flows
                flow = await self._process_packet(packet)
                if flow:
                    # Notify callbacks
                    for callback in self.callbacks:
                        try:
                            callback(flow)
                        except Exception as e:
                            logger.error(f"Error in flow callback: {e}")
                
                self._packet_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error processing packet: {e}")
    
    async def _process_packet(self, packet: Packet) -> Optional[NetworkFlow]:
        """Process a single network packet and update flows."""
        try:
            # Extract basic packet information
            ip_layer = None
            transport_layer = None
            src_ip = None
            dst_ip = None
            protocol = "unknown"
            
            # Get IP layer (IPv4 or IPv6)
            if IP in packet:
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                protocol = ip_layer.proto
            elif IPv6 in packet:
                ip_layer = packet[IPv6]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                protocol = ip_layer.nh  # Next header field in IPv6
            else:
                # Non-IP traffic (e.g., ARP)
                return None
            
            # Get transport layer
            src_port = None
            dst_port = None
            
            if TCP in packet:
                transport_layer = packet[TCP]
                src_port = transport_layer.sport
                dst_port = transport_layer.dport
                protocol = "tcp"
            elif UDP in packet:
                transport_layer = packet[UDP]
                src_port = transport_layer.sport
                dst_port = transport_layer.dport
                protocol = "udp"
            elif ICMP in packet:
                protocol = "icmp"
            else:
                # Unsupported transport protocol
                return None
            
            # Create flow key
            flow_key = self._get_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
            
            # Get or create flow
            if flow_key in self.flows:
                flow = self.flows[flow_key]
                flow.packets += 1
                flow.last_seen = datetime.utcnow()
                
                # Update byte counts based on direction
                if hasattr(packet, 'len'):
                    if src_ip == socket.gethostbyname(socket.gethostname()):
                        flow.bytes_sent += packet.len
                    else:
                        flow.bytes_received += packet.len
            else:
                # Create new flow
                flow = NetworkFlow(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    start_time=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    packets=1
                )
                
                if hasattr(packet, 'len'):
                    if src_ip == socket.gethostbyname(socket.gethostname()):
                        flow.bytes_sent = packet.len
                    else:
                        flow.bytes_received = packet.len
                
                self.flows[flow_key] = flow
            
            # Analyze protocol-specific data
            await self._analyze_protocols(flow, packet, ip_layer, transport_layer)
            
            return flow
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}", exc_info=True)
            return None
    
    async def _analyze_protocols(self, flow: NetworkFlow, packet: Packet, 
                               ip_layer: Optional[Packet], 
                               transport_layer: Optional[Packet]):
        """Analyze protocol-specific data in the packet."""
        try:
            # DNS analysis
            if 'dns' in self.config.protocols and packet.haslayer('DNS'):
                dns_analysis = await self.protocol_analyzers['dns'].analyze(packet['DNS'])
                if dns_analysis:
                    flow.metadata['dns'] = dns_analysis
                    
                    # Check for DNS tunneling or other anomalies
                    if dns_analysis.get('is_suspicious', False):
                        self._generate_alert(
                            "Suspicious DNS activity detected",
                            f"DNS query for {dns_analysis.get('query', 'unknown')} "
                            f"from {flow.src_ip} to {flow.dst_ip}",
                            severity=AlertSeverity.HIGH,
                            flow=flow,
                            metadata=dns_analysis
                        )
            
            # HTTP analysis
            if 'http' in self.config.protocols and packet.haslayer('HTTP'):
                http_analysis = await self.protocol_analyzers['http'].analyze(packet['HTTP'])
                if http_analysis:
                    flow.metadata['http'] = http_analysis
                    
                    # Check for HTTP anomalies
                    if http_analysis.get('is_malicious', False):
                        self._generate_alert(
                            "Suspicious HTTP activity detected",
                            f"HTTP {http_analysis.get('method', '')} request to "
                            f"{http_analysis.get('host', '')}{http_analysis.get('uri', '')}",
                            severity=AlertSeverity.MEDIUM,
                            flow=flow,
                            metadata=http_analysis
                        )
            
            # TLS/SSL analysis
            if 'tls' in self.config.protocols and packet.haslayer('TLS'):
                tls_analysis = await self.protocol_analyzers['tls'].analyze(packet['TLS'])
                if tls_analysis:
                    flow.metadata['tls'] = tls_analysis
                    
                    # Check for TLS anomalies
                    if tls_analysis.get('is_risky', False):
                        self._generate_alert(
                            "Risky TLS connection detected",
                            f"TLS connection to {tls_analysis.get('server_name', flow.dst_ip)} "
                            f"using {tls_analysis.get('version', 'unknown')} "
                            f"with {tls_analysis.get('cipher_suite', 'unknown cipher')}",
                            severity=AlertSeverity.MEDIUM,
                            flow=flow,
                            metadata=tls_analysis
                        )
                        
        except Exception as e:
            logger.error(f"Error in protocol analysis: {e}", exc_info=True)
    
    def _generate_alert(self, title: str, description: str, severity: 'AlertSeverity',
                       flow: NetworkFlow, metadata: Optional[Dict] = None):
        """Generate a security alert."""
        alert = NetworkAlert(
            title=title,
            description=description,
            severity=severity,
            timestamp=datetime.utcnow(),
            source_ip=flow.src_ip,
            destination_ip=flow.dst_ip,
            source_port=flow.src_port,
            destination_port=flow.dst_port,
            protocol=flow.protocol,
            metadata=metadata or {}
        )
        
        # Notify alert callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")
    
    async def _cleanup_flows(self):
        """Clean up old flows periodically."""
        while self.active:
            try:
                current_time = datetime.utcnow()
                expired_flows = []
                
                # Find expired flows
                for flow_key, flow in list(self.flows.items()):
                    if (current_time - flow.last_seen).total_seconds() > self.config.flow_timeout:
                        expired_flows.append(flow)
                        del self.flows[flow_key]
                
                # Log expired flows
                if expired_flows:
                    logger.debug(f"Cleaned up {len(expired_flows)} expired flows")
                
                # Sleep for a while before next cleanup
                await asyncio.sleep(min(60, self.config.flow_timeout / 2))
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in flow cleanup: {e}")
                await asyncio.sleep(5)  # Prevent tight loop on error
    
    @staticmethod
    def _get_flow_key(src_ip: str, dst_ip: str, src_port: Optional[int], 
                     dst_port: Optional[int], protocol: str) -> str:
        """Generate a unique key for a network flow."""
        # Sort IPs and ports to ensure bidirectional flows have the same key
        if src_ip > dst_ip or (src_ip == dst_ip and (src_port or 0) > (dst_port or 0)):
            src_ip, dst_ip = dst_ip, src_ip
            src_port, dst_port = dst_port, src_port
            
        return f"{src_ip}:{src_port or 0}-{dst_ip}:{dst_port or 0}-{protocol}"
    
    async def stop(self):
        """Stop the network collector."""
        if not self.active:
            return
            
        logger.info("Stopping network collector")
        self.active = False
        
        # Cancel tasks
        if hasattr(self, '_capture_task'):
            self._capture_task.cancel()
            
        if hasattr(self, '_processing_task'):
            self._processing_task.cancel()
            
        if self._flow_cleanup_task:
            self._flow_cleanup_task.cancel()
        
        # Clear packet queue
        while not self._packet_queue.empty():
            try:
                self._packet_queue.get_nowait()
                self._packet_queue.task_done()
            except asyncio.QueueEmpty:
                break
    
    def get_active_flows(self) -> List[Dict[str, Any]]:
        """Get a list of active network flows."""
        return [flow.to_dict() for flow in self.flows.values()]
    
    def get_flow_statistics(self) -> Dict[str, Any]:
        """Get statistics about the captured flows."""
        total_bytes = sum(f.bytes_sent + f.bytes_received for f in self.flows.values())
        total_packets = sum(f.packets for f in self.flows.values())
        
        return {
            'total_flows': len(self.flows),
            'total_bytes': total_bytes,
            'total_packets': total_packets,
            'protocols': self._get_protocol_stats(),
            'top_talkers': self._get_top_talkers()
        }
    
    def _get_protocol_stats(self) -> Dict[str, int]:
        """Get statistics by protocol."""
        stats = {}
        for flow in self.flows.values():
            if flow.protocol not in stats:
                stats[flow.protocol] = 0
            stats[flow.protocol] += flow.packets
        return stats
    
    def _get_top_talkers(self, count: int = 10) -> List[Dict[str, Any]]:
        """Get the top talkers by traffic volume."""
        sorted_flows = sorted(
            self.flows.values(),
            key=lambda f: f.bytes_sent + f.bytes_received,
            reverse=True
        )
        
        return [
            {
                'src_ip': flow.src_ip,
                'dst_ip': flow.dst_ip,
                'protocol': flow.protocol,
                'bytes': flow.bytes_sent + flow.bytes_received,
                'packets': flow.packets
            }
            for flow in sorted_flows[:count]
        ]
