"""
Network Detection and Response (NDR) module for monitoring and analyzing network traffic.

This module provides comprehensive visibility into both east-west (internal) and
north-south (external) network traffic using various collection methods.
"""
import asyncio
import logging
import socket
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
import json
import platform
from pathlib import Path

import psutil
from scapy.all import sniff, Packet, IP, TCP, UDP, ICMP, IPv6
from scapy.layers.inet6 import IPv6

logger = logging.getLogger('edr.network.monitor')


@dataclass
class NetworkFlow:
    """Represents a network flow with key attributes."""
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = "tcp"
    bytes_sent: int = 0
    bytes_received: int = 0
    packets: int = 0
    start_time: float = field(default_factory=lambda: datetime.now().timestamp())
    end_time: float = field(default_factory=lambda: datetime.now().timestamp())
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert flow to dictionary for serialization."""
        return {
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'packets': self.packets,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'tags': self.tags,
            'metadata': self.metadata
        }


class NetworkMonitor:
    """
    Network traffic monitoring and analysis.
    
    Collects and analyzes raw network traffic including NetFlow, PCAP, and metadata
    to provide visibility into both internal (east-west) and external (north-south) traffic.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the network monitor with configuration."""
        self.config = config
        self.active = False
        self.flows: Dict[str, NetworkFlow] = {}
        self.callbacks: List[Callable[[NetworkFlow], None]] = []
        self.interface = self.config.get('interface', None)
        self.sniffer = None
        
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
        if not self.interface:
            # Default to first non-loopback interface on Windows
            for iface, addrs in psutil.net_if_addrs().items():
                if not iface.startswith('Loopback'):
                    self.interface = iface
                    break
    
    def _init_linux(self):
        """Linux-specific initialization."""
        if not self.interface:
            # Default to first non-loopback interface on Linux
            for iface, addrs in psutil.net_if_addrs().items():
                if iface != 'lo':
                    self.interface = iface
                    break
    
    def _init_darwin(self):
        """macOS-specific initialization."""
        if not self.interface:
            # Default to first non-loopback interface on macOS
            for iface, addrs in psutil.net_if_addrs().items():
                if not iface.startswith('lo'):
                    self.interface = iface
                    break
    
    def register_callback(self, callback: Callable[[NetworkFlow], None]):
        """Register a callback to be called when a new flow is detected."""
        self.callbacks.append(callback)
    
    async def start(self):
        """Start the network monitoring."""
        if self.active:
            logger.warning("Network monitor is already running")
            return
            
        self.active = True
        logger.info(f"Starting network monitoring on interface {self.interface}")
        
        # Start packet capture in a separate thread
        loop = asyncio.get_event_loop()
        self.sniffer = await loop.run_in_executor(
            None,
            self._start_packet_capture
        )
    
    def _start_packet_capture(self):
        """Start packet capture using Scapy."""
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=0,
                stop_filter=lambda _: not self.active
            )
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
            self.active = False
    
    def _process_packet(self, packet: Packet):
        """Process a captured network packet."""
        try:
            # Extract basic packet information
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
                return
            
            # Handle different protocols
            src_port = None
            dst_port = None
            
            if TCP in packet:
                tcp = packet[TCP]
                src_port = tcp.sport
                dst_port = tcp.dport
                protocol = "tcp"
            elif UDP in packet:
                udp = packet[UDP]
                src_port = udp.sport
                dst_port = udp.dport
                protocol = "udp"
            elif ICMP in packet:
                protocol = "icmp"
            
            # Create a flow key
            flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            
            # Update or create flow
            if flow_key in self.flows:
                flow = self.flows[flow_key]
                flow.packets += 1
                flow.end_time = datetime.now().timestamp()
                
                # Update byte counts based on direction
                if hasattr(packet, 'len'):
                    if src_ip == socket.gethostbyname(socket.gethostname()):
                        flow.bytes_sent += packet.len
                    else:
                        flow.bytes_received += packet.len
            else:
                flow = NetworkFlow(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    packets=1,
                    start_time=datetime.now().timestamp(),
                    end_time=datetime.now().timestamp()
                )
                
                if hasattr(packet, 'len'):
                    if src_ip == socket.gethostbyname(socket.gethostname()):
                        flow.bytes_sent = packet.len
                    else:
                        flow.bytes_received = packet.len
                
                self.flows[flow_key] = flow
                
                # Notify callbacks of new flow
                for callback in self.callbacks:
                    try:
                        callback(flow)
                    except Exception as e:
                        logger.error(f"Error in flow callback: {e}")
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}", exc_info=True)
    
    async def stop(self):
        """Stop the network monitoring."""
        if not self.active:
            return
            
        logger.info("Stopping network monitoring")
        self.active = False
        
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
    
    def get_active_flows(self) -> List[Dict[str, Any]]:
        """Get a list of all active network flows."""
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
    
    def save_pcap(self, filepath: str, count: int = 100):
        """Save the last 'count' packets to a PCAP file."""
        try:
            if not self.sniffer:
                logger.error("No active packet capture to save")
                return False
                
            # Create directory if it doesn't exist
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)
            
            # Save packets to PCAP file
            self.sniffer.dump_packets(filepath, count=count)
            logger.info(f"Saved {count} packets to {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving PCAP file: {e}")
            return False
    
    def export_flows(self, filepath: str):
        """Export flow data to a JSON file."""
        try:
            flow_data = [flow.to_dict() for flow in self.flows.values()]
            
            # Create directory if it doesn't exist
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)
            
            with open(filepath, 'w') as f:
                json.dump(flow_data, f, indent=2)
                
            logger.info(f"Exported {len(flow_data)} flows to {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting flows: {e}")
            return False
