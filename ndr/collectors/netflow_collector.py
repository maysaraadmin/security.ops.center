"""
NetFlow Collector Module

Collects and processes NetFlow/sFlow data from network devices.
Supports multiple NetFlow versions and provides flow aggregation.
"""
import asyncio
import logging
import ipaddress
import socket
import struct
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any, Callable, Deque
import json
from pathlib import Path

# Update imports to use absolute paths
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from ndr.models.flow import NetworkFlow, FlowDirection
from ndr.models.alert import NetworkAlert, AlertSeverity
from ndr.utils.net_utils import is_private_ip, get_service_name

logger = logging.getLogger('ndr.collector.netflow')

class NetFlowVersion(Enum):
    """Supported NetFlow versions."""
    NETFLOW_V5 = 5
    NETFLOW_V9 = 9
    IPFIX = 10
    SFLOW_V5 = 1005  # Custom ID for sFlow v5

@dataclass
class NetFlowConfig:
    """Configuration for NetFlow collector."""
    # Network interface and port to listen on
    listen_address: str = '0.0.0.0'
    listen_port: int = 2055  # Default NetFlow port
    
    # NetFlow version (5, 9, or 10 for IPFIX)
    version: NetFlowVersion = NetFlowVersion.NETFLOW_V5
    
    # Export settings
    active_timeout: int = 300  # seconds
    inactive_timeout: int = 15  # seconds
    
    # Buffer settings
    max_buffer_size: int = 10000  # Max flows in buffer
    
    # Internal networks (for flow direction detection)
    internal_networks: List[str] = field(default_factory=lambda: [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        'fc00::/7'  # ULA (RFC 4193)
    ])
    
    # Sampling rate (1 in N packets)
    sampling_rate: int = 1
    
    # Enable/disable features
    enable_flow_export: bool = True
    enable_anomaly_detection: bool = True
    
    # Path to save flow data
    data_dir: str = "data/ndr/netflow"

class NetFlowCollector:
    """
    Collects and processes NetFlow/sFlow data from network devices.
    """
    
    def __init__(self, config: Optional[NetFlowConfig] = None):
        """Initialize the NetFlow collector."""
        self.config = config or NetFlowConfig()
        self.active = False
        self._transport = None
        self._flow_buffer: List[NetworkFlow] = []
        self._flow_cache: Dict[Tuple, NetworkFlow] = {}
        self._last_export = datetime.utcnow()
        
        # Statistics
        self.stats = {
            'total_flows': 0,
            'total_bytes': 0,
            'total_packets': 0,
            'flows_by_protocol': defaultdict(int),
            'bytes_by_protocol': defaultdict(int),
            'packets_by_protocol': defaultdict(int),
            'start_time': datetime.utcnow(),
            'last_update': datetime.utcnow()
        }
        
        # Callbacks
        self.flow_callbacks: List[Callable[[NetworkFlow], None]] = []
        self.alert_callbacks: List[Callable[[NetworkAlert], None]] = []
        
        # Initialize data directory
        self.data_dir = Path(self.config.data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize protocol handlers
        self._init_protocol_handlers()
    
    def _init_protocol_handlers(self):
        """Initialize protocol handlers for different NetFlow versions."""
        self._handlers = {
            NetFlowVersion.NETFLOW_V5: self._handle_netflow_v5,
            NetFlowVersion.NETFLOW_V9: self._handle_netflow_v9,
            NetFlowVersion.IPFIX: self._handle_ipfix,
            NetFlowVersion.SFLOW_V5: self._handle_sflow_v5
        }
    
    async def start(self):
        """Start the NetFlow collector."""
        if self.active:
            return
            
        self.active = True
        
        # Create UDP server
        loop = asyncio.get_running_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: NetFlowProtocol(self),
            local_addr=(self.config.listen_address, self.config.listen_port)
        )
        
        logger.info(f"NetFlow collector started on {self.config.listen_address}:{self.config.listen_port}")
        
        # Start background tasks
        asyncio.create_task(self._export_flows())
        asyncio.create_task(self._cleanup_old_flows())
    
    async def stop(self):
        """Stop the NetFlow collector."""
        if not self.active:
            return
            
        self.active = False
        
        if self._transport:
            self._transport.close()
            self._transport = None
        
        # Export any remaining flows
        await self._export_flows(force=True)
        
        logger.info("NetFlow collector stopped")
    
    def register_flow_callback(self, callback: Callable[[NetworkFlow], None]):
        """Register a callback for processed flows."""
        self.flow_callbacks.append(callback)
    
    def register_alert_callback(self, callback: Callable[[NetworkAlert], None]):
        """Register a callback for alerts."""
        self.alert_callbacks.append(callback)
    
    async def _export_flows(self, force: bool = False):
        """Export flows to callbacks and storage."""
        while self.active or force:
            try:
                # Check if we have flows to export
                if not self._flow_buffer and not force:
                    await asyncio.sleep(1)
                    continue
                
                # Process flows in batches
                batch_size = min(1000, len(self._flow_buffer))
                batch = self._flow_buffer[:batch_size]
                self._flow_buffer = self._flow_buffer[batch_size:]
                
                # Update statistics
                self._update_stats(batch)
                
                # Notify callbacks
                for flow in batch:
                    for callback in self.flow_callbacks:
                        try:
                            callback(flow)
                        except Exception as e:
                            logger.error(f"Error in flow callback: {e}")
                
                # Save to disk if enabled
                if self.config.enable_flow_export:
                    self._save_flows(batch)
                
                # Reset force flag after first iteration if needed
                if force and not self._flow_buffer:
                    break
                
            except Exception as e:
                logger.error(f"Error exporting flows: {e}")
                await asyncio.sleep(1)
    
    async def _cleanup_old_flows(self):
        """Clean up old flows from the cache."""
        while self.active:
            try:
                now = datetime.utcnow()
                expired_flows = []
                
                # Find expired flows
                for key, flow in list(self._flow_cache.items()):
                    if (now - flow.end_time).total_seconds() > self.config.inactive_timeout:
                        expired_flows.append(flow)
                        del self._flow_cache[key]
                
                # Process expired flows
                if expired_flows:
                    self._flow_buffer.extend(expired_flows)
                
                # Check less frequently when not under load
                await asyncio.sleep(5)
                
            except Exception as e:
                logger.error(f"Error cleaning up old flows: {e}")
                await asyncio.sleep(1)
    
    def _update_stats(self, flows: List[NetworkFlow]):
        """Update statistics with new flows."""
        for flow in flows:
            self.stats['total_flows'] += 1
            self.stats['total_bytes'] += flow.bytes_sent + flow.bytes_received
            self.stats['total_packets'] += flow.packets_sent + flow.packets_received
            
            protocol = flow.protocol or 'unknown'
            self.stats['flows_by_protocol'][protocol] += 1
            self.stats['bytes_by_protocol'][protocol] += flow.bytes_sent + flow.bytes_received
            self.stats['packets_by_protocol'][protocol] += flow.packets_sent + flow.packets_received
        
        self.stats['last_update'] = datetime.utcnow()
    
    def _save_flows(self, flows: List[NetworkFlow]):
        """Save flows to disk."""
        if not flows:
            return
            
        try:
            # Create daily directory
            date_str = datetime.utcnow().strftime("%Y-%m-%d")
            daily_dir = self.data_dir / date_str
            daily_dir.mkdir(exist_ok=True)
            
            # Save to hourly file
            hour_str = datetime.utcnow().strftime("%H")
            flow_file = daily_dir / f"flows_{hour_str}.jsonl"
            
            with open(flow_file, 'a') as f:
                for flow in flows:
                    f.write(flow.to_json() + "\n")
                    
        except Exception as e:
            logger.error(f"Error saving flows: {e}")
    
    def _get_flow_direction(self, src_ip: str, dst_ip: str) -> FlowDirection:
        """Determine the direction of a flow."""
        try:
            src_private = any(
                ipaddress.ip_address(src_ip) in ipaddress.ip_network(net, strict=False)
                for net in self.config.internal_networks
            )
            
            dst_private = any(
                ipaddress.ip_address(dst_ip) in ipaddress.ip_network(net, strict=False)
                for net in self.config.internal_networks
            )
            
            if src_private and dst_private:
                return FlowDirection.INTERNAL
            elif src_private and not dst_private:
                return FlowDirection.OUTBOUND
            elif not src_private and dst_private:
                return FlowDirection.INBOUND
            else:
                return FlowDirection.EXTERNAL
                
        except (ValueError, ipaddress.AddressValueError):
            return FlowDirection.UNKNOWN
    
    def _create_flow_key(self, flow: NetworkFlow) -> Tuple:
        """Create a cache key for a flow."""
        return (
            flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port,
            flow.protocol, int(flow.direction)
        )
    
    def _handle_netflow_v5(self, data: bytes, addr: Tuple[str, int]):
        """Handle NetFlow v5 packet."""
        try:
            # Parse NetFlow v5 header
            (version, count, sys_uptime, unix_secs, unix_nsecs, flow_sequence,
             engine_type, engine_id, sampling_interval) = struct.unpack('!HHIIIIBBH', data[:24])
            
            # Parse flows
            flow_data = data[24:]
            flow_size = 48  # NetFlow v5 flow size
            
            for i in range(0, len(flow_data), flow_size):
                if i + flow_size > len(flow_data):
                    break
                    
                flow = self._parse_netflow_v5_flow(flow_data[i:i+flow_size], unix_secs, unix_nsecs)
                if flow:
                    self._process_flow(flow)
            
        except Exception as e:
            logger.error(f"Error processing NetFlow v5 packet: {e}")
    
    def _parse_netflow_v5_flow(self, data: bytes, unix_secs: int, unix_nsecs: int) -> Optional[NetworkFlow]:
        """Parse a single NetFlow v5 flow record."""
        try:
            # Unpack flow record
            (src_addr, dst_addr, nexthop, input_int, output_int, packet_count,
             byte_count, start_time, end_time, src_port, dst_port, _,
             tcp_flags, protocol, tos, src_as, dst_as, src_mask, dst_mask) = struct.unpack('!4s4s4sIIIIIIIIHHBBBBBB', data[:48])
            
            # Convert IP addresses to strings
            src_ip = socket.inet_ntoa(src_addr)
            dst_ip = socket.inet_ntoa(dst_addr)
            
            # Skip invalid flows
            if not src_ip or not dst_ip or not protocol:
                return None
            
            # Create flow
            flow = NetworkFlow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=self._get_protocol_name(protocol),
                packets_sent=packet_count,
                bytes_sent=byte_count,
                start_time=datetime.utcfromtimestamp(unix_secs - (unix_secs - start_time // 1000)),
                end_time=datetime.utcfromtimestamp(unix_secs - (unix_secs - end_time // 1000)),
                direction=self._get_flow_direction(src_ip, dst_ip),
                metadata={
                    'netflow': {
                        'version': 5,
                        'input_interface': input_int,
                        'output_interface': output_int,
                        'tcp_flags': tcp_flags,
                        'tos': tos,
                        'src_as': src_as,
                        'dst_as': dst_as,
                        'src_mask': src_mask,
                        'dst_mask': dst_mask
                    }
                }
            )
            
            return flow
            
        except Exception as e:
            logger.error(f"Error parsing NetFlow v5 flow: {e}")
            return None
    
    def _handle_netflow_v9(self, data: bytes, addr: Tuple[str, int]):
        """Handle NetFlow v9 packet (stub)."""
        # NetFlow v9 is template-based and more complex
        # This is a simplified implementation
        logger.debug(f"Received NetFlow v9 packet from {addr}")
    
    def _handle_ipfix(self, data: bytes, addr: Tuple[str, int]):
        """Handle IPFIX packet (stub)."""
        # IPFIX is similar to NetFlow v9 but with some differences
        logger.debug(f"Received IPFIX packet from {addr}")
    
    def _handle_sflow_v5(self, data: bytes, addr: Tuple[str, int]):
        """Handle sFlow v5 packet (stub)."""
        # sFlow is a different protocol but provides similar data
        logger.debug(f"Received sFlow v5 packet from {addr}")
    
    def _get_protocol_name(self, protocol_num: int) -> str:
        """Convert protocol number to name."""
        protocol_map = {
            1: 'icmp',
            6: 'tcp',
            17: 'udp',
            58: 'icmpv6'
        }
        return protocol_map.get(protocol_num, f"ip-{protocol_num}")
    
    def _process_flow(self, flow: NetworkFlow):
        """Process a single flow."""
        if not flow:
            return
        
        # Update flow cache or add to buffer
        flow_key = self._create_flow_key(flow)
        
        if flow_key in self._flow_cache:
            # Update existing flow
            cached_flow = self._flow_cache[flow_key]
            cached_flow.bytes_sent += flow.bytes_sent
            cached_flow.bytes_received += flow.bytes_received
            cached_flow.packets_sent += flow.packets_sent
            cached_flow.packets_received += flow.packets_received
            cached_flow.end_time = flow.end_time
        else:
            # Add new flow to cache
            self._flow_cache[flow_key] = flow
        
        # Check if we should export the flow
        if len(self._flow_buffer) >= self.config.max_buffer_size:
            self._flow_buffer.pop(0)  # Remove oldest flow if buffer is full
        
        self._flow_buffer.append(flow)
        
        # Check for anomalies
        if self.config.enable_anomaly_detection:
            self._check_for_anomalies(flow)
    
    def _check_for_anomalies(self, flow: NetworkFlow):
        """Check for anomalies in the flow."""
        # Example: Detect large data transfers
        if flow.bytes_sent > 10 * 1024 * 1024:  # 10 MB
            self._generate_alert(
                title="Large Data Transfer Detected",
                description=f"Large outbound data transfer detected: {flow.bytes_sent / (1024*1024):.2f} MB from {flow.src_ip}:{flow.src_port} to {flow.dst_ip}:{flow.dst_port}",
                severity=AlertSeverity.MEDIUM,
                source_ip=flow.src_ip,
                destination_ip=flow.dst_ip,
                source_port=flow.src_port,
                destination_port=flow.dst_port,
                protocol=flow.protocol,
                metadata={
                    'bytes_sent': flow.bytes_sent,
                    'threat_type': 'large_data_transfer',
                    'direction': flow.direction.name.lower()
                }
            )
    
    def _generate_alert(self, **kwargs):
        """Generate an alert."""
        alert = NetworkAlert(**kwargs)
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")

class NetFlowProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for NetFlow packets."""
    
    def __init__(self, collector: 'NetFlowCollector'):
        self.collector = collector
        super().__init__()
    
    def connection_made(self, transport):
        self.transport = transport
    
    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """Handle incoming NetFlow packets."""
        if not data:
            return
            
        try:
            # Get NetFlow version from the first 2 bytes
            if len(data) >= 2:
                version = int.from_bytes(data[:2], byteorder='big')
                
                # Route to appropriate handler
                if version == 5:
                    self.collector._handle_netflow_v5(data, addr)
                elif version == 9:
                    self.collector._handle_netflow_v9(data, addr)
                elif version == 10:
                    self.collector._handle_ipfix(data, addr)
                else:
                    logger.warning(f"Unsupported NetFlow version: {version}")
            
        except Exception as e:
            logger.error(f"Error processing NetFlow packet from {addr}: {e}")
    
    def error_received(self, exc):
        logger.error(f"NetFlow protocol error: {exc}")
    
    def connection_lost(self, exc):
        if exc:
            logger.error(f"NetFlow connection lost: {exc}")
        else:
            logger.info("NetFlow connection closed")
