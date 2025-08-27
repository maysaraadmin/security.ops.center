"""
Network Monitor Module

This module provides network traffic monitoring capabilities for the NDR system.
It captures and processes network traffic in real-time.
"""

import asyncio
import socket
import struct
import logging
from typing import Dict, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
import platform
import ctypes

# Windows-specific imports
if platform.system() == 'Windows':
    import win32file
    import win32event
    import pywintypes
    import win32pipe

logger = logging.getLogger('ndr.network_monitor')

class Protocol(Enum):
    """Network protocol types."""
    TCP = 6
    UDP = 17
    ICMP = 1
    OTHER = 0

@dataclass
class NetworkFlow:
    """Represents a network flow/connection."""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: Protocol
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    flags: int = 0
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

class NetworkMonitor:
    """Monitors network traffic and provides callbacks for detected events."""
    
    def __init__(self, interface: str = None):
        """Initialize the network monitor.
        
        Args:
            interface: Network interface to monitor (e.g., 'eth0', '\\.\NPF_{GUID}')
        """
        self.interface = interface
        self.running = False
        self.callbacks = []
        self.active_flows: Dict[Tuple, NetworkFlow] = {}
        self._loop = asyncio.get_event_loop()
        self._tasks = []
    
    def add_callback(self, callback: Callable[[NetworkFlow], None]) -> None:
        """Add a callback function to be called when network events occur."""
        self.callbacks.append(callback)
    
    def remove_callback(self, callback: Callable[[NetworkFlow], None]) -> bool:
        """Remove a callback function."""
        try:
            self.callbacks.remove(callback)
            return True
        except ValueError:
            return False
    
    async def start(self) -> None:
        """Start the network monitor."""
        if self.running:
            logger.warning("Network monitor is already running")
            return
            
        self.running = True
        logger.info("Starting network monitor")
        
        try:
            # Start the packet capture task
            if platform.system() == 'Windows':
                self._tasks.append(
                    asyncio.create_task(self._capture_windows())
                )
            else:
                self._tasks.append(
                    asyncio.create_task(self._capture_linux())
                )
                
            # Start the flow cleanup task
            self._tasks.append(
                asyncio.create_task(self._cleanup_old_flows())
            )
            
        except Exception as e:
            logger.error(f"Failed to start network monitor: {e}")
            await self.stop()
            raise
    
    async def stop(self) -> None:
        """Stop the network monitor."""
        if not self.running:
            return
            
        logger.info("Stopping network monitor")
        self.running = False
        
        # Cancel all tasks
        for task in self._tasks:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        self._tasks.clear()
        logger.info("Network monitor stopped")
    
    async def _cleanup_old_flows(self) -> None:
        """Periodically clean up old, inactive flows."""
        while self.running:
            try:
                now = datetime.utcnow()
                to_remove = []
                
                for flow_key, flow in list(self.active_flows.items()):
                    # If flow is inactive for more than 5 minutes
                    if flow.end_time and (now - flow.end_time).total_seconds() > 300:
                        to_remove.append(flow_key)
                
                # Remove old flows
                for flow_key in to_remove:
                    self.active_flows.pop(flow_key, None)
                
                if to_remove:
                    logger.debug(f"Cleaned up {len(to_remove)} old flows")
                
            except Exception as e:
                logger.error(f"Error in flow cleanup: {e}")
            
            # Wait before next cleanup
            await asyncio.sleep(60)  # Check every minute
    
    async def _capture_linux(self) -> None:
        """Capture network traffic on Linux using raw sockets."""
        try:
            # Create a raw socket to capture IP packets
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            
            if self.interface:
                sock.bind((self.interface, 0))
            
            logger.info("Starting Linux packet capture")
            
            while self.running:
                try:
                    # Read a packet (non-blocking)
                    ready = await self._loop.sock_recv_into(sock, 65535)
                    if not ready:
                        continue
                        
                    # Process the packet
                    packet = sock.recv(65535)
                    self._process_packet(packet)
                    
                except BlockingIOError:
                    await asyncio.sleep(0.1)
                except Exception as e:
                    logger.error(f"Error processing packet: {e}")
                    
        except Exception as e:
            logger.error(f"Linux packet capture error: {e}")
            raise
        finally:
            sock.close()
    
    async def _capture_windows(self) -> None:
        """Capture network traffic on Windows using WinPcap/Npcap."""
        try:
            # This is a placeholder. In a real implementation, you would use:
            # 1. WinPcap/Npcap with a library like pypcap or scapy
            # 2. Windows Filtering Platform (WFP)
            # 3. Windows Sockets API with raw socket support
            
            logger.info("Windows packet capture not fully implemented. Using dummy capture.")
            
            while self.running:
                try:
                    # Simulate packet capture (replace with actual implementation)
                    await asyncio.sleep(1)
                    
                except Exception as e:
                    logger.error(f"Error in Windows packet capture: {e}")
                    
        except Exception as e:
            logger.error(f"Windows packet capture error: {e}")
            raise
    
    def _process_packet(self, packet: bytes) -> None:
        """Process a captured network packet."""
        try:
            # Parse Ethernet frame
            eth_length = 14
            eth_header = packet[:eth_length]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])
            
            # Parse IP packet (IPv4)
            if eth_protocol == 8:
                ip_header = packet[eth_length:20+eth_length]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                
                version_ihl = iph[0]
                ihl = version_ihl & 0xF
                iph_length = ihl * 4
                
                protocol = iph[6]
                src_ip = socket.inet_ntoa(iph[8])
                dst_ip = socket.inet_ntoa(iph[9])
                
                # TCP protocol
                if protocol == 6:
                    t = iph_length + eth_length
                    tcp_header = packet[t:t+20]
                    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                    
                    src_port = tcph[0]
                    dst_port = tcph[1]
                    flags = tcph[5]
                    
                    flow_key = (src_ip, src_port, dst_ip, dst_port, 6)  # 6 = TCP
                    
                    # Update or create flow
                    if flow_key not in self.active_flows:
                        self.active_flows[flow_key] = NetworkFlow(
                            src_ip=src_ip,
                            src_port=src_port,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            protocol=Protocol.TCP,
                            flags=flags
                        )
                    
                    flow = self.active_flows[flow_key]
                    flow.packets_sent += 1
                    flow.bytes_sent += len(packet)
                    
                    # Check for connection termination
                    if flags & 0x01:  # FIN flag
                        flow.end_time = datetime.utcnow()
                    
                    # Notify callbacks
                    for callback in self.callbacks:
                        try:
                            callback(flow)
                        except Exception as e:
                            logger.error(f"Error in callback: {e}")
                
                # TODO: Add support for UDP, ICMP, and other protocols
                
        except Exception as e:
            logger.error(f"Error processing packet: {e}", exc_info=True)
    
    def get_active_flows(self) -> List[NetworkFlow]:
        """Get a list of all active network flows."""
        return list(self.active_flows.values())
    
    def get_flow_stats(self) -> Dict[str, Any]:
        """Get statistics about the monitored network traffic."""
        total_flows = len(self.active_flows)
        total_bytes = sum(f.bytes_sent + f.bytes_received for f in self.active_flows.values())
        total_packets = sum(f.packets_sent + f.packets_received for f in self.active_flows.values())
        
        return {
            'active_flows': total_flows,
            'total_bytes': total_bytes,
            'total_packets': total_packets,
            'start_time': min((f.start_time for f in self.active_flows.values()), 
                            default=datetime.utcnow()).isoformat(),
            'protocols': {
                'tcp': sum(1 for f in self.active_flows.values() if f.protocol == Protocol.TCP),
                'udp': sum(1 for f in self.active_flows.values() if f.protocol == Protocol.UDP),
                'icmp': sum(1 for f in self.active_flows.values() if f.protocol == Protocol.ICMP),
                'other': sum(1 for f in self.active_flows.values() if f.protocol == Protocol.OTHER),
            }
        }
