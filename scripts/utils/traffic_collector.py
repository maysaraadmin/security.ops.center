"""
Network Traffic Collector for NDR.
Captures and processes network traffic for analysis.
"""
import socket
import struct
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import threading
import logging
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw
from scapy.packet import Packet

class TrafficCollector:
    """Collects and processes network traffic."""
    
    def __init__(self, interface: str = None, filter_exp: str = "ip"):
        """
        Initialize the traffic collector.
        
        Args:
            interface: Network interface to listen on (None for default)
            filter_exp: BPF filter expression for traffic filtering
        """
        self.interface = interface
        self.filter_exp = filter_exp
        self.running = False
        self.thread = None
        self.callbacks = []
        self.logger = logging.getLogger(__name__)
        
    def add_callback(self, callback):
        """Add a callback function to be called when traffic is captured."""
        self.callbacks.append(callback)
    
    def _packet_handler(self, packet: Packet):
        """Process each captured packet."""
        try:
            # Extract basic packet information
            packet_info = {
                'timestamp': datetime.utcnow().isoformat(),
                'src_ip': None,
                'dst_ip': None,
                'protocol': None,
                'src_port': None,
                'dst_port': None,
                'length': len(packet),
                'payload': None
            }
            
            # IP layer
            if IP in packet:
                packet_info['src_ip'] = packet[IP].src
                packet_info['dst_ip'] = packet[IP].dst
                
                # TCP
                if TCP in packet:
                    packet_info['protocol'] = 'tcp'
                    packet_info['src_port'] = packet[TCP].sport
                    packet_info['dst_port'] = packet[TCP].dport
                    if Raw in packet:
                        packet_info['payload'] = str(packet[Raw].load)
                        
                # UDP
                elif UDP in packet:
                    packet_info['protocol'] = 'udp'
                    packet_info['src_port'] = packet[UDP].sport
                    packet_info['dst_port'] = packet[UDP].dport
                    if Raw in packet:
                        packet_info['payload'] = str(packet[Raw].load)
                        
                # ICMP
                elif ICMP in packet:
                    packet_info['protocol'] = 'icmp'
                    
            # ARP
            elif ARP in packet:
                packet_info['protocol'] = 'arp'
                packet_info['src_ip'] = packet[ARP].psrc
                packet_info['dst_ip'] = packet[ARP].pdst
            
            # Notify all callbacks
            for callback in self.callbacks:
                try:
                    callback(packet_info)
                except Exception as e:
                    self.logger.error(f"Error in packet handler callback: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def start(self):
        """Start the traffic collection in a separate thread."""
        if self.running:
            self.logger.warning("Traffic collection already running")
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        self.logger.info("Started network traffic collection")
    
    def _run(self):
        """Main loop for packet capture."""
        try:
            sniff(iface=self.interface, 
                 filter=self.filter_exp, 
                 prn=self._packet_handler,
                 store=0)
        except Exception as e:
            self.logger.error(f"Error in packet capture: {e}")
            self.running = False
    
    def stop(self):
        """Stop the traffic collection."""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
        self.logger.info("Stopped network traffic collection")
