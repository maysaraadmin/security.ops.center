"""
Packet Inspector for NIPS - Analyzes individual network packets.
"""
import logging
import socket
import struct
from typing import Dict, Any, List, Callable, Optional, Tuple
from scapy.all import IP, TCP, UDP, ICMP, DNS, Raw, Packet
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP

class PacketInspector:
    """
    Analyzes individual network packets and extracts relevant information.
    """
    
    def __init__(self):
        """Initialize the packet inspector."""
        self.logger = logging.getLogger(__name__)
        self.callbacks = []
        
        # Protocol handlers for different packet types
        self.protocol_handlers = {
            'tcp': self._inspect_tcp,
            'udp': self._inspect_udp,
            'icmp': self._inspect_icmp,
            'dns': self._inspect_dns,
            'http': self._inspect_http,
            'https': self._inspect_https,
            'arp': self._inspect_arp,
        }
        
        # Known ports for common protocols
        self.known_ports = {
            80: 'http',
            443: 'https',
            53: 'dns',
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            110: 'pop3',
            143: 'imap',
            3306: 'mysql',
            3389: 'rdp',
            8080: 'http-proxy',
            8443: 'https-alt',
        }
    
    def add_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """
        Add a callback function to be called when a packet is inspected.
        
        Args:
            callback: Function that takes a dictionary of packet information
        """
        if callback not in self.callbacks:
            self.callbacks.append(callback)
    
    def inspect_packet(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Inspect a network packet and extract relevant information.
        
        Args:
            packet: The packet to inspect
            
        Returns:
            Dictionary containing extracted packet information, or None if the packet is invalid
        """
        if not packet:
            return None
            
        try:
            # Initialize packet info dictionary
            packet_info = {
                'timestamp': packet.time if hasattr(packet, 'time') else None,
                'length': len(packet),
                'summary': packet.summary(),
                'layers': []
            }
            
            # Extract layer information
            current = packet
            while current:
                layer_name = current.name
                layer_info = {
                    'name': layer_name,
                    'fields': {}
                }
                
                # Get field values for this layer
                for field in current.fields_desc:
                    if hasattr(current, field.name):
                        value = getattr(current, field.name)
                        layer_info['fields'][field.name] = value
                
                packet_info['layers'].append(layer_info)
                
                # Move to the next layer
                if hasattr(current, 'payload'):
                    current = current.payload
                    if current == current.original:
                        break  # Prevent infinite loop
                else:
                    break
            
            # Extract basic network information
            if IP in packet:
                packet_info['src_ip'] = packet[IP].src
                packet_info['dst_ip'] = packet[IP].dst
                packet_info['protocol'] = packet[IP].proto
                
                # Handle transport layer protocols
                if TCP in packet:
                    packet_info.update(self._inspect_tcp(packet[TCP]))
                elif UDP in packet:
                    packet_info.update(self._inspect_udp(packet[UDP]))
                elif ICMP in packet:
                    packet_info.update(self._inspect_icmp(packet[ICMP]))
                
                # Handle application layer protocols
                if Raw in packet:
                    payload = str(packet[Raw].load) if hasattr(packet[Raw], 'load') else ''
                    packet_info['payload'] = payload
                    
                    # Check for HTTP
                    if 'http' in payload.lower():
                        packet_info.update(self._inspect_http(payload))
                    
                    # Check for DNS
                    if DNS in packet:
                        packet_info.update(self._inspect_dns(packet[DNS]))
            
            # Handle ARP packets
            elif ARP in packet:
                packet_info.update(self._inspect_arp(packet[ARP]))
            
            # Call all registered callbacks
            for callback in self.callbacks:
                try:
                    callback(packet_info)
                except Exception as e:
                    self.logger.error(f"Error in packet callback: {e}")
            
            return packet_info
            
        except Exception as e:
            self.logger.error(f"Error inspecting packet: {e}")
            return None
    
    def _inspect_tcp(self, tcp_packet) -> Dict[str, Any]:
        """Inspect TCP packet."""
        info = {
            'transport_protocol': 'tcp',
            'src_port': tcp_packet.sport,
            'dst_port': tcp_packet.dport,
            'flags': {
                'syn': bool(tcp_packet.flags & 0x02),
                'ack': bool(tcp_packet.flags & 0x10),
                'fin': bool(tcp_packet.flags & 0x01),
                'rst': bool(tcp_packet.flags & 0x04),
                'psh': bool(tcp_packet.flags & 0x08),
                'urg': bool(tcp_packet.flags & 0x20),
            },
            'seq': tcp_packet.seq,
            'ack': tcp_packet.ack,
            'window': tcp_packet.window,
        }
        
        # Add application protocol if known
        if tcp_packet.dport in self.known_ports:
            info['application_protocol'] = self.known_ports[tcp_packet.dport]
        elif tcp_packet.sport in self.known_ports:
            info['application_protocol'] = self.known_ports[tcp_packet.sport]
        
        return info
    
    def _inspect_udp(self, udp_packet) -> Dict[str, Any]:
        """Inspect UDP packet."""
        info = {
            'transport_protocol': 'udp',
            'src_port': udp_packet.sport,
            'dst_port': udp_packet.dport,
            'length': udp_packet.len,
        }
        
        # Add application protocol if known
        if udp_packet.dport in self.known_ports:
            info['application_protocol'] = self.known_ports[udp_packet.dport]
        elif udp_packet.sport in self.known_ports:
            info['application_protocol'] = self.known_ports[udp_packet.sport]
        
        return info
    
    def _inspect_icmp(self, icmp_packet) -> Dict[str, Any]:
        """Inspect ICMP packet."""
        return {
            'transport_protocol': 'icmp',
            'type': icmp_packet.type,
            'code': icmp_packet.code,
            'id': icmp_packet.id if hasattr(icmp_packet, 'id') else None,
            'seq': icmp_packet.seq if hasattr(icmp_packet, 'seq') else None,
        }
    
    def _inspect_dns(self, dns_packet) -> Dict[str, Any]:
        """Inspect DNS packet."""
        info = {
            'application_protocol': 'dns',
            'qr': 'response' if dns_packet.qr else 'query',
            'opcode': dns_packet.opcode,
            'rcode': dns_packet.rcode,
        }
        
        # Extract DNS query information
        if hasattr(dns_packet, 'qd') and dns_packet.qd:
            info['query'] = {
                'name': str(dns_packet.qd.qname, 'utf-8', 'ignore') if hasattr(dns_packet.qd, 'qname') else None,
                'type': dns_packet.qd.qtype if hasattr(dns_packet.qd, 'qtype') else None,
                'class': dns_packet.qd.qclass if hasattr(dns_packet.qd, 'qclass') else None,
            }
        
        # Extract DNS answer information
        if hasattr(dns_packet, 'an') and dns_packet.an:
            answers = []
            for i in range(dns_packet.ancount):
                if i < len(dns_packet.an):
                    answer = dns_packet.an[i]
                    answer_info = {
                        'name': str(answer.rrname, 'utf-8', 'ignore') if hasattr(answer, 'rrname') else None,
                        'type': answer.type if hasattr(answer, 'type') else None,
                        'rclass': answer.rclass if hasattr(answer, 'rclass') else None,
                        'ttl': answer.ttl if hasattr(answer, 'ttl') else None,
                    }
                    
                    # Add type-specific fields
                    if hasattr(answer, 'rdata'):
                        if hasattr(answer.rdata, '__str__'):
                            answer_info['data'] = str(answer.rdata)
                        else:
                            answer_info['data'] = answer.rdata
                    
                    answers.append(answer_info)
            
            if answers:
                info['answers'] = answers
        
        return info
    
    def _inspect_http(self, payload: str) -> Dict[str, Any]:
        """Inspect HTTP packet."""
        info = {
            'application_protocol': 'http',
        }
        
        try:
            # Parse HTTP headers
            lines = payload.split('\r\n')
            if lines:
                # Parse request/response line
                first_line = lines[0].strip()
                if first_line.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH')):
                    # HTTP Request
                    parts = first_line.split(' ', 2)
                    if len(parts) >= 2:
                        info['http_method'] = parts[0]
                        info['http_uri'] = parts[1]
                        if len(parts) > 2:
                            info['http_version'] = parts[2]
                elif first_line.startswith('HTTP/'):
                    # HTTP Response
                    parts = first_line.split(' ', 2)
                    if len(parts) >= 2:
                        info['http_version'] = parts[0]
                        info['http_status_code'] = int(parts[1])
                        if len(parts) > 2:
                            info['http_status_message'] = parts[2]
                
                # Parse headers
                headers = {}
                for line in lines[1:]:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip().lower()] = value.strip()
                
                if headers:
                    info['http_headers'] = headers
                    
                    # Extract useful headers
                    for header in ['host', 'user-agent', 'content-type', 'content-length']:
                        if header in headers:
                            info[f'http_{header.replace("-", "_")}'] = headers[header]
        
        except Exception as e:
            self.logger.debug(f"Error parsing HTTP: {e}")
        
        return info
    
    def _inspect_https(self, payload: str) -> Dict[str, Any]:
        """Inspect HTTPS packet (limited due to encryption)."""
        return {
            'application_protocol': 'https',
            'encrypted': True,
        }
    
    def _inspect_arp(self, arp_packet) -> Dict[str, Any]:
        """Inspect ARP packet."""
        return {
            'protocol': 'arp',
            'operation': 'reply' if arp_packet.op == 2 else 'request',
            'sender_mac': arp_packet.hwsrc,
            'sender_ip': arp_packet.psrc,
            'target_mac': arp_packet.hwdst,
            'target_ip': arp_packet.pdst,
        }
