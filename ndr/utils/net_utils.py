"""
Network Utility Functions

Provides helper functions for network analysis and processing.
"""
import ipaddress
import socket
import re
from typing import Optional, List, Set, Dict, Any, Union, Tuple
from dataclasses import dataclass, field
import logging

logger = logging.getLogger('edr.network.utils')

def is_private_ip(ip: str, networks: Optional[List[str]] = None) -> bool:
    """
    Check if an IP address is in a private network range.
    
    Args:
        ip: IP address to check
        networks: Optional list of network CIDRs to check against
        
    Returns:
        bool: True if the IP is in a private network range
    """
    if not ip:
        return False
        
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        # Check against provided networks if any
        if networks:
            for net in networks:
                if ip_obj in ipaddress.ip_network(net, strict=False):
                    return True
        
        # Check standard private ranges
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        
    except ValueError as e:
        logger.warning(f"Invalid IP address {ip}: {e}")
        return False

def is_rfc1918(ip: str) -> bool:
    """
    Check if an IP address is in RFC1918 private address space.
    
    Args:
        ip: IP address to check
        
    Returns:
        bool: True if the IP is in RFC1918 private address space
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        if not ip_obj.is_private:
            return False
            
        # RFC1918 ranges:
        # 10.0.0.0/8
        # 172.16.0.0/12
        # 192.168.0.0/16
        if ip_obj.version == 4:
            octets = list(map(int, ip.split('.')))
            return (octets[0] == 10 or
                   (octets[0] == 172 and 16 <= octets[1] <= 31) or
                   (octets[0] == 192 and octets[1] == 168))
        return False
    except (ValueError, AttributeError):
        return False

def get_ip_version(ip: str) -> Optional[int]:
    """
    Get the IP version (4 or 6) of an IP address.
    
    Args:
        ip: IP address to check
        
    Returns:
        int: 4 for IPv4, 6 for IPv6, or None if invalid
    """
    try:
        return ipaddress.ip_address(ip).version
    except ValueError:
        return None

def is_valid_ip(ip: str) -> bool:
    """
    Check if a string is a valid IP address.
    
    Args:
        ip: String to check
        
    Returns:
        bool: True if the string is a valid IP address
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_port(port: int) -> bool:
    """
    Check if a port number is valid.
    
    Args:
        port: Port number to check
        
    Returns:
        bool: True if the port is valid (0-65535)
    """
    return 0 <= port <= 65535

def is_privileged_port(port: int) -> bool:
    """
    Check if a port is a privileged port (0-1023).
    
    Args:
        port: Port number to check
        
    Returns:
        bool: True if the port is privileged
    """
    return 0 <= port <= 1023

def is_well_known_port(port: int) -> bool:
    """
    Check if a port is a well-known port (0-1023).
    
    Args:
        port: Port number to check
        
    Returns:
        bool: True if the port is well-known
    """
    return 0 <= port <= 1023

def is_registered_port(port: int) -> bool:
    """
    Check if a port is a registered port (1024-49151).
    
    Args:
        port: Port number to check
        
    Returns:
        bool: True if the port is registered
    """
    return 1024 <= port <= 49151

def is_dynamic_port(port: int) -> bool:
    """
    Check if a port is a dynamic/private port (49152-65535).
    
    Args:
        port: Port number to check
        
    Returns:
        bool: True if the port is dynamic/private
    """
    return 49152 <= port <= 65535

def is_common_port(port: int) -> bool:
    """
    Check if a port is commonly used for standard services.
    
    Args:
        port: Port number to check
        
    Returns:
        bool: True if the port is commonly used
    """
    common_ports = {
        # Common TCP ports
        20, 21,     # FTP
        22,         # SSH
        23,         # Telnet
        25,         # SMTP
        53,         # DNS
        80,         # HTTP
        110,        # POP3
        115,        # SFTP
        143,        # IMAP
        194,        # IRC
        443,        # HTTPS
        465,        # SMTPS
        514,        # Syslog
        587,        # SMTP (message submission)
        636,        # LDAPS
        993,        # IMAPS
        995,        # POP3S
        1080,       # SOCKS proxy
        1194,       # OpenVPN
        1433,       # MS SQL Server
        1521,       # Oracle DB
        1723,       # PPTP
        2049,       # NFS
        2082, 2083, # cPanel
        2086, 2087, # WHM
        2095, 2096, # cPanel webmail
        2181,       # ZooKeeper
        2375, 2376, # Docker
        3000,       # Common web dev
        3306,       # MySQL
        3389,       # RDP
        3690,       # SVN
        4000,       # Common dev
        4369,       # Erlang port mapper
        5000,       # Common dev
        5432,       # PostgreSQL
        5672,       # AMQP
        5900,       # VNC
        6000,       # X11
        6379,       # Redis
        7000, 7001, # Cassandra
        8000, 8080, # Common web dev
        8081, 8082, # Common web dev
        8443,       # Common HTTPS alt
        8888,       # Common web dev
        9000,       # Common web dev
        9042,       # Cassandra
        9092,       # Kafka
        9200, 9300, # Elasticsearch
        11211,      # Memcached
        15672,      # RabbitMQ management
        16379,      # Redis Sentinel
        27017,      # MongoDB
        
        # Common UDP ports
        53,         # DNS
        67, 68,     # DHCP
        69,         # TFTP
        123,        # NTP
        161, 162,   # SNMP
        500,        # IPsec IKE
        514,        # Syslog
        1194,       # OpenVPN
        1701,       # L2TP
        4500,       # IPsec NAT-T
        5353,       # mDNS
        1900,       # UPnP
        10000,      # Webmin
    }
    
    return port in common_ports

def is_suspicious_port(port: int) -> bool:
    """
    Check if a port is commonly used for malicious activity.
    
    Args:
        port: Port number to check
        
    Returns:
        bool: True if the port is suspicious
    """
    suspicious_ports = {
        # Common malware C2 ports
        4444,  # Metasploit
        47120, # Windows Remote Desktop
        50050, # Kubernetes API - often targeted
        50051, # gRPC - often targeted
        31337, # Back Orifice
        47808, # BACnet - often scanned
        47809, # BACnet over IP - often scanned
        
        # Common brute force targets
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        110,   # POP3
        143,   # IMAP
        445,   # SMB
        993,   # IMAPS
        995,   # POP3S
        1433,  # MS SQL
        1521,  # Oracle
        1723,  # PPTP
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5900,  # VNC
        5985,  # WinRM
        5986,  # WinRM SSL
        8080,  # HTTP Proxy
        8443,  # HTTPS Proxy
        10000, # Webmin
    }
    
    return port in suspicious_ports

def get_service_name(port: int, protocol: str = 'tcp') -> str:
    """
    Get the common service name for a port and protocol.
    
    Args:
        port: Port number
        protocol: Protocol (tcp or udp)
        
    Returns:
        str: Service name if known, or 'unknown'
    """
    # Common TCP services
    tcp_services = {
        20: 'ftp-data',
        21: 'ftp',
        22: 'ssh',
        23: 'telnet',
        25: 'smtp',
        53: 'dns',
        80: 'http',
        110: 'pop3',
        143: 'imap',
        443: 'https',
        445: 'microsoft-ds',
        465: 'smtps',
        587: 'submission',
        993: 'imaps',
        995: 'pop3s',
        1433: 'ms-sql-s',
        1521: 'oracle',
        1723: 'pptp',
        2049: 'nfs',
        3306: 'mysql',
        3389: 'ms-wbt-server',
        5432: 'postgresql',
        5900: 'vnc',
        6000: 'x11',
        8080: 'http-proxy',
        8443: 'https-alt',
        8888: 'sun-answerbook',
        9000: 'cslistener',
        10000: 'snet-sensor-mgmt',
        11211: 'memcached',
        27017: 'mongod',
    }
    
    # Common UDP services
    udp_services = {
        53: 'dns',
        67: 'dhcps',
        68: 'dhcpc',
        69: 'tftp',
        123: 'ntp',
        161: 'snmp',
        162: 'snmptrap',
        500: 'isakmp',
        514: 'syslog',
        1701: 'l2tp',
        1900: 'upnp',
        4500: 'ipsec-nat-t',
        5353: 'mdns',
    }
    
    if protocol.lower() == 'udp':
        return udp_services.get(port, 'unknown')
    else:
        return tcp_services.get(port, 'unknown')

def is_private_domain(domain: str) -> bool:
    """
    Check if a domain is likely to be private/internal.
    
    Args:
        domain: Domain name to check
        
    Returns:
        bool: True if the domain appears to be private
    """
    if not domain:
        return False
        
    # Convert to lowercase and remove any leading/trailing dots
    domain = domain.lower().strip('.')
    
    # Check for common TLDs used internally
    internal_tlds = {
        'local', 'localdomain', 'intranet', 'internal', 'private', 'lan', 'home',
        'corp', 'office', 'company', 'test', 'dev', 'development', 'staging'
    }
    
    # Check if the domain ends with any internal TLDs
    if any(domain.endswith(f'.{tld}') or domain == tld for tld in internal_tlds):
        return True
    
    # Check for common internal domain patterns
    internal_patterns = [
        r'\.local$',
        r'\.local\.',
        r'\.int$',
        r'\.int\.',
        r'\.internal$',
        r'\.internal\.',
        r'\.lan$',
        r'\.lan\.',
        r'\.corp$',
        r'\.corp\.',
        r'\.prv$',
        r'\.prv\.',
        r'^10\.',
        r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
        r'^192\.168\.',
        r'^127\.',
        r'^169\.254\.',
        r'^localhost$',
    ]
    
    return any(re.search(pattern, domain) for pattern in internal_patterns)
