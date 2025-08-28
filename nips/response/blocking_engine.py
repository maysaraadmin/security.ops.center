"""
Automated Threat Blocking Engine for NIPS
"""
import ipaddress
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple, Union, Any
import subprocess
import platform
import time
import threading
from datetime import datetime, timedelta
import socket
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('nips_blocking')

class BlockAction(Enum):
    """Types of blocking actions."""
    DROP = "drop"
    REJECT = "reject"
    QUARANTINE = "quarantine"
    TERMINATE = "terminate"
    RATE_LIMIT = "rate_limit"

class BlockTarget(Enum):
    """Types of targets that can be blocked."""
    IP = "ip"
    PORT = "port"
    SESSION = "session"
    HOST = "host"
    DOMAIN = "domain"
    USER = "user"

@dataclass
class BlockRule:
    """A rule defining what to block and how."""
    action: BlockAction
    target_type: BlockTarget
    target: str  # IP, port, session ID, etc.
    protocol: Optional[str] = None  # tcp, udp, icmp, etc.
    port: Optional[int] = None  # For IP+port blocking
    direction: str = "both"  # in, out, both
    duration: int = 3600  # seconds, 0 for permanent
    reason: str = ""
    created_at: float = field(default_factory=time.time)
    active: bool = True
    
    @property
    def expires_at(self) -> Optional[float]:
        """When this block will expire, or None if permanent."""
        if self.duration <= 0:
            return None
        return self.created_at + self.duration
    
    def is_expired(self) -> bool:
        """Check if this block rule has expired."""
        if self.duration <= 0:
            return False
        return time.time() > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'action': self.action.value,
            'target_type': self.target_type.value,
            'target': self.target,
            'protocol': self.protocol,
            'port': self.port,
            'direction': self.direction,
            'duration': self.duration,
            'reason': self.reason,
            'created_at': self.created_at,
            'expires_at': self.expires_at,
            'active': self.active
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BlockRule':
        """Create a BlockRule from a dictionary."""
        return cls(
            action=BlockAction(data['action']),
            target_type=BlockTarget(data['target_type']),
            target=data['target'],
            protocol=data.get('protocol'),
            port=data.get('port'),
            direction=data.get('direction', 'both'),
            duration=data.get('duration', 3600),
            reason=data.get('reason', ''),
            created_at=data.get('created_at', time.time()),
            active=data.get('active', True)
        )

class BlockingEngine:
    """
    Engine for managing and applying network blocks.
    Supports multiple backends (iptables, Windows Firewall, etc.)
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the blocking engine."""
        self.config = config or {}
        self.rules: Dict[str, BlockRule] = {}
        self.lock = threading.RLock()
        self.backend = self._get_backend()
        self.quarantine_networks: List[ipaddress.IPv4Network] = []
        self._load_quarantine_networks()
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_expired_rules,
            daemon=True
        )
        self._cleanup_thread.start()
    
    def _get_backend(self):
        """Get the appropriate blocking backend for the current platform."""
        system = platform.system().lower()
        if system == 'linux':
            return IPTablesBackend()
        elif system == 'windows':
            return WindowsFirewallBackend()
        else:
            logger.warning(f"Unsupported platform {system}, using dummy backend")
            return DummyBackend()
    
    def _load_quarantine_networks(self):
        """Load quarantine network configurations."""
        quarantine_config = self.config.get('quarantine', {})
        networks = quarantine_config.get('networks', [])
        
        for net in networks:
            try:
                self.quarantine_networks.append(ipaddress.IPv4Network(net))
            except ValueError as e:
                logger.error(f"Invalid quarantine network {net}: {e}")
    
    def _cleanup_expired_rules(self):
        """Background thread to clean up expired rules."""
        while True:
            try:
                with self.lock:
                    now = time.time()
                    to_remove = [
                        rule_id for rule_id, rule in self.rules.items()
                        if rule.is_expired()
                    ]
                    
                    for rule_id in to_remove:
                        self._remove_rule(rule_id)
                        logger.info(f"Removed expired block rule: {rule_id}")
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Error in cleanup thread: {e}", exc_info=True)
                time.sleep(10)  # Avoid tight loop on error
    
    def _get_rule_id(self, rule: BlockRule) -> str:
        """Generate a unique ID for a rule."""
        parts = [
            rule.action.value,
            rule.target_type.value,
            rule.target,
            str(rule.protocol or ''),
            str(rule.port or ''),
            rule.direction,
            str(rule.duration)
        ]
        return hashlib.md5('|'.join(parts).encode()).hexdigest()
    
    def add_block_rule(self, rule: BlockRule) -> str:
        """
        Add a new block rule.
        Returns the rule ID.
        """
        with self.lock:
            rule_id = self._get_rule_id(rule)
            
            if rule_id in self.rules:
                # Update existing rule
                existing_rule = self.rules[rule_id]
                if not existing_rule.is_expired():
                    # Extend the duration if the new rule has a longer duration
                    if rule.duration > 0 and (
                        existing_rule.duration <= 0 or 
                        rule.created_at + rule.duration > existing_rule.expires_at
                    ):
                        existing_rule.duration = rule.duration
                        existing_rule.created_at = rule.created_at
                        logger.info(f"Updated existing block rule: {rule_id}")
                    return rule_id
            
            # Add new rule
            self.rules[rule_id] = rule
            
            try:
                # Apply the block
                if rule.target_type == BlockTarget.IP:
                    self.backend.block_ip(
                        ip=rule.target,
                        protocol=rule.protocol,
                        port=rule.port,
                        direction=rule.direction,
                        action=rule.action
                    )
                elif rule.target_type == BlockTarget.PORT:
                    self.backend.block_port(
                        port=int(rule.target),
                        protocol=rule.protocol
                    )
                elif rule.target_type == BlockTarget.SESSION:
                    self.backend.terminate_session(rule.target)
                elif rule.target_type == BlockTarget.HOST:
                    self.backend.quarantine_host(rule.target)
                
                logger.info(f"Added new block rule: {rule_id} - {rule.action.value} {rule.target_type.value} {rule.target}")
                
            except Exception as e:
                logger.error(f"Failed to apply block rule {rule_id}: {e}", exc_info=True)
                rule.active = False
            
            return rule_id
    
    def remove_block_rule(self, rule_id: str) -> bool:
        """Remove a block rule by ID."""
        with self.lock:
            if rule_id in self.rules:
                self._remove_rule(rule_id)
                return True
            return False
    
    def _remove_rule(self, rule_id: str):
        """Internal method to remove a rule."""
        rule = self.rules[rule_id]
        
        try:
            # Remove the block
            if rule.target_type == BlockTarget.IP:
                self.backend.unblock_ip(
                    ip=rule.target,
                    protocol=rule.protocol,
                    port=rule.port,
                    direction=rule.direction
                )
            elif rule.target_type == BlockTarget.PORT:
                self.backend.unblock_port(
                    port=int(rule.target),
                    protocol=rule.protocol
                )
            elif rule.target_type == BlockTarget.HOST:
                self.backend.release_host(rule.target)
            
            logger.info(f"Removed block rule: {rule_id}")
            
        except Exception as e:
            logger.error(f"Failed to remove block rule {rule_id}: {e}", exc_info=True)
        finally:
            del self.rules[rule_id]
    
    def get_active_rules(self) -> List[Dict[str, Any]]:
        """Get all active block rules as dictionaries."""
        with self.lock:
            now = time.time()
            return [
                rule.to_dict() | {'id': rule_id}
                for rule_id, rule in self.rules.items()
                if not rule.is_expired() and rule.active
            ]
    
    def is_blocked(self, target: str, target_type: BlockTarget) -> bool:
        """Check if a target is currently blocked."""
        with self.lock:
            now = time.time()
            for rule in self.rules.values():
                if (
                    rule.target_type == target_type and 
                    rule.target == target and 
                    not rule.is_expired() and 
                    rule.active
                ):
                    return True
            return False
    
    def clear_all_rules(self):
        """Remove all block rules."""
        with self.lock:
            for rule_id in list(self.rules.keys()):
                self._remove_rule(rule_id)

class BlockingBackend(ABC):
    """Abstract base class for blocking backends."""
    
    @abstractmethod
    def block_ip(self, ip: str, protocol: Optional[str] = None, 
                port: Optional[int] = None, direction: str = "both",
                action: BlockAction = BlockAction.DROP) -> bool:
        """Block an IP address."""
        pass
    
    @abstractmethod
    def unblock_ip(self, ip: str, protocol: Optional[str] = None, 
                  port: Optional[int] = None, direction: str = "both") -> bool:
        """Unblock an IP address."""
        pass
    
    @abstractmethod
    def block_port(self, port: int, protocol: str) -> bool:
        """Block a port."""
        pass
    
    @abstractmethod
    def unblock_port(self, port: int, protocol: str) -> bool:
        """Unblock a port."""
        pass
    
    @abstractmethod
    def terminate_session(self, session_id: str) -> bool:
        """Terminate a network session."""
        pass
    
    @abstractmethod
    def quarantine_host(self, host: str) -> bool:
        """Quarantine a host."""
        pass
    
    @abstractmethod
    def release_host(self, host: str) -> bool:
        """Release a host from quarantine."""
        pass

class IPTablesBackend(BlockingBackend):
    """Linux iptables backend for blocking."""
    
    def __init__(self):
        self.chain = "NIPS_BLOCK"
        self._init_iptables()
    
    def _run_command(self, cmd: List[str]) -> bool:
        """Run a shell command and return success status."""
        try:
            subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {' '.join(cmd)}")
            logger.error(f"Error: {e.stderr}")
            return False
    
    def _init_iptables(self):
        """Initialize iptables with our custom chain if needed."""
        # Check if our chain exists
        result = subprocess.run(
            ['iptables', '-L', self.chain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        if result.returncode != 0:
            # Chain doesn't exist, create it
            cmds = [
                ['iptables', '-N', self.chain],
                ['iptables', '-A', 'INPUT', '-j', self.chain],
                ['iptables', '-A', 'FORWARD', '-j', self.chain]
            ]
            
            for cmd in cmds:
                if not self._run_command(cmd):
                    logger.error("Failed to initialize iptables rules")
                    return False
        
        return True
    
    def block_ip(self, ip: str, protocol: Optional[str] = None, 
                port: Optional[int] = None, direction: str = "both",
                action: BlockAction = BlockAction.DROP) -> bool:
        """Block an IP address using iptables."""
        if not self._is_valid_ip(ip):
            logger.error(f"Invalid IP address: {ip}")
            return False
        
        target = 'DROP' if action == BlockAction.DROP else 'REJECT'
        
        # Build the iptables command
        cmd = ['iptables', '-A', self.chain]
        
        # Add protocol if specified
        if protocol:
            cmd.extend(['-p', protocol])
        
        # Add source/destination based on direction
        if direction in ('in', 'both'):
            cmd.extend(['-s', ip])
        if direction in ('out', 'both'):
            cmd.extend(['-d', ip])
        
        # Add port if specified
        if port is not None:
            if protocol == 'tcp' or protocol == 'udp':
                cmd.extend(['--dport', str(port)])
        
        # Add the target
        cmd.extend(['-j', target])
        
        # Add a comment for tracking
        cmd.extend(['-m', 'comment', '--comment', f'nips_block_{int(time.time())}'])
        
        return self._run_command(cmd)
    
    def unblock_ip(self, ip: str, protocol: Optional[str] = None, 
                  port: Optional[int] = None, direction: str = "both") -> bool:
        """Unblock an IP address."""
        if not self._is_valid_ip(ip):
            logger.error(f"Invalid IP address: {ip}")
            return False
        
        # List all rules in our chain
        result = subprocess.run(
            ['iptables', '-L', self.chain, '--line-numbers', '-n'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if result.returncode != 0:
            logger.error("Failed to list iptables rules")
            return False
        
        # Parse the output to find matching rules
        lines = result.stdout.splitlines()
        rules_to_delete = []
        
        for line in lines:
            if not line.strip() or line.startswith('Chain') or line.startswith('target'):
                continue
                
            parts = line.split()
            if len(parts) < 4:
                continue
                
            rule_num = parts[0]
            target = parts[1]
            prot = parts[2]
            opt = parts[3]
            
            # Check if this rule matches our criteria
            if protocol and prot != protocol:
                continue
                
            # Check source/destination IP
            src = None
            dst = None
            dport = None
            
            i = 0
            while i < len(parts):
                if parts[i] == '--source' or parts[i] == '-s':
                    src = parts[i+1] if i+1 < len(parts) else None
                elif parts[i] == '--destination' or parts[i] == '-d':
                    dst = parts[i+1] if i+1 < len(parts) else None
                elif parts[i] == '--dport':
                    dport = int(parts[i+1]) if i+1 < len(parts) else None
                i += 1
            
            # Check if this rule matches our IP and direction
            if ((direction in ('in', 'both') and src == ip) or 
                (direction in ('out', 'both') and dst == ip)):
                # Check port if specified
                if port is not None and dport != port:
                    continue
                    
                rules_to_delete.append(rule_num)
        
        # Delete matching rules (in reverse order to avoid renumbering issues)
        success = True
        for rule_num in sorted(rules_to_delete, reverse=True, key=int):
            if not self._run_command(['iptables', '-D', self.chain, rule_num]):
                success = False
        
        return success
    
    def block_port(self, port: int, protocol: str) -> bool:
        """Block a port."""
        if protocol not in ('tcp', 'udp'):
            logger.error(f"Unsupported protocol for port blocking: {protocol}")
            return False
            
        cmd = [
            'iptables', '-A', self.chain,
            '-p', protocol,
            '--dport', str(port),
            '-j', 'DROP',
            '-m', 'comment', '--comment', f'nips_block_port_{port}_{protocol}'
        ]
        
        return self._run_command(cmd)
    
    def unblock_port(self, port: int, protocol: str) -> bool:
        """Unblock a port."""
        if protocol not in ('tcp', 'udp'):
            logger.error(f"Unsupported protocol for port blocking: {protocol}")
            return False
            
        # List all rules in our chain
        result = subprocess.run(
            ['iptables', '-L', self.chain, '--line-numbers', '-n'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if result.returncode != 0:
            logger.error("Failed to list iptables rules")
            return False
        
        # Parse the output to find matching rules
        lines = result.stdout.splitlines()
        rules_to_delete = []
        
        for line in lines:
            if not line.strip() or line.startswith('Chain') or line.startswith('target'):
                continue
                
            parts = line.split()
            if len(parts) < 4:
                continue
                
            rule_num = parts[0]
            target = parts[1]
            prot = parts[2]
            
            # Check if this rule matches our criteria
            if prot != protocol:
                continue
                
            # Look for dport in the rule
            dport = None
            for i in range(len(parts)):
                if parts[i] == '--dport' and i+1 < len(parts):
                    try:
                        dport = int(parts[i+1])
                    except ValueError:
                        pass
                    break
            
            if dport == port:
                rules_to_delete.append(rule_num)
        
        # Delete matching rules (in reverse order)
        success = True
        for rule_num in sorted(rules_to_delete, reverse=True, key=int):
            if not self._run_command(['iptables', '-D', self.chain, rule_num]):
                success = False
        
        return success
    
    def terminate_session(self, session_id: str) -> bool:
        """Terminate a network session using conntrack."""
        if not os.path.exists('/proc/net/nf_conntrack'):
            logger.error("conntrack not supported on this system")
            return False
            
        # Find the connection by ID and kill it
        cmd = ['conntrack', '-D', '--orig-src', session_id]
        return self._run_command(cmd)
    
    def quarantine_host(self, host: str) -> bool:
        """Quarantine a host by moving it to a separate VLAN or network segment."""
        # This is a placeholder - actual implementation would depend on your network setup
        logger.warning(f"Quarantine host not fully implemented: {host}")
        return True
    
    def release_host(self, host: str) -> bool:
        """Release a host from quarantine."""
        # This is a placeholder - actual implementation would depend on your network setup
        logger.warning(f"Release host not fully implemented: {host}")
        return True
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if a string is a valid IP address."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

class WindowsFirewallBackend(BlockingBackend):
    """Windows Firewall backend for blocking."""
    
    def __init__(self):
        self.rule_prefix = "NIPS_"
    
    def _run_powershell(self, script: str) -> bool:
        """Run a PowerShell script and return success status."""
        try:
            subprocess.run(
                ['powershell', '-Command', script],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"PowerShell command failed: {script}")
            logger.error(f"Error: {e.stderr}")
            return False
    
    def block_ip(self, ip: str, protocol: Optional[str] = None, 
                port: Optional[int] = None, direction: str = "both",
                action: BlockAction = BlockAction.DROP) -> bool:
        """Block an IP address using Windows Firewall."""
        if not self._is_valid_ip(ip):
            logger.error(f"Invalid IP address: {ip}")
            return False
        
        # Create a unique rule name
        rule_name = f"{self.rule_prefix}BLOCK_IP_{ip.replace('.', '_')}_{int(time.time())}"
        
        # Build the PowerShell command
        cmd = [
            'New-NetFirewallRule',
            f'-DisplayName "{rule_name}"',
            f'-Name "{rule_name}"',
            '-Enabled True',
            '-Profile Any',
            '-Direction Inbound' if direction in ('in', 'both') else '-Direction Outbound',
            '-Action Block',
            f'-RemoteAddress {ip}'
        ]
        
        # Add protocol if specified
        if protocol:
            cmd.append(f'-Protocol {protocol.upper()}')
            
            # Add port if specified
            if port is not None and protocol in ('tcp', 'udp'):
                cmd.append(f'-LocalPort {port}')
        
        # Execute the command
        ps_script = '; '.join(cmd)
        return self._run_powershell(ps_script)
    
    def unblock_ip(self, ip: str, protocol: Optional[str] = None, 
                  port: Optional[int] = None, direction: str = "both") -> bool:
        """Unblock an IP address."""
        # Find and remove all matching rules
        ps_script = f'''
        $rules = Get-NetFirewallRule -DisplayName "{self.rule_prefix}BLOCK_IP_*" | Where {{
            $_.Direction -eq 'Inbound' -or $_.Direction -eq 'Outbound'
        }}
        foreach ($rule in $rules) {{
            $addr = (Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule).RemoteAddress
            if ($addr -eq '{ip}') {{
                Remove-NetFirewallRule -Name $rule.Name -Confirm:$false
            }}
        }}
        '''
        return self._run_powershell(ps_script)
    
    def block_port(self, port: int, protocol: str) -> bool:
        """Block a port."""
        if protocol.lower() not in ('tcp', 'udp'):
            logger.error(f"Unsupported protocol for port blocking: {protocol}")
            return False
            
        rule_name = f"{self.rule_prefix}BLOCK_PORT_{protocol.upper()}_{port}"
        
        ps_script = f'''
        if (-not (Get-NetFirewallRule -DisplayName "{rule_name}" -ErrorAction SilentlyContinue)) {{
            New-NetFirewallRule -DisplayName "{rule_name}" `
                              -Name "{rule_name}" `
                              -Enabled True `
                              -Profile Any `
                              -Direction Inbound `
                              -Action Block `
                              -Protocol {protocol.upper()} `
                              -LocalPort {port}
        }}
        '''
        return self._run_powershell(ps_script)
    
    def unblock_port(self, port: int, protocol: str) -> bool:
        """Unblock a port."""
        rule_name = f"{self.rule_prefix}BLOCK_PORT_{protocol.upper()}_{port}"
        ps_script = f'Remove-NetFirewallRule -DisplayName "{rule_name}" -Confirm:$false'
        return self._run_powershell(ps_script)
    
    def terminate_session(self, session_id: str) -> bool:
        """Terminate a network session."""
        # This is a simplified example - in practice, you'd need to map the session ID
        # to the appropriate connection and terminate it
        ps_script = f'''
        $session = Get-NetTCPConnection -State Established | Where {{
            $_.LocalAddress -eq '{session_id}' -or $_.RemoteAddress -eq '{session_id}'
        }}
        if ($session) {{
            $session | ForEach-Object {{ $_ | Remove-NetTCPConnection -Confirm:$false }}
        }}
        '''
        return self._run_powershell(ps_script)
    
    def quarantine_host(self, host: str) -> bool:
        """Quarantine a host."""
        # This is a placeholder - actual implementation would depend on your network setup
        logger.warning(f"Quarantine host not fully implemented: {host}")
        return True
    
    def release_host(self, host: str) -> bool:
        """Release a host from quarantine."""
        # This is a placeholder - actual implementation would depend on your network setup
        logger.warning(f"Release host not fully implemented: {host}")
        return True
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if a string is a valid IP address."""
        try:
            socket.inet_pton(socket.AF_INET, ip)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, ip)
                return True
            except socket.error:
                return False

class DummyBackend(BlockingBackend):
    """Dummy backend for testing or unsupported platforms."""
    
    def block_ip(self, ip: str, protocol: Optional[str] = None, 
                port: Optional[int] = None, direction: str = "both",
                action: BlockAction = BlockAction.DROP) -> bool:
        logger.info(f"[DUMMY] Would block IP: {ip}, protocol: {protocol}, port: {port}, direction: {direction}, action: {action}")
        return True
    
    def unblock_ip(self, ip: str, protocol: Optional[str] = None, 
                  port: Optional[int] = None, direction: str = "both") -> bool:
        logger.info(f"[DUMMY] Would unblock IP: {ip}, protocol: {protocol}, port: {port}, direction: {direction}")
        return True
    
    def block_port(self, port: int, protocol: str) -> bool:
        logger.info(f"[DUMMY] Would block port: {port}/{protocol}")
        return True
    
    def unblock_port(self, port: int, protocol: str) -> bool:
        logger.info(f"[DUMMY] Would unblock port: {port}/{protocol}")
        return True
    
    def terminate_session(self, session_id: str) -> bool:
        logger.info(f"[DUMMY] Would terminate session: {session_id}")
        return True
    
    def quarantine_host(self, host: str) -> bool:
        logger.info(f"[DUMMY] Would quarantine host: {host}")
        return True
    
    def release_host(self, host: str) -> bool:
        logger.info(f"[DUMMY] Would release host: {host}")
        return True
