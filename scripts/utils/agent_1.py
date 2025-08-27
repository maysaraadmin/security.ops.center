"""
EDR Agent - Endpoint Detection and Response Agent

This module implements the EDR agent that runs on endpoints to collect security events,
apply detection rules, and execute response actions.
"""
import logging
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import platform
import psutil
import socket
import json

logger = logging.getLogger('edr.agent')

@dataclass
class SystemInfo:
    """System information collected by the EDR agent."""
    hostname: str
    os: str
    os_version: str
    architecture: str
    cpu_cores: int
    total_memory: int  # in MB
    ip_addresses: Dict[str, List[str]]  # interface -> list of IPs
    mac_addresses: Dict[str, str]  # interface -> MAC address
    boot_time: float
    users: List[str]
    processes: int
    timestamp: float = field(default_factory=time.time)

class EDRAgent:
    """
    EDR Agent that runs on endpoints to monitor and respond to security events.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the EDR agent with configuration."""
        self.config = config or {
            'collect_interval': 60,  # seconds
            'server_url': 'http://localhost:8000',
            'enabled_modules': ['process', 'network', 'file'],
            'log_level': 'INFO'
        }
        self.running = False
        self.last_heartbeat = 0
        self.agent_id = self._generate_agent_id()
        self.system_info = self._collect_system_info()
        
        # Configure logging
        log_level = getattr(logging, self.config.get('log_level', 'INFO').upper())
        logging.basicConfig(level=log_level)
        
        logger.info(f"EDR Agent {self.agent_id} initialized on {self.system_info.hostname}")
    
    def _generate_agent_id(self) -> str:
        """Generate a unique ID for this agent."""
        hostname = socket.gethostname()
        system_info = f"{platform.system()}-{platform.machine()}-{platform.node()}"
        return f"{hostname}-{hash(system_info) & 0xFFFFFFFF}"
    
    def _collect_system_info(self) -> SystemInfo:
        """Collect system information."""
        net_if_addrs = psutil.net_if_addrs()
        
        return SystemInfo(
            hostname=socket.gethostname(),
            os=f"{platform.system()} {platform.release()}",
            os_version=platform.version(),
            architecture=platform.machine(),
            cpu_cores=psutil.cpu_count(),
            total_memory=psutil.virtual_memory().total // (1024 * 1024),  # Convert to MB
            ip_addresses={
                iface: [addr.address for addr in addrs if addr.family == socket.AF_INET]
                for iface, addrs in net_if_addrs.items()
            },
            mac_addresses={
                iface: next((addr.address for addr in addrs if addr.family == psutil.AF_LINK), "")
                for iface, addrs in net_if_addrs.items()
            },
            boot_time=psutil.boot_time(),
            users=[user.name for user in psutil.users()],
            processes=len(psutil.pids())
        )
    
    def start(self) -> None:
        """Start the EDR agent."""
        if self.running:
            logger.warning("EDR Agent is already running")
            return
            
        self.running = True
        logger.info("Starting EDR Agent...")
        
        try:
            while self.running:
                self._heartbeat()
                time.sleep(self.config['collect_interval'])
        except KeyboardInterrupt:
            logger.info("Shutting down EDR Agent...")
        except Exception as e:
            logger.error(f"EDR Agent error: {e}", exc_info=True)
        finally:
            self.running = False
    
    def stop(self) -> None:
        """Stop the EDR agent."""
        self.running = False
        logger.info("EDR Agent stopped")
    
    def _heartbeat(self) -> None:
        """Send a heartbeat to the EDR server."""
        try:
            self.last_heartbeat = time.time()
            # In a real implementation, this would send data to the EDR server
            logger.debug(f"Heartbeat from agent {self.agent_id}")
            
        except Exception as e:
            logger.error(f"Heartbeat failed: {e}", exc_info=True)
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the EDR agent."""
        return {
            'agent_id': self.agent_id,
            'running': self.running,
            'last_heartbeat': self.last_heartbeat,
            'system_info': {
                'hostname': self.system_info.hostname,
                'os': self.system_info.os,
                'ip_addresses': self.system_info.ip_addresses,
                'status': 'healthy' if self.running else 'stopped'
            }
        }

# Example usage
if __name__ == "__main__":
    agent = EDRAgent()
    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()
