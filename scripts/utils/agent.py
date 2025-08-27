"""
EDR (Endpoint Detection and Response) Agent

This module implements the EDR agent that runs on endpoints to monitor system activities,
collect security events, and respond to commands from the EDR server.
"""
import os
import sys
import json
import time
import socket
import psutil
import hashlib
import logging
import platform
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable
import requests
import uuid

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('edr_agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('edr.agent')

class EDRAgent:
    """EDR Agent for endpoint monitoring and response"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the EDR agent with configuration"""
        self.config = config
        self.agent_id = self._get_agent_id()
        self.hostname = socket.gethostname()
        self.os_info = self._get_os_info()
        self.running = False
        self.last_heartbeat = 0
        self.server_url = config.get('server_url', 'http://localhost:5000')
        self.heartbeat_interval = config.get('heartbeat_interval', 60)  # seconds
        self.collectors = []
        self.command_handlers = {
            'scan_memory': self._handle_scan_memory,
            'scan_disk': self._handle_scan_disk,
            'quarantine_file': self._handle_quarantine_file,
            'get_process_info': self._handle_get_process_info,
            'kill_process': self._handle_kill_process,
            'block_ip': self._handle_block_ip,
            'collect_artifacts': self._handle_collect_artifacts
        }
        
        # Initialize collectors
        self._initialize_collectors()
    
    def _get_agent_id(self) -> str:
        """Generate a unique agent ID based on system information"""
        # Try to get a stable identifier for this system
        system_info = f"{platform.node()}-{platform.machine()}-{platform.processor()}"
        return hashlib.sha256(system_info.encode()).hexdigest()
    
    def _get_os_info(self) -> Dict[str, str]:
        """Get operating system information"""
        return {
            'system': platform.system(),
            'node': platform.node(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version()
        }
    
    def _initialize_collectors(self) -> None:
        """Initialize data collectors based on configuration"""
        collectors_config = self.config.get('collectors', {})
        
        # Process collector
        if collectors_config.get('process', {}).get('enabled', True):
            from .collectors.process_collector import ProcessCollector
            self.collectors.append(ProcessCollector(collectors_config.get('process', {})))
        
        # Network collector
        if collectors_config.get('network', {}).get('enabled', True):
            from .collectors.network_collector import NetworkCollector
            self.collectors.append(NetworkCollector(collectors_config.get('network', {})))
        
        # File system collector
        if collectors_config.get('filesystem', {}).get('enabled', True):
            from .collectors.filesystem_collector import FilesystemCollector
            self.collectors.append(FilesystemCollector(collectors_config.get('filesystem', {})))
        
        # Registry collector (Windows only)
        if platform.system() == 'Windows' and collectors_config.get('registry', {}).get('enabled', True):
            from .collectors.registry_collector import RegistryCollector
            self.collectors.append(RegistryCollector(collectors_config.get('registry', {})))
        
        logger.info(f"Initialized {len(self.collectors)} collectors")
    
    def start(self) -> None:
        """Start the EDR agent"""
        if self.running:
            logger.warning("EDR agent is already running")
            return
        
        self.running = True
        logger.info(f"Starting EDR Agent (ID: {self.agent_id})")
        
        # Start collectors
        for collector in self.collectors:
            try:
                collector.start()
                logger.debug(f"Started collector: {collector.__class__.__name__}")
            except Exception as e:
                logger.error(f"Failed to start collector {collector.__class__.__name__}: {str(e)}")
        
        # Start heartbeat thread
        heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        heartbeat_thread.start()
        
        # Start command processing thread
        command_thread = threading.Thread(target=self._command_loop, daemon=True)
        command_thread.start()
        
        logger.info("EDR agent started successfully")
    
    def stop(self) -> None:
        """Stop the EDR agent"""
        if not self.running:
            return
        
        logger.info("Stopping EDR agent...")
        self.running = False
        
        # Stop all collectors
        for collector in self.collectors:
            try:
                collector.stop()
            except Exception as e:
                logger.error(f"Error stopping collector {collector.__class__.__name__}: {str(e)}")
        
        logger.info("EDR agent stopped")
    
    def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats to the EDR server"""
        while self.running:
            try:
                self._send_heartbeat()
            except Exception as e:
                logger.error(f"Error sending heartbeat: {str(e)}")
            
            # Sleep until next heartbeat
            time.sleep(self.heartbeat_interval)
    
    def _send_heartbeat(self) -> None:
        """Send a heartbeat to the EDR server"""
        data = {
            'agent_id': self.agent_id,
            'hostname': self.hostname,
            'os_info': self.os_info,
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'online',
            'metrics': self._collect_metrics()
        }
        
        try:
            response = requests.post(
                f"{self.server_url}/api/v1/heartbeat",
                json=data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            response.raise_for_status()
            self.last_heartbeat = time.time()
            
            # Process any commands from the server
            if response.status_code == 200:
                commands = response.json().get('commands', [])
                if commands:
                    self._process_commands(commands)
            
            logger.debug("Heartbeat sent successfully")
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send heartbeat: {str(e)}")
    
    def _collect_metrics(self) -> Dict[str, Any]:
        """Collect system metrics"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            
            # Disk usage
            disk = psutil.disk_usage('/')
            
            # Process count
            process_count = len(psutil.pids())
            
            # Network I/O
            net_io = psutil.net_io_counters()
            
            return {
                'cpu_percent': cpu_percent,
                'memory': {
                    'total': memory.total,
                    'available': memory.available,
                    'percent': memory.percent,
                    'used': memory.used,
                    'free': memory.free
                },
                'disk': {
                    'total': disk.total,
                    'used': disk.used,
                    'free': disk.free,
                    'percent': disk.percent
                },
                'processes': {
                    'count': process_count
                },
                'network': {
                    'bytes_sent': net_io.bytes_sent,
                    'bytes_recv': net_io.bytes_recv,
                    'packets_sent': net_io.packets_sent,
                    'packets_recv': net_io.packets_recv,
                    'err_in': net_io.errin,
                    'err_out': net_io.errout,
                    'drop_in': net_io.dropin,
                    'drop_out': net_io.dropout
                },
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error collecting metrics: {str(e)}")
            return {}
    
    def _command_loop(self) -> None:
        """Main loop for processing commands from the server"""
        while self.running:
            try:
                self._check_commands()
            except Exception as e:
                logger.error(f"Error in command loop: {str(e)}")
            
            # Check for commands every 30 seconds
            time.sleep(30)
    
    def _check_commands(self) -> None:
        """Check for new commands from the server"""
        try:
            response = requests.get(
                f"{self.server_url}/api/v1/commands/{self.agent_id}",
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            response.raise_for_status()
            
            commands = response.json().get('commands', [])
            if commands:
                self._process_commands(commands)
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch commands: {str(e)}")
    
    def _process_commands(self, commands: List[Dict[str, Any]]) -> None:
        """Process commands from the server"""
        results = []
        
        for cmd in commands:
            try:
                command_id = cmd.get('id')
                command_type = cmd.get('type')
                command_args = cmd.get('args', {})
                
                logger.info(f"Processing command: {command_type} (ID: {command_id})")
                
                # Find and execute the command handler
                handler = self.command_handlers.get(command_type)
                if handler:
                    result = handler(command_args)
                    results.append({
                        'command_id': command_id,
                        'status': 'success',
                        'result': result
                    })
                else:
                    results.append({
                        'command_id': command_id,
                        'status': 'error',
                        'error': f"Unknown command type: {command_type}"
                    })
                    
            except Exception as e:
                logger.error(f"Error processing command: {str(e)}")
                results.append({
                    'command_id': command_id,
                    'status': 'error',
                    'error': str(e)
                })
        
        # Send command results back to the server
        if results:
            self._send_command_results(results)
    
    def _send_command_results(self, results: List[Dict[str, Any]]) -> None:
        """Send command execution results to the server"""
        try:
            response = requests.post(
                f"{self.server_url}/api/v1/command_results",
                json={
                    'agent_id': self.agent_id,
                    'results': results
                },
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            response.raise_for_status()
            logger.info(f"Sent {len(results)} command results to server")
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send command results: {str(e)}")
    
    # Command Handlers
    
    def _handle_scan_memory(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Handle memory scan command"""
        logger.info(f"Scanning memory with args: {args}")
        
        # In a real implementation, this would scan memory for suspicious patterns
        # For now, we'll just return some mock data
        return {
            'status': 'completed',
            'suspicious_regions': [],
            'scan_duration': 1.5,
            'memory_analyzed_mb': 2048
        }
    
    def _handle_scan_disk(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Handle disk scan command"""
        path = args.get('path', '/')
        logger.info(f"Scanning disk at {path} with args: {args}")
        
        # In a real implementation, this would scan the disk for malicious files
        # For now, we'll just return some mock data
        return {
            'status': 'completed',
            'path': path,
            'files_scanned': 0,
            'threats_found': 0,
            'scan_duration': 5.2
        }
    
    def _handle_quarantine_file(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Handle file quarantine command"""
        file_path = args.get('file_path')
        if not file_path:
            raise ValueError("Missing required parameter: file_path")
        
        logger.info(f"Quarantining file: {file_path}")
        
        # In a real implementation, this would move the file to quarantine
        # and log the action
        return {
            'status': 'quarantined',
            'file_path': file_path,
            'quarantine_id': str(uuid.uuid4()),
            'original_md5': hashlib.md5(file_path.encode()).hexdigest()
        }
    
    def _handle_get_process_info(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get process info command"""
        pid = args.get('pid')
        if not pid:
            raise ValueError("Missing required parameter: pid")
        
        logger.info(f"Getting info for process {pid}")
        
        try:
            process = psutil.Process(pid)
            
            return {
                'pid': process.pid,
                'name': process.name(),
                'exe': process.exe(),
                'cmdline': process.cmdline(),
                'status': process.status(),
                'username': process.username(),
                'create_time': process.create_time(),
                'cpu_percent': process.cpu_percent(interval=0.1),
                'memory_percent': process.memory_percent(),
                'open_files': [f.path for f in process.open_files()],
                'connections': [{
                    'fd': conn.fd,
                    'family': conn.family,
                    'type': conn.type,
                    'laddr': conn.laddr,
                    'raddr': conn.raddr,
                    'status': conn.status
                } for conn in process.connections()]
            }
            
        except psutil.NoSuchProcess:
            return {
                'error': f"Process with PID {pid} not found",
                'exists': False
            }
    
    def _handle_kill_process(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Handle kill process command"""
        pid = args.get('pid')
        if not pid:
            raise ValueError("Missing required parameter: pid")
        
        logger.warning(f"Killing process {pid}")
        
        try:
            process = psutil.Process(pid)
            process.terminate()
            
            # Wait for process to terminate
            try:
                process.wait(timeout=5)
            except psutil.TimeoutExpired:
                process.kill()
            
            return {
                'status': 'terminated',
                'pid': pid,
                'name': process.name()
            }
            
        except psutil.NoSuchProcess:
            return {
                'error': f"Process with PID {pid} not found",
                'exists': False
            }
    
    def _handle_block_ip(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Handle block IP command"""
        ip_address = args.get('ip_address')
        direction = args.get('direction', 'both')  # 'in', 'out', or 'both'
        
        if not ip_address:
            raise ValueError("Missing required parameter: ip_address")
        
        logger.info(f"Blocking IP {ip_address} (direction: {direction})")
        
        # In a real implementation, this would add a firewall rule
        # For now, we'll just return a success response
        return {
            'status': 'blocked',
            'ip_address': ip_address,
            'direction': direction,
            'rule_id': f"block_{ip_address}_{int(time.time())}"
        }
    
    def _handle_collect_artifacts(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Handle collect artifacts command"""
        artifact_types = args.get('types', [])
        output_dir = args.get('output_dir', '/tmp/artifacts')
        
        if not artifact_types:
            artifact_types = ['processes', 'network', 'files', 'registry']
        
        logger.info(f"Collecting artifacts: {', '.join(artifact_types)}")
        
        # In a real implementation, this would collect the requested artifacts
        # For now, we'll just return a success response
        return {
            'status': 'collected',
            'artifact_types': artifact_types,
            'output_dir': output_dir,
            'files': [
                f"{output_dir}/processes.json",
                f"{output_dir}/network_connections.json",
                f"{output_dir}/suspicious_files.tar.gz"
            ]
        }

def main():
    """Main entry point for the EDR agent"""
    # Default configuration
    config = {
        'server_url': 'http://localhost:5000',
        'heartbeat_interval': 60,
        'collectors': {
            'process': {'enabled': True},
            'network': {'enabled': True},
            'filesystem': {'enabled': True},
            'registry': {'enabled': platform.system() == 'Windows'}
        }
    }
    
    # Create and start the agent
    agent = EDRAgent(config)
    
    try:
        agent.start()
        
        # Keep the main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Shutting down EDR agent...")
        agent.stop()
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}", exc_info=True)
        agent.stop()
        sys.exit(1)

if __name__ == "__main__":
    main()
