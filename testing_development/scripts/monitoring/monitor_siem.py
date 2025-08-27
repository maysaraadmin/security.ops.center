import os
import sys
import time
import logging
import subprocess
import psutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('siem_monitor.log')
    ]
)
logger = logging.getLogger('siem.monitor')

class SIEMServiceMonitor:
    def __init__(self):
        self.services = {
            'siem_main': {
                'cmd': ['python', 'main.py'],
                'port': 5000,
                'required': True,
                'process': None
            },
            'metrics': {
                'cmd': ['python', 'api/metrics_api.py'],
                'port': 9090,
                'required': True,
                'process': None
            },
            'log_collector': {
                'cmd': ['python', 'core/log_collector.py'],
                'port': None,
                'required': True,
                'process': None
            },
            'correlation_engine': {
                'cmd': ['python', 'core/correlation_engine.py'],
                'port': None,
                'required': True,
                'process': None
            }
        }
        
        self.check_interval = 60  # seconds
        self.max_restart_attempts = 3
        self.restart_attempts = {name: 0 for name in self.services}
    
    def find_process(self, cmd_parts: List[str]) -> Optional[psutil.Process]:
        """Find a process matching the command parts."""
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = proc.info['cmdline'] or []
                if all(part in ' '.join(cmdline) for part in cmd_parts):
                    return proc
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return None
    
    def is_port_in_use(self, port: int) -> bool:
        """Check if a port is in use."""
        if not port:
            return True
            
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('localhost', port)) == 0
    
    def start_service(self, name: str) -> bool:
        """Start a SIEM service."""
        if name not in self.services:
            logger.error(f"Unknown service: {name}")
            return False
            
        service = self.services[name]
        
        # Check if already running
        if service['process'] and service['process'].is_running():
            logger.info(f"Service {name} is already running (PID: {service['process'].pid})")
            return True
            
        # Check if port is available
        if service['port'] and self.is_port_in_use(service['port']):
            logger.warning(f"Port {service['port']} is already in use by another process")
            return False
            
        try:
            # Start the service
            proc = subprocess.Popen(
                service['cmd'],
                cwd=Path(__file__).parent.parent,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Store process info
            service['process'] = psutil.Process(proc.pid)
            self.restart_attempts[name] += 1
            
            logger.info(f"Started {name} (PID: {proc.pid})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start {name}: {e}")
            return False
    
    def stop_service(self, name: str) -> bool:
        """Stop a SIEM service gracefully."""
        if name not in self.services or not self.services[name]['process']:
            return True
            
        proc = self.services[name]['process']
        
        try:
            if proc.is_running():
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except psutil.TimeoutExpired:
                    proc.kill()
                
                logger.info(f"Stopped {name} (PID: {proc.pid})")
            
            self.services[name]['process'] = None
            return True
            
        except Exception as e:
            logger.error(f"Failed to stop {name}: {e}")
            return False
    
    def check_service(self, name: str) -> bool:
        """Check if a service is running and healthy."""
        if name not in self.services:
            return False
            
        service = self.services[name]
        
        # Check if process is running
        if not service['process'] or not service['process'].is_running():
            logger.warning(f"Service {name} is not running")
            return False
            
        # Check if port is listening (if applicable)
        if service['port'] and not self.is_port_in_use(service['port']):
            logger.warning(f"Service {name} is running but port {service['port']} is not listening")
            return False
            
        return True
    
    def monitor(self):
        """Monitor and maintain SIEM services."""
        logger.info("Starting SIEM service monitor...")
        
        try:
            while True:
                for name in self.services:
                    if not self.check_service(name):
                        logger.warning(f"Service {name} is not healthy")
                        
                        # Don't restart too many times
                        if self.restart_attempts[name] >= self.max_restart_attempts:
                            logger.error(f"Max restart attempts reached for {name}")
                            continue
                            
                        # Try to restart the service
                        logger.info(f"Attempting to restart {name}...")
                        if self.start_service(name):
                            logger.info(f"Successfully restarted {name}")
                        else:
                            logger.error(f"Failed to restart {name}")
                
                # Wait before next check
                time.sleep(self.check_interval)
                
        except KeyboardInterrupt:
            logger.info("Shutting down SIEM monitor...")
            self.shutdown()
        except Exception as e:
            logger.error(f"Monitor error: {e}", exc_info=True)
            self.shutdown()
    
    def shutdown(self):
        """Shutdown all services."""
        logger.info("Shutting down all services...")
        for name in self.services:
            self.stop_service(name)
        logger.info("All services stopped")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='SIEM Service Monitor')
    parser.add_argument('--start-all', action='store_true', help='Start all services')
    parser.add_argument('--stop-all', action='store_true', help='Stop all services')
    parser.add_argument('--status', action='store_true', help='Show status of all services')
    
    args = parser.parse_args()
    
    monitor = SIEMServiceMonitor()
    
    if args.start_all:
        for name in monitor.services:
            monitor.start_service(name)
    elif args.stop_all:
        for name in reversed(monitor.services):
            monitor.stop_service(name)
    elif args.status:
        for name in monitor.services:
            status = "RUNNING" if monitor.check_service(name) else "STOPPED"
            print(f"{name:20} {status}")
    else:
        # Start monitoring
        monitor.monitor()

if __name__ == "__main__":
    main()
