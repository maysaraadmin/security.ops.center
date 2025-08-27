import logging
import psutil
import socket
import json
import time
from datetime import datetime
from typing import Dict, List, Optional
import threading
import platform
import os

class EDRAgent:
    """
    Endpoint Detection and Response (EDR) Agent
    Monitors system activities and detects potential security threats.
    """
    
    def __init__(self, siem_endpoint: str, check_interval: int = 60):
        """
        Initialize the EDR Agent
        
        Args:
            siem_endpoint: URL of the SIEM system to send alerts to
            check_interval: Interval in seconds between system checks
        """
        self.siem_endpoint = siem_endpoint
        self.check_interval = check_interval
        self.running = False
        self.hostname = socket.gethostname()
        self.agent_id = f"edr-{self.hostname}-{os.getpid()}"
        self.logger = self._setup_logging()
        self.baseline = {}
        
    def _setup_logging(self) -> logging.Logger:
        """Configure logging for the EDR agent"""
        logger = logging.getLogger('edr_agent')
        logger.setLevel(logging.INFO)
        
        # Create console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        
        # Add handler to logger
        logger.addHandler(ch)
        return logger
    
    def collect_system_info(self) -> Dict:
        """Collect basic system information"""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "hostname": self.hostname,
            "os": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine()
            },
            "cpu": {
                "cores": psutil.cpu_count(logical=False),
                "logical_cores": psutil.cpu_count(),
                "usage": psutil.cpu_percent(interval=1, percpu=True)
            },
            "memory": {
                "total": psutil.virtual_memory().total,
                "available": psutil.virtual_memory().available,
                "percent_used": psutil.virtual_memory().percent
            },
            "disks": [{
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "total": psutil.disk_usage(part.mountpoint).total,
                "used": psutil.disk_usage(part.mountpoint).used,
                "free": psutil.disk_usage(part.mountpoint).free,
                "percent_used": psutil.disk_usage(part.mountpoint).percent
            } for part in psutil.disk_partitions()]
        }
    
    def detect_suspicious_processes(self) -> List[Dict]:
        """Detect potentially suspicious processes"""
        suspicious = []
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'exe', 'cmdline', 'create_time']):
            try:
                process_info = proc.info
                
                # Example detection logic - can be expanded
                if process_info['cmdline'] and any(s in ' '.join(process_info['cmdline']).lower() 
                                                for s in ['powershell -nop -c', 'iex', 'nishang', 'mimikatz']):
                    suspicious.append({
                        "type": "suspicious_commandline",
                        "process": process_info['name'],
                        "pid": process_info['pid'],
                        "command_line": ' '.join(process_info['cmdline']) if process_info['cmdline'] else '',
                        "username": process_info['username'],
                        "executable": process_info['exe']
                    })
                
                # Detect processes with high CPU usage
                if proc.cpu_percent(interval=0.1) > 90:  # 90% CPU usage
                    suspicious.append({
                        "type": "high_cpu_usage",
                        "process": process_info['name'],
                        "pid": process_info['pid'],
                        "cpu_percent": proc.cpu_percent(interval=0.1),
                        "username": process_info['username']
                    })
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
                
        return suspicious
    
    def check_network_connections(self) -> List[Dict]:
        """Check for suspicious network connections"""
        suspicious = []
        
        for conn in psutil.net_connections(kind='inet'):
            try:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    # Example: Detect connections to known-bad IPs or unusual ports
                    if conn.raddr.port in [4444, 8080, 9001]:  # Common C2 ports
                        suspicious.append({
                            "type": "suspicious_connection",
                            "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                            "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                            "status": conn.status,
                            "pid": conn.pid,
                            "process": psutil.Process(conn.pid).name() if conn.pid else "unknown"
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return suspicious
    
    def run_detection_cycle(self):
        """Run one cycle of detection checks"""
        self.logger.info("Running EDR detection cycle")
        
        # Collect system information
        system_info = self.collect_system_info()
        
        # Run detection methods
        alerts = []
        alerts.extend(self.detect_suspicious_processes())
        alerts.extend(self.check_network_connections())
        
        # Add metadata to each alert
        for alert in alerts:
            alert.update({
                "agent_id": self.agent_id,
                "timestamp": datetime.utcnow().isoformat(),
                "hostname": self.hostname,
                "severity": "high"  # Default severity
            })
        
        return alerts
    
    def start(self):
        """Start the EDR agent"""
        if self.running:
            self.logger.warning("EDR agent is already running")
            return
            
        self.running = True
        self.logger.info(f"Starting EDR Agent (ID: {self.agent_id})")
        
        # Initial system baseline
        self.baseline = self.collect_system_info()
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop(self):
        """Stop the EDR agent"""
        self.logger.info("Stopping EDR Agent")
        self.running = False
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join(timeout=5)
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                alerts = self.run_detection_cycle()
                if alerts:
                    self._send_alerts(alerts)
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {str(e)}")
            
            # Wait for the next cycle
            time.sleep(self.check_interval)
    
    def _send_alerts(self, alerts: List[Dict]):
        """Send alerts to SIEM system (placeholder implementation)"""
        # TODO: Implement actual SIEM integration
        for alert in alerts:
            self.logger.warning(f"ALERT: {json.dumps(alert, indent=2)}")
        
        # Example of how to send to SIEM (commented out as it requires actual implementation)
        # try:
        #     response = requests.post(
        #         f"{self.siem_endpoint}/api/alerts",
        #         json={"alerts": alerts},
        #         headers={"Content-Type": "application/json"}
        #     )
        #     response.raise_for_status()
        # except Exception as e:
        #     self.logger.error(f"Failed to send alerts to SIEM: {str(e)}")


def create_edr_agent(siem_endpoint: str, check_interval: int = 60) -> EDRAgent:
    """Factory function to create and start an EDR agent"""
    agent = EDRAgent(siem_endpoint=siem_endpoint, check_interval=check_interval)
    agent.start()
    return agent
