import psutil
import os
import sys
import logging
import time
from typing import Dict, List, Optional, Set, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('service_check.log')
    ]
)
logger = logging.getLogger('siem.service_check')

class ServiceChecker:
    def __init__(self):
        # Expected SIEM processes
        self.expected_processes = [
            'python.exe:main.py',  # Main SIEM process
            'python.exe:api/metrics_api.py',  # Metrics API
            'python.exe:core/log_collector.py',  # Log collector
            'python.exe:core/correlation_engine.py',  # Correlation engine
        ]
        
        # Expected ports
        self.expected_ports = [
            (5000, 'REST API'),
            (9090, 'Metrics'),
            (514, 'Syslog'),
        ]
        
        # Expected directories
        self.expected_dirs = [
            'logs',
            'config',
            'core',
            'models',
            'views',
            'integrations',
        ]
    
    def check_processes(self) -> Dict[str, bool]:
        """Check if expected processes are running."""
        logger.info("Checking running processes...")
        
        running = {}
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = ' '.join(proc.info['cmdline'] or [])
                for expected in self.expected_processes:
                    if expected in cmdline:
                        running[expected] = True
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        # Check for missing processes
        results = {}
        for proc in self.expected_processes:
            results[proc] = running.get(proc, False)
            
        return results
    
    def check_ports(self) -> Dict[Tuple[int, str], bool]:
        """Check if expected ports are in use."""
        logger.info("Checking network ports...")
        
        # Get all listening ports
        listening_ports = set()
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN' and conn.laddr:
                listening_ports.add(conn.laddr.port)
        
        # Check expected ports
        results = {}
        for port, name in self.expected_ports:
            results[(port, name)] = port in listening_ports
            
        return results
    
    def check_directories(self) -> Dict[str, bool]:
        """Check if expected directories exist and are accessible."""
        logger.info("Checking directories...")
        
        results = {}
        for dir_name in self.expected_dirs:
            path = os.path.join(os.getcwd(), dir_name)
            exists = os.path.exists(path) and os.path.isdir(path)
            writable = os.access(path, os.W_OK) if exists else False
            results[dir_name] = exists and writable
            
        return results
    
    def check_disk_space(self, min_gb: float = 1.0) -> Dict[str, any]:
        """Check available disk space."""
        logger.info("Checking disk space...")
        
        results = {}
        for part in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(part.mountpoint)
                results[part.mountpoint] = {
                    'total_gb': round(usage.total / (1024**3), 2),
                    'free_gb': round(usage.free / (1024**3), 2),
                    'used_percent': usage.percent,
                    'ok': (usage.free / (1024**3)) >= min_gb
                }
            except Exception as e:
                logger.warning(f"Could not check disk space for {part.mountpoint}: {e}")
                
        return results
    
    def check_system_resources(self) -> Dict[str, any]:
        """Check system resource usage."""
        logger.info("Checking system resources...")
        
        return {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'swap_percent': psutil.swap_memory().percent if hasattr(psutil, 'swap_memory') else 0,
            'load_avg': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else [0, 0, 0]
        }
    
    def generate_report(self, results: Dict[str, any]) -> str:
        """Generate a formatted report of the check results."""
        report = []
        report.append("\n=== SIEM System Health Check ===\n")
        
        # Processes
        report.append("## Running Processes")
        processes = results.get('processes', {})
        for proc, running in processes.items():
            status = "[RUNNING]" if running else "[STOPPED]"
            report.append(f"{status} {proc}")
        
        # Ports
        report.append("\n## Network Ports")
        ports = results.get('ports', {})
        for (port, name), listening in ports.items():
            status = "[LISTENING]" if listening else "[CLOSED]  "
            report.append(f"{status} {name} (port {port})")
        
        # Directories
        report.append("\n## Directory Access")
        dirs = results.get('directories', {})
        for dir_name, accessible in dirs.items():
            status = "[OK]" if accessible else "[ERROR]"
            report.append(f"{status} {dir_name}")
        
        # Disk Space
        report.append("\n## Disk Space")
        disks = results.get('disk_space', {})
        for mount, info in disks.items():
            status = "[OK]" if info.get('ok', False) else "[LOW]"
            report.append(
                f"{status} {mount}: {info['free_gb']:.1f}GB free "
                f"({info['used_percent']}% used, {info['total_gb']:.1f}GB total)"
            )
        
        # System Resources
        report.append("\n## System Resources")
        res = results.get('system_resources', {})
        report.append(f"CPU Usage: {res.get('cpu_percent', 0):.1f}%")
        report.append(f"Memory Usage: {res.get('memory_percent', 0):.1f}%")
        if 'load_avg' in res:
            report.append(
                f"Load Average: {res['load_avg'][0]:.2f}, "
                f"{res['load_avg'][1]:.2f}, {res['load_avg'][2]:.2f}"
            )
        
        # Issues summary
        issues = []
        if not all(processes.values()):
            issues.append("- Some required processes are not running")
        if not all(ports.values()):
            issues.append("- Some required ports are not listening")
        if not all(dirs.values()):
            issues.append("- Some directories are not accessible")
        if not all(info.get('ok', False) for info in disks.values()):
            issues.append("- Low disk space on one or more partitions")
        
        if issues:
            report.append("\n## Issues Found")
            report.extend(issues)
        else:
            report.append("\n## No critical issues found")
        
        return "\n".join(report)

def main():
    """Run system health checks and print report."""
    checker = ServiceChecker()
    
    results = {
        'processes': checker.check_processes(),
        'ports': checker.check_ports(),
        'directories': checker.check_directories(),
        'disk_space': checker.check_disk_space(),
        'system_resources': checker.check_system_resources()
    }
    
    report = checker.generate_report(results)
    print(report)
    
    # Write report to file
    with open('siem_health_check.txt', 'w') as f:
        f.write(report)
    
    # Return non-zero exit code if there are issues
    if any(not all(section.values()) for section in [
        results['processes'],
        results['ports'],
        results['directories']
    ]):
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
