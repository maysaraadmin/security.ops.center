import psutil
import platform
import socket
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.models.security_models import *
# DashboardMetrics is imported in the function signature to avoid circular imports

logger = logging.getLogger(__name__)

class DataCollector:
    def __init__(self, db_connection=None):
        self.db = db_connection
        self.executor = ThreadPoolExecutor(max_workers=5)
        self.last_collection_time = datetime.now()
        
    def collect_all_metrics(self) -> 'DashboardMetrics':
        from src.models.metrics import DashboardMetrics  # Local import to avoid circular imports
        """Collect metrics from all security components."""
        try:
            current_time = datetime.now()
            
            # Collect metrics in parallel
            with ThreadPoolExecutor() as executor:
                futures = {
                    'siem': executor.submit(self._collect_siem_metrics),
                    'edr': executor.submit(self._collect_edr_metrics),
                    'ndr': executor.submit(self._collect_ndr_metrics),
                    'dlp': executor.submit(self._collect_dlp_metrics),
                    'fim': executor.submit(self._collect_fim_metrics),
                    'hips': executor.submit(self._collect_hips_metrics),
                    'nips': executor.submit(self._collect_nips_metrics)
                }
                
                # Wait for all futures to complete
                results = {}
                for key, future in futures.items():
                    try:
                        results[key] = future.result()
                    except Exception as e:
                        logger.error(f"Error collecting {key} metrics: {e}")
                        results[key] = {}
            
            # Calculate time delta
            time_delta = current_time - self.last_collection_time
            self.last_collection_time = current_time
            
            return DashboardMetrics(
                siem_metrics=results['siem'],
                edr_metrics=results['edr'],
                ndr_metrics=results['ndr'],
                dlp_metrics=results['dlp'],
                fim_metrics=results['fim'],
                hips_metrics=results['hips'],
                nips_metrics=results['nips'],
                timestamp=current_time
            )
            
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}")
            # Return empty metrics on error
            return self._get_empty_metrics()
    
    def _get_empty_metrics(self) -> 'DashboardMetrics':
        """Return an empty metrics object."""
        from src.models.metrics import DashboardMetrics  # Local import to avoid circular imports
        empty = {}
        return DashboardMetrics(
            siem_metrics=empty.copy(),
            edr_metrics=empty.copy(),
            ndr_metrics=empty.copy(),
            dlp_metrics=empty.copy(),
            fim_metrics=empty.copy(),
            hips_metrics=empty.copy(),
            nips_metrics=empty.copy()
        )
    
    def _collect_siem_metrics(self) -> Dict[str, Any]:
        """Collect SIEM metrics."""
        try:
            # Get system info
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Get process count
            process_count = len(psutil.pids())
            
            # Get network stats
            net_io = psutil.net_io_counters()
            
            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'disk_percent': disk.percent,
                'process_count': process_count,
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv,
                'hostname': socket.gethostname(),
                'os': f"{platform.system()} {platform.release()}",
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error collecting SIEM metrics: {e}")
            return {}
    
    def _collect_edr_metrics(self) -> Dict[str, Any]:
        """Collect EDR metrics."""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
                try:
                    pinfo = proc.info
                    processes.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'user': pinfo['username'],
                        'cpu': pinfo['cpu_percent'],
                        'memory': pinfo['memory_percent']
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            return {
                'process_count': len(processes),
                'suspicious_processes': 0,  # Would be populated by actual EDR
                'active_threats': 0,  # Would be populated by actual EDR
                'processes': processes[:100],  # Limit to 100 processes
                'last_scan': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error collecting EDR metrics: {e}")
            return {}
    
    def _collect_ndr_metrics(self) -> Dict[str, Any]:
        """Collect NDR metrics."""
        try:
            # This would be populated by actual NDR solution
            return {
                'connections': [],
                'anomalies': [],
                'threats_detected': 0,
                'bandwidth_usage': 0,
                'last_scan': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error collecting NDR metrics: {e}")
            return {}
    
    def _collect_dlp_metrics(self) -> Dict[str, Any]:
        """Collect DLP metrics."""
        try:
            # This would be populated by actual DLP solution
            return {
                'policies': [],
                'violations': [],
                'violations_today': 0,
                'sensitive_data_detected': 0,
                'last_scan': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error collecting DLP metrics: {e}")
            return {}
    
    def _collect_fim_metrics(self) -> Dict[str, Any]:
        """Collect FIM metrics."""
        try:
            # This would be populated by actual FIM solution
            return {
                'monitored_files': 0,
                'changes_detected': 0,
                'critical_changes': 0,
                'last_scan': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error collecting FIM metrics: {e}")
            return {}
    
    def _collect_hips_metrics(self) -> Dict[str, Any]:
        """Collect HIPS metrics."""
        try:
            # This would be populated by actual HIPS solution
            return {
                'active_rules': 0,
                'prevented_attacks': 0,
                'suspicious_activities': 0,
                'last_scan': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error collecting HIPS metrics: {e}")
            return {}
    
    def _collect_nips_metrics(self) -> Dict[str, Any]:
        """Collect NIPS metrics."""
        try:
            # This would be populated by actual NIPS solution
            return {
                'blocked_ips': [],
                'prevented_attacks': 0,
                'active_rules': 0,
                'last_scan': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error collecting NIPS metrics: {e}")
            return {}
    
    def close(self):
        """Clean up resources."""
        self.executor.shutdown(wait=True)
