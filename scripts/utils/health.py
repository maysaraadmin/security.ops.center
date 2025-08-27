"""
SIEM Health Check Module

This module provides health check functionality for the SIEM system.
"""

import time
import threading
import socket
import psutil
import logging
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from datetime import datetime, timedelta

class HealthStatus(Enum):
    """Health status enumeration."""
    HEALTHY = auto()
    DEGRADED = auto()
    UNHEALTHY = auto()
    UNKNOWN = auto()

@dataclass
class HealthCheckResult:
    """Result of a health check."""
    status: HealthStatus
    message: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    details: Dict[str, Any] = field(default_factory=dict)

class HealthChecker:
    """Health checker for SIEM components."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the health checker.
        
        Args:
            config: Health check configuration.
        """
        self.config = config
        self.logger = logging.getLogger('siem.health')
        self.checks: Dict[str, Callable[[], HealthCheckResult]] = {}
        self.results: Dict[str, HealthCheckResult] = {}
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        
        # Register default health checks
        self.register_check('system', self._check_system_health)
        self.register_check('disk', self._check_disk_health)
        self.register_check('memory', self._check_memory_health)
        self.register_check('network', self._check_network_health)
    
    def register_check(self, name: str, check_func: Callable[[], HealthCheckResult]) -> None:
        """Register a health check function.
        
        Args:
            name: Name of the health check.
            check_func: Function that performs the health check.
        """
        self.checks[name] = check_func
    
    def start(self) -> None:
        """Start the health check background thread."""
        if self._thread and self._thread.is_alive():
            self.logger.warning("Health checker is already running")
            return
            
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_checks,
            name="HealthChecker",
            daemon=True
        )
        self._thread.start()
        self.logger.info("Health checker started")
    
    def stop(self) -> None:
        """Stop the health check background thread."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        self.logger.info("Health checker stopped")
    
    def _run_checks(self) -> None:
        """Run health checks in a loop."""
        check_interval = self.config.get('check_interval', 60)
        
        while not self._stop_event.is_set():
            try:
                self.run_checks()
            except Exception as e:
                self.logger.error(f"Error running health checks: {e}", exc_info=True)
            
            # Wait for the next check interval or until stopped
            self._stop_event.wait(check_interval)
    
    def run_checks(self) -> Dict[str, HealthCheckResult]:
        """Run all registered health checks.
        
        Returns:
            Dictionary of check results.
        """
        results = {}
        for name, check_func in self.checks.items():
            try:
                result = check_func()
                results[name] = result
                
                # Log status changes or errors
                if name in self.results and self.results[name].status != result.status:
                    self.logger.warning(
                        f"Health status changed for {name}: "
                        f"{self.results[name].status.name} -> {result.status.name}"
                    )
                
                if result.status != HealthStatus.HEALTHY:
                    self.logger.warning(
                        f"Health check '{name}' is {result.status.name}: {result.message}"
                    )
                    
            except Exception as e:
                self.logger.error(f"Error running health check '{name}': {e}", exc_info=True)
                results[name] = HealthCheckResult(
                    status=HealthStatus.UNHEALTHY,
                    message=f"Error: {str(e)}",
                    details={"error": str(e)}
                )
        
        self.results = results
        return results
    
    def get_status(self) -> HealthStatus:
        """Get the overall system health status.
        
        Returns:
            The most severe status from all health checks.
        """
        if not self.results:
            return HealthStatus.UNKNOWN
            
        statuses = [result.status for result in self.results.values()]
        
        if HealthStatus.UNHEALTHY in statuses:
            return HealthStatus.UNHEALTHY
        elif HealthStatus.DEGRADED in statuses:
            return HealthStatus.DEGRADED
        elif all(s == HealthStatus.HEALTHY for s in statuses):
            return HealthStatus.HEALTHY
        else:
            return HealthStatus.UNKNOWN
    
    def _check_system_health(self) -> HealthCheckResult:
        """Check system-level health metrics."""
        try:
            # Check CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_ok = cpu_percent < 90  # 90% threshold
            
            # Check load average (Unix-like systems)
            load_avg = psutil.getloadavg()[0] if hasattr(psutil, 'getloadavg') else 0
            load_ok = load_avg < (psutil.cpu_count() * 0.75)
            
            status = HealthStatus.HEALTHY
            messages = []
            
            if not cpu_ok:
                status = HealthStatus.DEGRADED
                messages.append(f"High CPU usage: {cpu_percent:.1f}%")
                
            if not load_ok:
                status = max(status, HealthStatus.DEGRADED)
                messages.append(f"High system load: {load_avg:.2f}")
            
            return HealthCheckResult(
                status=status,
                message="; ".join(messages) or "System is healthy",
                details={
                    "cpu_percent": cpu_percent,
                    "load_avg": load_avg,
                    "cpu_count": psutil.cpu_count(),
                }
            )
            
        except Exception as e:
            return HealthCheckResult(
                status=HealthStatus.UNHEALTHY,
                message=f"System health check failed: {str(e)}",
                details={"error": str(e)}
            )
    
    def _check_disk_health(self) -> HealthCheckResult:
        """Check disk usage and health."""
        try:
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            disk_ok = disk_percent < 90  # 90% threshold
            
            return HealthCheckResult(
                status=HealthStatus.HEALTHY if disk_ok else HealthStatus.DEGRADED,
                message=f"Disk usage: {disk_percent:.1f}%" if disk_ok else f"High disk usage: {disk_percent:.1f}%",
                details={
                    "total_gb": disk.total / (1024**3),
                    "used_gb": disk.used / (1024**3),
                    "free_gb": disk.free / (1024**3),
                    "percent_used": disk_percent,
                }
            )
            
        except Exception as e:
            return HealthCheckResult(
                status=HealthStatus.UNHEALTHY,
                message=f"Disk health check failed: {str(e)}",
                details={"error": str(e)}
            )
    
    def _check_memory_health(self) -> HealthCheckResult:
        """Check memory usage."""
        try:
            mem = psutil.virtual_memory()
            mem_percent = mem.percent
            mem_ok = mem_percent < 90  # 90% threshold
            
            return HealthCheckResult(
                status=HealthStatus.HEALTHY if mem_ok else HealthStatus.DEGRADED,
                message=f"Memory usage: {mem_percent:.1f}%" if mem_ok else f"High memory usage: {mem_percent:.1f}%",
                details={
                    "total_gb": mem.total / (1024**3),
                    "available_gb": mem.available / (1024**3),
                    "used_gb": mem.used / (1024**3),
                    "percent_used": mem_percent,
                }
            )
            
        except Exception as e:
            return HealthCheckResult(
                status=HealthStatus.UNHEALTHY,
                message=f"Memory health check failed: {str(e)}",
                details={"error": str(e)}
            )
    
    def _check_network_health(self) -> HealthCheckResult:
        """Check network connectivity."""
        try:
            # Try to resolve a well-known host
            socket.gethostbyname("google.com")
            
            # Check if we can bind to a socket (basic network stack check)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('', 0))
            
            return HealthCheckResult(
                status=HealthStatus.HEALTHY,
                message="Network connectivity is good",
                details={
                    "hostname": socket.gethostname(),
                    "ip_address": socket.gethostbyname(socket.gethostname()),
                }
            )
            
        except Exception as e:
            return HealthCheckResult(
                status=HealthStatus.UNHEALTHY,
                message=f"Network connectivity check failed: {str(e)}",
                details={"error": str(e)}
            )
