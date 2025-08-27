"""
Health check system for the SIEM.
"""

import time
import socket
import psutil
import threading
import logging
from typing import Dict, List, Optional, Any
from enum import Enum, auto
from dataclasses import dataclass, field
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import metrics for health checks
from .metrics import metrics_collector

class HealthStatus(Enum):
    """Health status of a component or service."""
    HEALTHY = auto()
    DEGRADED = auto()
    UNHEALTHY = auto()
    UNKNOWN = auto()

@dataclass
class HealthCheckResult:
    """Result of a health check."""
    component: str
    status: HealthStatus
    message: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the result to a dictionary."""
        return {
            'component': self.component,
            'status': self.status.name,
            'message': self.message,
            'timestamp': self.timestamp.isoformat(),
            'details': self.details
        }

class HealthCheck:
    """Base class for health checks."""
    
    def __init__(self, name: str, component: str, 
                 timeout: float = 5.0, 
                 interval: float = 60.0):
        """Initialize the health check."""
        self.name = name
        self.component = component
        self.timeout = timeout
        self.interval = interval
        self._last_run: Optional[datetime] = None
        self._last_result: Optional[HealthCheckResult] = None
        self.logger = logging.getLogger(f'siem.health.{self.component}.{self.name}')
    
    def check(self) -> HealthCheckResult:
        """Run the health check and return the result."""
        start_time = time.time()
        
        try:
            result = self._check()
            result.timestamp = datetime.now(timezone.utc)
            
            # Record metrics
            status_value = 1.0 if result.status == HealthStatus.HEALTHY else 0.0
            metrics_collector.set_gauge(
                f'health.check.{self.component}.{self.name}', 
                status_value,
                {'component': self.component, 'check': self.name}
            )
            
            self.logger.debug(
                f"Health check '{self.name}' for component '{self.component}' "
                f"completed in {(time.time() - start_time):.3f}s: {result.status.name}"
            )
            
            return result
            
        except Exception as e:
            self.logger.error(
                f"Health check '{self.name}' for component '{self.component}' "
                f"failed after {(time.time() - start_time):.3f}s: {e}", 
                exc_info=True
            )
            
            return HealthCheckResult(
                component=self.component,
                status=HealthStatus.UNHEALTHY,
                message=f"Check failed: {str(e)}",
                details={
                    'error': str(e),
                    'check_duration': time.time() - start_time
                }
            )
        finally:
            self._last_run = datetime.now(timezone.utc)
    
    def _check(self) -> HealthCheckResult:
        """Override this method to implement the actual health check logic."""
        raise NotImplementedError("Subclasses must implement _check()")

# Implementation of specific health checks
class DiskSpaceCheck(HealthCheck):
    """Check available disk space."""
    
    def __init__(self, 
                 path: str = "/", 
                 warning_threshold: float = 20.0,  # 20% free
                 critical_threshold: float = 5.0,   # 5% free
                 **kwargs):
        """Initialize the disk space check."""
        super().__init__(f"disk_space_{path.replace('/', '_')}", "system", **kwargs)
        self.path = path
        self.warning_threshold = warning_threshold
        self.critical_threshold = critical_threshold
    
    def _check(self) -> HealthCheckResult:
        """Check disk space."""
        usage = psutil.disk_usage(self.path)
        free_percent = (usage.free / usage.total) * 100
        
        if free_percent < self.critical_threshold:
            status = HealthStatus.UNHEALTHY
            message = f"Critical: Only {free_percent:.1f}% free space on {self.path}"
        elif free_percent < self.warning_threshold:
            status = HealthStatus.DEGRADED
            message = f"Warning: {free_percent:.1f}% free space on {self.path}"
        else:
            status = HealthStatus.HEALTHY
            message = f"Sufficient disk space on {self.path} ({free_percent:.1f}% free)"
        
        return HealthCheckResult(
            component=self.component,
            status=status,
            message=message,
            details={
                'path': self.path,
                'total_gb': usage.total / (1024**3),
                'used_gb': usage.used / (1024**3),
                'free_gb': usage.free / (1024**3),
                'free_percent': free_percent,
                'warning_threshold': self.warning_threshold,
                'critical_threshold': self.critical_threshold
            }
        )

class MemoryCheck(HealthCheck):
    """Check system memory usage."""
    
    def __init__(self, 
                 warning_threshold: float = 80.0,  # 80% used
                 critical_threshold: float = 90.0, # 90% used
                 **kwargs):
        """Initialize the memory check."""
        super().__init__("memory_usage", "system", **kwargs)
        self.warning_threshold = warning_threshold
        self.critical_threshold = critical_threshold
    
    def _check(self) -> HealthCheckResult:
        """Check memory usage."""
        memory = psutil.virtual_memory()
        used_percent = memory.percent
        
        if used_percent > self.critical_threshold:
            status = HealthStatus.UNHEALTHY
            message = f"Critical: Memory usage at {used_percent:.1f}%"
        elif used_percent > self.warning_threshold:
            status = HealthStatus.DEGRADED
            message = f"Warning: Memory usage at {used_percent:.1f}%"
        else:
            status = HealthStatus.HEALTHY
            message = f"Memory usage at {used_percent:.1f}%"
        
        return HealthCheckResult(
            component=self.component,
            status=status,
            message=message,
            details={
                'total_gb': memory.total / (1024**3),
                'available_gb': memory.available / (1024**3),
                'used_gb': memory.used / (1024**3),
                'used_percent': used_percent,
                'warning_threshold': self.warning_threshold,
                'critical_threshold': self.critical_threshold
            }
        )

class CpuCheck(HealthCheck):
    """Check CPU usage."""
    
    def __init__(self, 
                 warning_threshold: float = 80.0,  # 80% used
                 critical_threshold: float = 90.0, # 90% used
                 **kwargs):
        """Initialize the CPU check."""
        super().__init__("cpu_usage", "system", **kwargs)
        self.warning_threshold = warning_threshold
        self.critical_threshold = critical_threshold
    
    def _check(self) -> HealthCheckResult:
        """Check CPU usage."""
        cpu_percent = psutil.cpu_percent(interval=1.0)
        
        if cpu_percent > self.critical_threshold:
            status = HealthStatus.UNHEALTHY
            message = f"Critical: CPU usage at {cpu_percent:.1f}%"
        elif cpu_percent > self.warning_threshold:
            status = HealthStatus.DEGRADED
            message = f"Warning: CPU usage at {cpu_percent:.1f}%"
        else:
            status = HealthStatus.HEALTHY
            message = f"CPU usage at {cpu_percent:.1f}%"
        
        return HealthCheckResult(
            component=self.component,
            status=status,
            message=message,
            details={
                'cpu_percent': cpu_percent,
                'cpu_count': psutil.cpu_count(),
                'warning_threshold': self.warning_threshold,
                'critical_threshold': self.critical_threshold
            }
        )

class HealthCheckRunner:
    """Runs health checks and reports results."""
    
    def __init__(self, max_workers: int = 10):
        """Initialize the health check runner."""
        self.checks: Dict[str, HealthCheck] = {}
        self.max_workers = max_workers
        self.lock = threading.Lock()
        self.logger = logging.getLogger('siem.health.runner')
        self._stop_event = threading.Event()
        self._thread = None
        self._interval = 60.0
    
    def add_check(self, check: HealthCheck) -> None:
        """Add a health check."""
        with self.lock:
            check_id = f"{check.component}.{check.name}"
            self.checks[check_id] = check
            self.logger.info(f"Added health check: {check_id}")
    
    def run_checks(self) -> Dict[str, HealthCheckResult]:
        """Run all health checks in parallel."""
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_check = {
                executor.submit(self._run_check, check_id, check): check_id
                for check_id, check in self.checks.items()
            }
            
            for future in as_completed(future_to_check):
                check_id = future_to_check[future]
                try:
                    result = future.result()
                    results[check_id] = result
                except Exception as e:
                    self.logger.error(f"Error running health check {check_id}: {e}", exc_info=True)
                    results[check_id] = HealthCheckResult(
                        component=check_id.split('.', 1)[0],
                        status=HealthStatus.UNHEALTHY,
                        message=f"Check failed: {str(e)}",
                        details={'error': str(e)}
                    )
        
        return results
    
    def _run_check(self, check_id: str, check: HealthCheck) -> HealthCheckResult:
        """Run a single health check and return the result."""
        try:
            return check.check()
        except Exception as e:
            self.logger.error(f"Unhandled exception in health check {check_id}: {e}", exc_info=True)
            return HealthCheckResult(
                component=check.component,
                status=HealthStatus.UNHEALTHY,
                message=f"Unhandled exception: {str(e)}",
                details={
                    'error': str(e),
                    'check_id': check_id
                }
            )
    
    def start(self, interval: float = 60.0) -> None:
        """Start the health check runner in a background thread."""
        if self._thread is not None and self._thread.is_alive():
            self.logger.warning("Health check runner is already running")
            return
            
        self._interval = interval
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name='health_check_runner',
            daemon=True
        )
        self._thread.start()
        self.logger.info(f"Started health check runner with {len(self.checks)} checks (interval: {interval}s)")
    
    def stop(self) -> None:
        """Stop the health check runner."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
        self.logger.info("Stopped health check runner")
    
    def _run_loop(self) -> None:
        """Run health checks in a loop."""
        while not self._stop_event.is_set():
            start_time = time.time()
            
            try:
                results = self.run_checks()
                
                # Log summary
                status_counts = {status: 0 for status in HealthStatus}
                for result in results.values():
                    status_counts[result.status] = status_counts.get(result.status, 0) + 1
                
                self.logger.info(
                    f"Health check summary: {', '.join(f'{v} {k.name}' for k, v in status_counts.items())}"
                )
                
                # Log any unhealthy checks
                for check_id, result in results.items():
                    if result.status != HealthStatus.HEALTHY:
                        self.logger.warning(
                            f"Unhealthy check: {check_id} - {result.message} "
                            f"(status: {result.status.name})"
                        )
                
                # Update metrics
                metrics_collector.set_gauge(
                    'health.checks.total', 
                    len(results),
                    {'status': 'all'}
                )
                
                for status in HealthStatus:
                    metrics_collector.set_gauge(
                        'health.checks.total', 
                        status_counts.get(status, 0),
                        {'status': status.name.lower()}
                    )
                
            except Exception as e:
                self.logger.error(f"Error in health check loop: {e}", exc_info=True)
            
            # Sleep for the remaining interval
            elapsed = time.time() - start_time
            sleep_time = max(0, self._interval - elapsed)
            
            if sleep_time > 0:
                self._stop_event.wait(sleep_time)

# Global health check runner instance
health_check_runner = HealthCheckRunner()

def setup_default_checks() -> None:
    """Set up default health checks for the SIEM system."""
    # System resource checks
    health_check_runner.add_check(DiskSpaceCheck(
        path="/",
        warning_threshold=20.0,
        critical_threshold=5.0,
        interval=300.0  # 5 minutes
    ))
    
    health_check_runner.add_check(MemoryCheck(
        warning_threshold=80.0,
        critical_threshold=90.0,
        interval=60.0  # 1 minute
    ))
    
    health_check_runner.add_check(CpuCheck(
        warning_threshold=80.0,
        critical_threshold=90.0,
        interval=60.0  # 1 minute
    ))
    
    # Start the health check runner
    health_check_runner.start(interval=60.0)

# Example usage
if __name__ == "__main__":
    import logging
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Set up default checks
    setup_default_checks()
    
    # Run for a while
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping health check runner...")
        health_check_runner.stop()
