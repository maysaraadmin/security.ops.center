"""
Metrics collection and monitoring for the SIEM system.
"""

import time
import psutil
import platform
import socket
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from collections import defaultdict, deque
import threading
import logging

@dataclass
class Metric:
    """Base class for all metrics."""
    name: str
    value: Any
    timestamp: float = field(default_factory=lambda: time.time())
    tags: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the metric to a dictionary."""
        return {
            'name': self.name,
            'value': self.value,
            'timestamp': self.timestamp,
            'tags': self.tags
        }

@dataclass
class Counter(Metric):
    """A counter metric that can only increase or be reset to zero."""
    pass

@dataclass
class Gauge(Metric):
    """A gauge metric that can go up and down."""
    pass

@dataclass
class Histogram(Metric):
    """A histogram metric that samples observations."""
    count: int = 0
    sum: float = 0.0
    buckets: Dict[float, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the histogram to a dictionary."""
        data = super().to_dict()
        data.update({
            'count': self.count,
            'sum': self.sum,
            'buckets': self.buckets
        })
        return data

class MetricsCollector:
    """Collects and manages metrics for the SIEM system."""
    
    def __init__(self, prefix: str = 'siem'):
        """Initialize the metrics collector.
        
        Args:
            prefix: Prefix for all metric names
        """
        self.prefix = prefix
        self.metrics: Dict[str, Metric] = {}
        self.lock = threading.RLock()
        self.logger = logging.getLogger('siem.metrics')
        
        # Register default metrics
        self._register_default_metrics()
    
    def _register_default_metrics(self) -> None:
        """Register default system metrics."""
        # System metrics
        self.register_gauge('system.cpu.percent', 0.0, {'host': socket.gethostname()})
        self.register_gauge('system.memory.percent', 0.0, {'host': socket.gethostname()})
        self.register_gauge('system.disk.percent', 0.0, {'host': socket.gethostname()})
        self.register_gauge('system.process.memory.rss', 0, {'host': socket.gethostname()})
        self.register_gauge('system.process.cpu.percent', 0.0, {'host': socket.gethostname()})
        
        # Application metrics
        self.register_counter('siem.events.processed', 0)
        self.register_counter('siem.events.dropped', 0)
        self.register_histogram('siem.processing.time', buckets=[0.1, 0.5, 1.0, 5.0, 10.0])
    
    def register_counter(self, name: str, initial_value: int = 0, tags: Optional[Dict[str, str]] = None) -> None:
        """Register a new counter metric.
        
        Args:
            name: Name of the metric
            initial_value: Initial value of the counter
            tags: Tags for the metric
        """
        with self.lock:
            full_name = f"{self.prefix}.{name}" if not name.startswith(self.prefix) else name
            if full_name not in self.metrics:
                self.metrics[full_name] = Counter(
                    name=full_name,
                    value=initial_value,
                    tags=tags or {}
                )
    
    def register_gauge(self, name: str, initial_value: float, tags: Optional[Dict[str, str]] = None) -> None:
        """Register a new gauge metric.
        
        Args:
            name: Name of the metric
            initial_value: Initial value of the gauge
            tags: Tags for the metric
        """
        with self.lock:
            full_name = f"{self.prefix}.{name}" if not name.startswith(self.prefix) else name
            if full_name not in self.metrics:
                self.metrics[full_name] = Gauge(
                    name=full_name,
                    value=float(initial_value),
                    tags=tags or {}
                )
    
    def register_histogram(self, name: str, buckets: Optional[List[float]] = None, 
                         tags: Optional[Dict[str, str]] = None) -> None:
        """Register a new histogram metric.
        
        Args:
            name: Name of the metric
            buckets: Bucket boundaries for the histogram
            tags: Tags for the metric
        """
        with self.lock:
            full_name = f"{self.prefix}.{name}" if not name.startswith(self.prefix) else name
            if full_name not in self.metrics:
                self.metrics[full_name] = Histogram(
                    name=full_name,
                    value=0.0,
                    tags=tags or {},
                    buckets={str(b): 0 for b in (buckets or [])}
                )
    
    def increment(self, name: str, value: int = 1, tags: Optional[Dict[str, str]] = None) -> None:
        """Increment a counter metric.
        
        Args:
            name: Name of the metric
            value: Value to increment by
            tags: Tags to identify the metric
        """
        with self.lock:
            full_name = f"{self.prefix}.{name}" if not name.startswith(self.prefix) else name
            if full_name in self.metrics and isinstance(self.metrics[full_name], Counter):
                self.metrics[full_name].value += value
                self.metrics[full_name].timestamp = time.time()
            else:
                self.logger.warning(f"Counter {full_name} not found")
    
    def set_gauge(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        """Set the value of a gauge metric.
        
        Args:
            name: Name of the metric
            value: New value of the gauge
            tags: Tags to identify the metric
        """
        with self.lock:
            full_name = f"{self.prefix}.{name}" if not name.startswith(self.prefix) else name
            if full_name in self.metrics and isinstance(self.metrics[full_name], Gauge):
                self.metrics[full_name].value = float(value)
                self.metrics[full_name].timestamp = time.time()
            else:
                self.logger.warning(f"Gauge {full_name} not found")
    
    def observe_histogram(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        """Observe a value in a histogram.
        
        Args:
            name: Name of the metric
            value: Value to observe
            tags: Tags to identify the metric
        """
        with self.lock:
            full_name = f"{self.prefix}.{name}" if not name.startswith(self.prefix) else name
            if full_name in self.metrics and isinstance(self.metrics[full_name], Histogram):
                histogram = self.metrics[full_name]
                histogram.value = float(value)
                histogram.count += 1
                histogram.sum += value
                
                # Update buckets
                for bucket in histogram.buckets:
                    if value <= float(bucket):
                        histogram.buckets[bucket] += 1
                
                histogram.timestamp = time.time()
            else:
                self.logger.warning(f"Histogram {full_name} not found")
    
    def get_metric(self, name: str) -> Optional[Metric]:
        """Get a metric by name.
        
        Args:
            name: Name of the metric
            
        Returns:
            The metric or None if not found
        """
        full_name = f"{self.prefix}.{name}" if not name.startswith(self.prefix) else name
        return self.metrics.get(full_name)
    
    def get_metrics(self) -> Dict[str, Metric]:
        """Get all metrics.
        
        Returns:
            Dictionary of all metrics
        """
        with self.lock:
            return self.metrics.copy()
    
    def collect_system_metrics(self) -> None:
        """Collect system metrics."""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self.set_gauge('system.cpu.percent', cpu_percent)
            
            # Memory usage
            memory = psutil.virtual_memory()
            self.set_gauge('system.memory.percent', memory.percent)
            
            # Disk usage
            disk = psutil.disk_usage('/')
            self.set_gauge('system.disk.percent', disk.percent)
            
            # Process metrics
            process = psutil.Process()
            with process.oneshot():
                self.set_gauge('system.process.memory.rss', process.memory_info().rss)
                self.set_gauge('system.process.cpu.percent', process.cpu_percent(interval=0.1))
                
        except Exception as e:
            self.logger.error(f"Error collecting system metrics: {e}")

class MetricsExporter:
    """Base class for metrics exporters."""
    
    def export(self, metrics: Dict[str, Metric]) -> bool:
        """Export metrics.
        
        Args:
            metrics: Dictionary of metrics to export
            
        Returns:
            True if the export was successful, False otherwise
        """
        raise NotImplementedError()

class ConsoleExporter(MetricsExporter):
    """Exports metrics to the console."""
    
    def __init__(self, format: str = 'text'):
        """Initialize the console exporter.
        
        Args:
            format: Output format ('text' or 'json')
        """
        self.format = format
        self.logger = logging.getLogger('siem.metrics.console_exporter')
    
    def export(self, metrics: Dict[str, Metric]) -> bool:
        """Export metrics to the console."""
        try:
            if self.format == 'json':
                import json
                print(json.dumps({
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'metrics': {k: v.to_dict() for k, v in metrics.items()}
                }, indent=2))
            else:
                print(f"\n=== Metrics at {datetime.now(timezone.utc).isoformat()} ===")
                for name, metric in metrics.items():
                    if isinstance(metric, Histogram):
                        print(f"{name}: {metric.value} (count={metric.count}, sum={metric.sum}, buckets={metric.buckets})")
                    else:
                        print(f"{name}: {metric.value}")
                print("=" * 60)
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting metrics to console: {e}")
            return False

class PrometheusExporter(MetricsExporter):
    """Exports metrics in Prometheus format."""
    
    def __init__(self, port: int = 9090):
        """Initialize the Prometheus exporter.
        
        Args:
            port: Port to expose the metrics on
        """
        self.port = port
        self.server = None
        self.logger = logging.getLogger('siem.metrics.prometheus_exporter')
    
    def start(self) -> bool:
        """Start the Prometheus metrics server."""
        try:
            from prometheus_client import start_http_server, Gauge as PromGauge, Counter as PromCounter, Histogram as PromHistogram
            
            # Start the Prometheus metrics server
            start_http_server(self.port)
            self.logger.info(f"Prometheus metrics server started on port {self.port}")
            return True
            
        except ImportError:
            self.logger.error("Prometheus client not installed. Install with: pip install prometheus-client")
            return False
        except Exception as e:
            self.logger.error(f"Error starting Prometheus metrics server: {e}")
            return False
    
    def export(self, metrics: Dict[str, Metric]) -> bool:
        """Export metrics in Prometheus format."""
        try:
            from prometheus_client import Gauge as PromGauge, Counter as PromCounter, Histogram as PromHistogram
            
            # Create or update Prometheus metrics
            for name, metric in metrics.items():
                # Convert metric name to Prometheus format
                prom_name = name.replace('.', '_')
                
                if isinstance(metric, Counter):
                    # Create or get the counter
                    counter = getattr(self, f'_{prom_name}_counter', None)
                    if counter is None:
                        counter = PromCounter(
                            prom_name,
                            f'Counter for {name}',
                            list(metric.tags.keys()) or ['_']
                        )
                        setattr(self, f'_{prom_name}_counter', counter)
                    
                    # Update the counter
                    if metric.tags:
                        counter.labels(**metric.tags).inc(metric.value)
                    else:
                        counter.inc(metric.value)
                        
                elif isinstance(metric, Gauge):
                    # Create or get the gauge
                    gauge = getattr(self, f'_{prom_name}_gauge', None)
                    if gauge is None:
                        gauge = PromGauge(
                            prom_name,
                            f'Gauge for {name}',
                            list(metric.tags.keys()) or ['_']
                        )
                        setattr(self, f'_{prom_name}_gauge', gauge)
                    
                    # Update the gauge
                    if metric.tags:
                        gauge.labels(**metric.tags).set(metric.value)
                    else:
                        gauge.set(metric.value)
                        
                elif isinstance(metric, Histogram):
                    # Create or get the histogram
                    histogram = getattr(self, f'_{prom_name}_histogram', None)
                    if histogram is None:
                        histogram = PromHistogram(
                            prom_name,
                            f'Histogram for {name}',
                            list(metric.tags.keys()) or ['_'],
                            buckets=list(metric.buckets.keys()) or [0.1, 0.5, 1.0, 5.0, 10.0]
                        )
                        setattr(self, f'_{prom_name}_histogram', histogram)
                    
                    # Update the histogram
                    if metric.tags:
                        histogram.labels(**metric.tags).observe(metric.value)
                    else:
                        histogram.observe(metric.value)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting metrics to Prometheus: {e}")
            return False

class MetricsManager:
    """Manages metrics collection and export."""
    
    def __init__(self, collector: MetricsCollector, exporters: Optional[List[MetricsExporter]] = None):
        """Initialize the metrics manager.
        
        Args:
            collector: Metrics collector instance
            exporters: List of metrics exporters
        """
        self.collector = collector
        self.exporters = exporters or []
        self.logger = logging.getLogger('siem.metrics.manager')
        self._stop_event = threading.Event()
        self._export_thread = None
        
    def add_exporter(self, exporter: MetricsExporter) -> None:
        """Add a metrics exporter."""
        self.exporters.append(exporter)
    
    def start(self, interval: float = 60.0) -> None:
        """Start the metrics collection and export loop.
        
        Args:
            interval: Export interval in seconds
        """
        if self._export_thread is not None and self._export_thread.is_alive():
            self.logger.warning("Metrics export is already running")
            return
            
        self._stop_event.clear()
        self._export_thread = threading.Thread(
            target=self._export_loop,
            args=(interval,),
            name='metrics_export',
            daemon=True
        )
        self._export_thread.start()
        self.logger.info(f"Started metrics export with {len(self.exporters)} exporters")
    
    def stop(self) -> None:
        """Stop the metrics collection and export loop."""
        self._stop_event.set()
        if self._export_thread is not None:
            self._export_thread.join(timeout=5.0)
        self.logger.info("Stopped metrics export")
    
    def _export_loop(self, interval: float) -> None:
        """Run the metrics export loop."""
        while not self._stop_event.is_set():
            try:
                # Collect system metrics
                self.collector.collect_system_metrics()
                
                # Get all metrics
                metrics = self.collector.get_metrics()
                
                # Export metrics using all exporters
                for exporter in self.exporters:
                    try:
                        exporter.export(metrics)
                    except Exception as e:
                        self.logger.error(f"Error in metrics exporter {exporter.__class__.__name__}: {e}")
                
                # Wait for the next interval
                self._stop_event.wait(interval)
                
            except Exception as e:
                self.logger.error(f"Error in metrics export loop: {e}")
                self._stop_event.wait(min(interval, 5.0))  # Wait before retrying

# Global metrics collector instance
metrics_collector = MetricsCollector()

# Example usage
if __name__ == "__main__":
    import time
    import random
    import logging
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create a metrics collector
    collector = MetricsCollector(prefix='siem_demo')
    
    # Register some metrics
    collector.register_counter('http_requests_total', tags={'handler': 'index'})
    collector.register_gauge('active_connections', 0)
    collector.register_histogram('request_duration_seconds', buckets=[0.1, 0.5, 1.0, 2.5, 5.0])
    
    # Create exporters
    console_exporter = ConsoleExporter()
    prometheus_exporter = PrometheusExporter(port=9090)
    
    # Create and start the metrics manager
    manager = MetricsManager(collector, [console_exporter, prometheus_exporter])
    prometheus_exporter.start()  # Start Prometheus server
    manager.start(interval=5.0)  # Export every 5 seconds
    
    # Simulate some metrics
    try:
        while True:
            # Simulate HTTP requests
            collector.increment('http_requests_total', random.randint(1, 10))
            
            # Simulate active connections
            collector.set_gauge('active_connections', random.randint(0, 100))
            
            # Simulate request duration
            for _ in range(random.randint(1, 5)):
                duration = random.uniform(0.01, 3.0)
                collector.observe_histogram('request_duration_seconds', duration)
            
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping metrics collection...")
        manager.stop()
