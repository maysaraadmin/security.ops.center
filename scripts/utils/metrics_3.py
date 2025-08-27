"""Metrics collection and monitoring for the SIEM system."""
import time
import psutil
import platform
from typing import Dict, Any, Optional, Callable, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import deque
import threading
import logging
from src.models.database import Database

logger = logging.getLogger('siem.metrics')

@dataclass
class Metric:
    """Base class for all metrics."""
    name: str
    value: Any
    timestamp: datetime = field(default_factory=datetime.utcnow)
    tags: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metric to dictionary for serialization."""
        return {
            'name': self.name,
            'value': self.value,
            'timestamp': self.timestamp.isoformat(),
            'tags': self.tags
        }

class Counter(Metric):
    """A counter metric that can only increase or be reset to zero."""
    def __init__(self, name: str, initial_value: int = 0, **tags):
        super().__init__(name, initial_value, tags=tags)
        self._lock = threading.Lock()
    
    def inc(self, value: int = 1) -> None:
        """Increment the counter by the given value."""
        with self._lock:
            self.value += value
            self.timestamp = datetime.utcnow()
    
    def reset(self) -> None:
        """Reset the counter to zero."""
        with self._lock:
            self.value = 0
            self.timestamp = datetime.utcnow()

class Gauge(Metric):
    """A gauge metric that can go up and down."""
    def __init__(self, name: str, initial_value: float = 0.0, **tags):
        super().__init__(name, float(initial_value), tags=tags)
        self._lock = threading.Lock()
    
    def set(self, value: float) -> None:
        """Set the gauge to the given value."""
        with self._lock:
            self.value = float(value)
            self.timestamp = datetime.utcnow()
    
    def inc(self, value: float = 1.0) -> None:
        """Increment the gauge by the given value."""
        with self._lock:
            self.value += float(value)
            self.timestamp = datetime.utcnow()
    
    def dec(self, value: float = 1.0) -> None:
        """Decrement the gauge by the given value."""
        with self._lock:
            self.value -= float(value)
            self.timestamp = datetime.utcnow()

class Histogram(Metric):
    """A histogram metric that tracks the distribution of values."""
    def __init__(self, name: str, **tags):
        super().__init__(name, [], tags=tags)
        self._lock = threading.Lock()
        self._sum = 0.0
        self._count = 0
    
    def observe(self, value: float) -> None:
        """Observe a value and update the histogram."""
        with self._lock:
            self.value.append(float(value))
            self._sum += float(value)
            self._count += 1
            self.timestamp = datetime.utcnow()
    
    def get_summary(self) -> Dict[str, float]:
        """Get summary statistics for the histogram."""
        with self._lock:
            if not self.value:
                return {
                    'count': 0,
                    'sum': 0.0,
                    'avg': 0.0,
                    'min': 0.0,
                    'max': 0.0,
                    'p50': 0.0,
                    'p90': 0.0,
                    'p95': 0.0,
                    'p99': 0.0
                }
            
            values = sorted(self.value)
            count = len(values)
            total = sum(values)
            
            def percentile(p: float) -> float:
                if not values:
                    return 0.0
                k = (len(values) - 1) * p
                f = int(k)
                c = int(k) + 1
                if c >= len(values):
                    return values[-1]
                return values[f] + (values[c] - values[f]) * (k - f)
            
            return {
                'count': count,
                'sum': total,
                'avg': total / count,
                'min': min(values),
                'max': max(values),
                'p50': percentile(0.5),
                'p90': percentile(0.9),
                'p95': percentile(0.95),
                'p99': percentile(0.99)
            }
    
    def reset(self) -> None:
        """Reset the histogram."""
        with self._lock:
            self.value = []
            self._sum = 0.0
            self._count = 0
            self.timestamp = datetime.utcnow()

class MetricsCollector:
    """Collects and manages application metrics."""
    def __init__(self, db: Optional[Database] = None):
        self._metrics: Dict[str, Metric] = {}
        self._lock = threading.RLock()
        self._db = db
        self._running = False
        self._collector_thread: Optional[threading.Thread] = None
        
        # Register system metrics
        self.register_gauge('system.cpu.percent')
        self.register_gauge('system.memory.percent')
        self.register_gauge('system.disk.percent')
        self.register_gauge('system.process.memory.rss')
        self.register_gauge('system.process.cpu.percent')
        
        # Register application metrics
        self.register_counter('siem.events.processed')
        self.register_counter('siem.events.dropped')
        self.register_histogram('siem.event.processing.time')
        self.register_gauge('siem.queue.size')
        self.register_gauge('siem.threads.active')
        
        # Start background collector
        self.start()
    
    def register_counter(self, name: str, **tags) -> Counter:
        """Register a new counter metric."""
        with self._lock:
            if name in self._metrics:
                if not isinstance(self._metrics[name], Counter):
                    raise ValueError(f"Metric {name} already exists with a different type")
                return self._metrics[name]
            
            counter = Counter(name, **tags)
            self._metrics[name] = counter
            return counter
    
    def register_gauge(self, name: str, **tags) -> Gauge:
        """Register a new gauge metric."""
        with self._lock:
            if name in self._metrics:
                if not isinstance(self._metrics[name], Gauge):
                    raise ValueError(f"Metric {name} already exists with a different type")
                return self._metrics[name]
            
            gauge = Gauge(name, **tags)
            self._metrics[name] = gauge
            return gauge
    
    def register_histogram(self, name: str, **tags) -> Histogram:
        """Register a new histogram metric."""
        with self._lock:
            if name in self._metrics:
                if not isinstance(self._metrics[name], Histogram):
                    raise ValueError(f"Metric {name} already exists with a different type")
                return self._metrics[name]
            
            histogram = Histogram(name, **tags)
            self._metrics[name] = histogram
            return histogram
    
    def get_metric(self, name: str) -> Optional[Metric]:
        """Get a metric by name."""
        with self._lock:
            return self._metrics.get(name)
    
    def get_all_metrics(self) -> Dict[str, Metric]:
        """Get all registered metrics."""
        with self._lock:
            return self._metrics.copy()
    
    def collect_system_metrics(self) -> None:
        """Collect system-level metrics."""
        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=None)
            self.get_metric('system.cpu.percent').set(cpu_percent)
            
            # Memory
            memory = psutil.virtual_memory()
            self.get_metric('system.memory.percent').set(memory.percent)
            
            # Disk
            disk = psutil.disk_usage('/')
            self.get_metric('system.disk.percent').set(disk.percent)
            
            # Process info
            process = psutil.Process()
            with process.oneshot():
                self.get_metric('system.process.memory.rss').set(process.memory_info().rss / 1024 / 1024)  # MB
                self.get_metric('system.process.cpu.percent').set(process.cpu_percent(interval=None))
                
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}", exc_info=True)
    
    def collect_application_metrics(self) -> None:
        """Collect application-level metrics."""
        try:
            # Thread count
            self.get_metric('siem.threads.active').set(threading.active_count())
            
            # Database metrics if available
            if self._db:
                try:
                    # Handle both direct connections and connection pools
                    if hasattr(self._db, 'get_connection'):
                        # Connection pool
                        with self._db.get_connection() as conn:
                            cursor = conn.cursor()
                    else:
                        # Direct connection
                        cursor = self._db.cursor()
                    
                    # Event counts
                    cursor.execute("""
                        SELECT 
                            COUNT(*) as total_events,
                            SUM(CASE WHEN status = 'New' THEN 1 ELSE 0 END) as new_events,
                            SUM(CASE WHEN status = 'In Progress' THEN 1 ELSE 0 END) as in_progress_events,
                            SUM(CASE WHEN status = 'Resolved' THEN 1 ELSE 0 END) as resolved_events
                        FROM events
                    """)
                    result = cursor.fetchone()
                    
                    # Handle both dictionary and tuple results
                    if isinstance(result, dict):
                        total = result.get('total_events', 0) or 0
                        new = result.get('new_events', 0) or 0
                        in_progress = result.get('in_progress_events', 0) or 0
                        resolved = result.get('resolved_events', 0) or 0
                    else:  # Handle tuple results
                        total = result[0] if result and len(result) > 0 else 0
                        new = result[1] if result and len(result) > 1 else 0
                        in_progress = result[2] if result and len(result) > 2 else 0
                        resolved = result[3] if result and len(result) > 3 else 0
                    
                    self.register_gauge('siem.events.total').set(total)
                    self.register_gauge('siem.events.status.new').set(new)
                    self.register_gauge('siem.events.status.in_progress').set(in_progress)
                    self.register_gauge('siem.events.status.resolved').set(resolved)
                    
                    # Rule counts
                    cursor.execute("""
                        SELECT 
                            COUNT(*) as total_rules,
                            SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as enabled_rules
                        FROM rules
                    """)
                    result = cursor.fetchone()
                    
                    # Handle both dictionary and tuple results with proper null checking
                    total_rules = 0
                    enabled_rules = 0
                    
                    if isinstance(result, dict):
                        total_rules = int(result.get('total_rules', 0)) if result and 'total_rules' in result else 0
                        enabled_rules = int(result.get('enabled_rules', 0)) if result and 'enabled_rules' in result else 0
                    elif isinstance(result, (list, tuple)) and len(result) >= 2:  # Handle tuple/list results
                        total_rules = int(result[0]) if result[0] is not None else 0
                        enabled_rules = int(result[1]) if len(result) > 1 and result[1] is not None else 0
                    
                    # Ensure values are non-negative integers
                    total_rules = max(0, int(total_rules) if total_rules is not None else 0)
                    enabled_rules = max(0, int(enabled_rules) if enabled_rules is not None else 0)
                    
                    # Set the gauge values with type safety
                    self.register_gauge('siem.rules.total').set(float(total_rules))
                    self.register_gauge('siem.rules.enabled').set(float(enabled_rules))
                    
                except Exception as e:
                    logger.error(f"Error collecting database metrics: {e}", exc_info=True)
                    
        except Exception as e:
            logger.error(f"Error collecting application metrics: {e}", exc_info=True)
    
    def collect_metrics(self) -> None:
        """Collect all metrics."""
        self.collect_system_metrics()
        self.collect_application_metrics()
    
    def start(self) -> None:
        """Start the metrics collector thread."""
        if self._running:
            return
            
        self._running = True
        self._collector_thread = threading.Thread(
            target=self._run_collector,
            name="MetricsCollector",
            daemon=True
        )
        self._collector_thread.start()
        logger.info("Metrics collector started")
    
    def stop(self) -> None:
        """Stop the metrics collector thread."""
        self._running = False
        if self._collector_thread and self._collector_thread.is_alive():
            self._collector_thread.join(timeout=5.0)
        logger.info("Metrics collector stopped")
    
    def _run_collector(self) -> None:
        """Run the metrics collector in a loop."""
        while self._running:
            try:
                self.collect_metrics()
            except Exception as e:
                logger.error(f"Error in metrics collector: {e}", exc_info=True)
            
            # Sleep for a bit before collecting again
            for _ in range(10):  # Check every 0.5s if we should stop
                if not self._running:
                    break
                time.sleep(0.5)
    
    def get_metrics_snapshot(self) -> Dict[str, Any]:
        """Get a snapshot of all metrics."""
        snapshot = {
            'timestamp': datetime.utcnow().isoformat(),
            'metrics': {}
        }
        
        with self._lock:
            for name, metric in self._metrics.items():
                if isinstance(metric, Histogram):
                    snapshot['metrics'][name] = {
                        'type': 'histogram',
                        'summary': metric.get_summary(),
                        'tags': metric.tags
                    }
                else:
                    snapshot['metrics'][name] = {
                        'type': metric.__class__.__name__.lower(),
                        'value': metric.value,
                        'tags': metric.tags
                    }
        
        return snapshot
    
    def increment_counter(self, name: str, value: int = 1, **tags) -> None:
        """Increment a counter metric.
        
        Args:
            name: Name of the counter metric
            value: Value to increment by (default: 1)
            **tags: Additional tags for the metric
        """
        with self._lock:
            if name not in self._metrics:
                self.register_counter(name, **tags)
            if isinstance(self._metrics[name], Counter):
                self._metrics[name].inc(value)
            else:
                logger.warning(f"Metric {name} is not a counter")
    
    def record_gauge(self, name: str, value: float, **tags) -> None:
        """Set the value of a gauge metric.
        
        Args:
            name: Name of the gauge metric
            value: Value to set
            **tags: Additional tags for the metric
        """
        with self._lock:
            if name not in self._metrics:
                self.register_gauge(name, **tags)
            if isinstance(self._metrics[name], Gauge):
                self._metrics[name].set(value)
            else:
                logger.warning(f"Metric {name} is not a gauge")
    
    def __del__(self):
        """Clean up resources."""
        self.stop()

# Global metrics collector instance
_metrics_collector: Optional[MetricsCollector] = None

def init_metrics(db: Optional[Database] = None) -> None:
    """Initialize the global metrics collector."""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector(db)

def get_metrics_collector() -> MetricsCollector:
    """Get the global metrics collector instance."""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector

def get_metric(name: str) -> Optional[Metric]:
    """Get a metric by name from the global collector."""
    collector = get_metrics_collector()
    return collector.get_metric(name)

def get_metrics_snapshot() -> Dict[str, Any]:
    """Get a snapshot of all metrics from the global collector."""
    collector = get_metrics_collector()
    return collector.get_metrics_snapshot()

def record_histogram(name: str, value: float, **tags) -> None:
    """Record a value in a histogram metric."""
    collector = get_metrics_collector()
    metric = collector.get_metric(name)
    if metric is None:
        metric = collector.register_histogram(name, **tags)
    if isinstance(metric, Histogram):
        metric.observe(value)
    else:
        logger.warning(f"Metric {name} is not a histogram")

def increment_counter(name: str, value: int = 1, **tags) -> None:
    """Increment a counter metric."""
    collector = get_metrics_collector()
    metric = collector.get_metric(name)
    if metric is None:
        metric = collector.register_counter(name, **tags)
    if isinstance(metric, Counter):
        metric.inc(value)
    else:
        logger.warning(f"Metric {name} is not a counter")

def set_gauge(name: str, value: float, **tags) -> None:
    """Set the value of a gauge metric."""
    collector = get_metrics_collector()
    metric = collector.get_metric(name)
    if metric is None:
        metric = collector.register_gauge(name, **tags)
    if isinstance(metric, Gauge):
        metric.set(value)
    else:
        logger.warning(f"Metric {name} is not a gauge")
