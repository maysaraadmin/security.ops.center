"""Data models for metrics and statistics in the SIEM system."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any

@dataclass
class MetricValue:
    """Represents a single metric value with timestamp."""
    value: float
    timestamp: datetime
    unit: str = 'count'
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class TimeSeriesMetric:
    """Represents a time series metric with multiple data points."""
    name: str
    values: List[MetricValue]
    description: str = ""
    tags: Dict[str, str] = field(default_factory=dict)

@dataclass
class DashboardMetrics:
    """Container for all metrics to be displayed on the dashboard."""
    timestamp: datetime
    siem_metrics: Dict[str, Any] = field(default_factory=dict)
    edr_metrics: Dict[str, Any] = field(default_factory=dict)
    ndr_metrics: Dict[str, Any] = field(default_factory=dict)
    dlp_metrics: Dict[str, Any] = field(default_factory=dict)
    fim_metrics: Dict[str, Any] = field(default_factory=dict)
    hips_metrics: Dict[str, Any] = field(default_factory=dict)
    nips_metrics: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, TimeSeriesMetric] = field(default_factory=dict)
    
    def add_metric(self, name: str, value: float, timestamp: Optional[datetime] = None, 
                  unit: str = 'count', metadata: Optional[Dict[str, Any]] = None, 
                  description: str = "", tags: Optional[Dict[str, str]] = None):
        """Add a new metric value.
        
        Args:
            name: Name of the metric
            value: Numeric value of the metric
            timestamp: When the metric was recorded (defaults to now)
            unit: Unit of measurement (default: 'count')
            metadata: Additional metadata about the metric
            description: Description of what the metric measures
            tags: Key-value pairs for categorizing the metric
        """
        if timestamp is None:
            timestamp = datetime.utcnow()
            
        if name not in self.metrics:
            self.metrics[name] = TimeSeriesMetric(
                name=name,
                values=[],
                description=description,
                tags=tags or {}
            )
            
        self.metrics[name].values.append(
            MetricValue(
                value=value,
                timestamp=timestamp,
                unit=unit,
                metadata=metadata or {}
            )
        )
    
    def get_latest_value(self, name: str) -> Optional[float]:
        """Get the most recent value for a metric."""
        if name not in self.metrics or not self.metrics[name].values:
            return None
        return self.metrics[name].values[-1].value
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to a dictionary for serialization."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'metrics': {
                name: {
                    'name': metric.name,
                    'description': metric.description,
                    'tags': metric.tags,
                    'values': [
                        {
                            'value': v.value,
                            'timestamp': v.timestamp.isoformat(),
                            'unit': v.unit,
                            'metadata': v.metadata
                        } for v in metric.values
                    ]
                } for name, metric in self.metrics.items()
            }
        }
