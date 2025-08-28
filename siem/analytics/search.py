"""
Search and Analytics Module

This module provides search and analytical capabilities for time-series data,
including advanced queries, aggregations, and statistical analysis.
"""
import logging
import re
import json
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
import time
import math
from collections import defaultdict, Counter
import numpy as np
import pandas as pd

# Local imports
from .timeseries import TimeSeriesStorage, TimeRange, TimeGranularity, TimeSeriesPoint
from ..ueba.profiling import EntityType

logger = logging.getLogger(__name__)

class FilterOperator(Enum):
    """Supported filter operators for search queries."""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    GREATER_THAN = "gt"
    GREATER_THAN_OR_EQUAL = "gte"
    LESS_THAN = "lt"
    LESS_THAN_OR_EQUAL = "lte"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    REGEX = "regex"
    IN = "in"
    NOT_IN = "not_in"
    BETWEEN = "between"
    OUTSIDE = "outside"

@dataclass
class FilterCondition:
    """Represents a filter condition for search queries."""
    field: str
    operator: FilterOperator
    value: Any
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'field': self.field,
            'operator': self.operator.value,
            'value': self.value
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FilterCondition':
        """Create from dictionary."""
        return cls(
            field=data['field'],
            operator=FilterOperator(data['operator']),
            value=data['value']
        )
    
    def matches(self, point: TimeSeriesPoint) -> bool:
        """Check if a point matches this filter condition."""
        # Handle special fields
        if self.field == 'timestamp':
            field_value = point.timestamp
        elif self.field == 'value':
            field_value = point.value
        else:
            # Get from metadata
            field_value = point.metadata.get(self.field)
        
        # Handle different operators
        if self.operator == FilterOperator.EQUALS:
            return field_value == self.value
        elif self.operator == FilterOperator.NOT_EQUALS:
            return field_value != self.value
        elif self.operator == FilterOperator.CONTAINS:
            return (isinstance(field_value, str) and 
                    isinstance(self.value, str) and 
                    self.value in field_value)
        elif self.operator == FilterOperator.NOT_CONTAINS:
            return not (isinstance(field_value, str) and 
                       isinstance(self.value, str) and 
                       self.value in field_value)
        elif self.operator == FilterOperator.STARTS_WITH:
            return (isinstance(field_value, str) and 
                    isinstance(self.value, str) and 
                    field_value.startswith(self.value))
        elif self.operator == FilterOperator.ENDS_WITH:
            return (isinstance(field_value, str) and 
                    isinstance(self.value, str) and 
                    field_value.endswith(self.value))
        elif self.operator == FilterOperator.GREATER_THAN:
            return field_value is not None and field_value > self.value
        elif self.operator == FilterOperator.GREATER_THAN_OR_EQUAL:
            return field_value is not None and field_value >= self.value
        elif self.operator == FilterOperator.LESS_THAN:
            return field_value is not None and field_value < self.value
        elif self.operator == FilterOperator.LESS_THAN_OR_EQUAL:
            return field_value is not None and field_value <= self.value
        elif self.operator == FilterOperator.EXISTS:
            return field_value is not None
        elif self.operator == FilterOperator.NOT_EXISTS:
            return field_value is None
        elif self.operator == FilterOperator.REGEX:
            if not isinstance(field_value, str) or not isinstance(self.value, str):
                return False
            return bool(re.search(self.value, field_value, re.IGNORECASE))
        elif self.operator == FilterOperator.IN:
            return field_value in self.value if isinstance(self.value, (list, set, tuple)) else False
        elif self.operator == FilterOperator.NOT_IN:
            return field_value not in self.value if isinstance(self.value, (list, set, tuple)) else True
        elif self.operator == FilterOperator.BETWEEN:
            if not isinstance(self.value, (list, tuple)) or len(self.value) != 2:
                return False
            return (field_value is not None and 
                   self.value[0] <= field_value <= self.value[1])
        elif self.operator == FilterOperator.OUTSIDE:
            if not isinstance(self.value, (list, tuple)) or len(self.value) != 2:
                return False
            return (field_value is not None and 
                   (field_value < self.value[0] or field_value > self.value[1]))
        
        return False

@dataclass
class Aggregation:
    """Represents an aggregation operation for search queries."""
    field: str = "value"  # Default to aggregating the value field
    function: str = "count"  # count, sum, avg, min, max, stddev, variance, p50, p90, p95, p99
    as_name: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'field': self.field,
            'function': self.function,
            'as_name': self.as_name
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Aggregation':
        """Create from dictionary."""
        return cls(
            field=data.get('field', 'value'),
            function=data.get('function', 'count'),
            as_name=data.get('as_name')
        )
    
    def apply(self, values: List[float]) -> Dict[str, float]:
        """Apply the aggregation to a list of values."""
        if not values:
            return {}
        
        result = {}
        
        if self.function == 'count':
            result['count'] = len(values)
        elif self.function == 'sum':
            result['sum'] = sum(values)
        elif self.function == 'avg':
            result['avg'] = sum(values) / len(values)
        elif self.function == 'min':
            result['min'] = min(values)
        elif self.function == 'max':
            result['max'] = max(values)
        elif self.function == 'stddev':
            if len(values) > 1:
                result['stddev'] = statistics.stdev(values)
            else:
                result['stddev'] = 0.0
        elif self.function == 'variance':
            if len(values) > 1:
                result['variance'] = statistics.variance(values)
            else:
                result['variance'] = 0.0
        elif self.function == 'p50':
            result['p50'] = np.percentile(values, 50)
        elif self.function == 'p90':
            result['p90'] = np.percentile(values, 90)
        elif self.function == 'p95':
            result['p95'] = np.percentile(values, 95)
        elif self.function == 'p99':
            result['p99'] = np.percentile(values, 99)
        else:
            raise ValueError(f"Unsupported aggregation function: {self.function}")
        
        # Rename the result keys if as_name is specified
        if self.as_name:
            return {f"{self.as_name}_{k}": v for k, v in result.items()}
        
        return result

@dataclass
class GroupBy:
    """Represents a group by clause for search queries."""
    field: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {'field': self.field}
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'GroupBy':
        """Create from dictionary."""
        return cls(field=data['field'])

@dataclass
class SearchQuery:
    """Represents a search query for time-series data."""
    metrics: List[str]  # List of metric names or patterns
    time_range: TimeRange
    filters: List[FilterCondition] = field(default_factory=list)
    group_by: Optional[GroupBy] = None
    aggregations: List[Aggregation] = field(default_factory=list)
    limit: Optional[int] = None
    offset: int = 0
    sort: Optional[List[Tuple[str, str]]] = None  # List of (field, direction) tuples
    include_metadata: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'metrics': self.metrics,
            'time_range': self.time_range.to_dict(),
            'filters': [f.to_dict() for f in self.filters],
            'group_by': self.group_by.to_dict() if self.group_by else None,
            'aggregations': [a.to_dict() for a in self.aggregations],
            'limit': self.limit,
            'offset': self.offset,
            'sort': self.sort,
            'include_metadata': self.include_metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SearchQuery':
        """Create from dictionary."""
        return cls(
            metrics=data['metrics'],
            time_range=TimeRange.from_dict(data['time_range']),
            filters=[FilterCondition.from_dict(f) for f in data.get('filters', [])],
            group_by=GroupBy.from_dict(data['group_by']) if data.get('group_by') else None,
            aggregations=[Aggregation.from_dict(a) for a in data.get('aggregations', [])],
            limit=data.get('limit'),
            offset=data.get('offset', 0),
            sort=data.get('sort'),
            include_metadata=data.get('include_metadata', True)
        )
    
    def add_filter(self, field: str, operator: Union[str, FilterOperator], value: Any) -> 'SearchQuery':
        """Add a filter condition to the query."""
        if isinstance(operator, str):
            operator = FilterOperator(operator.lower())
            
        self.filters.append(FilterCondition(
            field=field,
            operator=operator,
            value=value
        ))
        return self
    
    def add_aggregation(self, function: str, field: str = "value", as_name: Optional[str] = None) -> 'SearchQuery':
        """Add an aggregation to the query."""
        self.aggregations.append(Aggregation(
            field=field,
            function=function.lower(),
            as_name=as_name
        ))
        return self
    
    def set_group_by(self, field: str) -> 'SearchQuery':
        """Set the group by field."""
        self.group_by = GroupBy(field=field)
        return self
    
    def set_limit(self, limit: int) -> 'SearchQuery':
        """Set the result limit."""
        self.limit = limit
        return self
    
    def set_offset(self, offset: int) -> 'SearchQuery':
        """Set the result offset."""
        self.offset = offset
        return self
    
    def set_sort(self, field: str, direction: str = 'asc') -> 'SearchQuery':
        """Set the sort order."""
        if self.sort is None:
            self.sort = []
        
        self.sort.append((field, direction.lower()))
        return self

@dataclass
class SearchResult:
    """Represents the result of a search query."""
    points: List[TimeSeriesPoint]
    total: int
    query: Optional[SearchQuery] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'points': [p.to_dict() for p in self.points],
            'total': self.total,
            'query': self.query.to_dict() if self.query else None,
            'metadata': self.metadata
        }
    
    def to_dataframe(self) -> 'pd.DataFrame':
        """Convert the result to a pandas DataFrame."""
        if not self.points:
            return pd.DataFrame()
        
        # Create a list of dictionaries for each point
        data = []
        
        for point in self.points:
            point_dict = {
                'timestamp': point.timestamp,
                'value': point.value
            }
            
            # Add metadata fields
            if point.metadata:
                for k, v in point.metadata.items():
                    point_dict[k] = v
            
            data.append(point_dict)
        
        return pd.DataFrame(data)
    
    def get_aggregations(self) -> Dict[str, Dict[str, float]]:
        """Calculate aggregations for the result set."""
        if not self.query or not self.query.aggregations:
            return {}
        
        # Group values by field
        field_values = defaultdict(list)
        
        for point in self.points:
            for agg in self.query.aggregations:
                if agg.field == 'value':
                    field_values['value'].append(point.value)
                else:
                    # Get from metadata
                    if point.metadata and agg.field in point.metadata:
                        field_values[agg.field].append(point.metadata[agg.field])
        
        # Calculate aggregations
        results = {}
        
        for agg in self.query.aggregations:
            values = field_values.get(agg.field, [])
            
            # Convert to float if possible
            try:
                values = [float(v) for v in values if v is not None]
            except (ValueError, TypeError):
                # Skip non-numeric values for numerical aggregations
                if agg.function not in ('count', 'cardinality'):
                    continue
            
            # Apply aggregation
            agg_result = agg.apply(values)
            
            # Merge with existing results
            for k, v in agg_result.items():
                if agg.as_name:
                    results[f"{agg.as_name}_{k}"] = v
                else:
                    results[f"{agg.field}_{k}"] = v
        
        return results
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the search results."""
        summary = {
            'total_points': len(self.points),
            'time_range': {
                'start': min(p.timestamp for p in self.points) if self.points else None,
                'end': max(p.timestamp for p in self.points) if self.points else None
            },
            'metrics': {},
            'aggregations': {}
        }
        
        # Count unique values for each metadata field
        if self.points and self.points[0].metadata:
            field_values = defaultdict(set)
            
            for point in self.points:
                for k, v in point.metadata.items():
                    field_values[k].add(v)
            
            for field, values in field_values.items():
                summary['metrics'][f"unique_{field}_count"] = len(values)
        
        # Add aggregations
        if self.query and self.query.aggregations:
            summary['aggregations'] = self.get_aggregations()
        
        return summary

class SearchEngine:
    """Search engine for time-series data with advanced querying capabilities."""
    
    def __init__(self, storage: TimeSeriesStorage):
        """Initialize the search engine.
        
        Args:
            storage: TimeSeriesStorage instance to query
        """
        self.storage = storage
    
    def search(self, query: Union[Dict[str, Any], SearchQuery]) -> SearchResult:
        """Execute a search query.
        
        Args:
            query: Search query as a dictionary or SearchQuery object
            
        Returns:
            SearchResult with matching points and metadata
        """
        if isinstance(query, dict):
            query = SearchQuery.from_dict(query)
        
        # Find all metrics that match the patterns
        matching_metrics = set()
        
        for pattern in query.metrics:
            if '*' in pattern or '?' in pattern or '[' in pattern:
                # Handle glob patterns
                import fnmatch
                for metric in self.storage.list_metrics():
                    if fnmatch.fnmatch(metric, pattern):
                        matching_metrics.add(metric)
            else:
                # Exact match
                if pattern in self.storage.list_metrics():
                    matching_metrics.add(pattern)
        
        if not matching_metrics:
            return SearchResult(points=[], total=0, query=query)
        
        # Query each matching metric
        all_points = []
        
        for metric in matching_metrics:
            # Get points for this metric
            points = self.storage.query_points(
                metric_name=metric,
                time_range=query.time_range
            )
            
            # Apply filters
            if query.filters:
                filtered_points = []
                
                for point in points:
                    # Check if all filters match
                    if all(f.matches(point) for f in query.filters):
                        filtered_points.append(point)
                
                points = filtered_points
            
            all_points.extend(points)
        
        # Apply sorting
        if query.sort:
            for field, direction in reversed(query.sort):
                reverse = (direction.lower() == 'desc')
                
                def get_sort_key(p):
                    if field == 'timestamp':
                        return p.timestamp
                    elif field == 'value':
                        return p.value
                    else:
                        return p.metadata.get(field)
                
                all_points.sort(key=get_sort_key, reverse=reverse)
        
        # Apply grouping if specified
        if query.group_by:
            grouped_points = defaultdict(list)
            
            for point in all_points:
                if query.group_by.field == 'metric':
                    group_key = point.metadata.get('_metric', 'unknown')
                else:
                    group_key = point.metadata.get(query.group_by.field)
                
                if group_key is not None:
                    grouped_points[group_key].append(point)
            
            # Create a new point for each group with aggregated values
            result_points = []
            
            for group_key, group_points in grouped_points.items():
                # Calculate aggregations for this group
                if query.aggregations:
                    agg_results = {}
                    
                    for agg in query.aggregations:
                        if agg.field == 'value':
                            values = [p.value for p in group_points]
                        else:
                            values = [p.metadata.get(agg.field) for p in group_points]
                            values = [v for v in values if v is not None]
                        
                        agg_result = agg.apply(values)
                        agg_results.update(agg_result)
                    
                    # Create a new point with aggregated values
                    metadata = {
                        query.group_by.field: group_key,
                        **agg_results
                    }
                    
                    # Use the first point's timestamp or now() if no points
                    timestamp = group_points[0].timestamp if group_points else datetime.utcnow()
                    
                    result_points.append(TimeSeriesPoint(
                        timestamp=timestamp,
                        value=len(group_points),  # Default to count
                        metadata=metadata
                    ))
                else:
                    # No aggregations, just include all points
                    result_points.extend(group_points)
            
            all_points = result_points
        
        # Apply pagination
        total_points = len(all_points)
        
        if query.offset > 0 or query.limit is not None:
            start = query.offset
            end = start + query.limit if query.limit is not None else None
            all_points = all_points[start:end]
        
        return SearchResult(
            points=all_points,
            total=total_points,
            query=query,
            metadata={
                'metrics': list(matching_metrics),
                'matched_metrics_count': len(matching_metrics)
            }
        )
    
    def aggregate(self, query: Union[Dict[str, Any], SearchQuery]) -> Dict[str, Any]:
        """Execute an aggregation query.
        
        Args:
            query: Search query with aggregations
            
        Returns:
            Dictionary with aggregation results
        """
        if isinstance(query, dict):
            query = SearchQuery.from_dict(query)
        
        # Ensure we have aggregations
        if not query.aggregations:
            raise ValueError("No aggregations specified in query")
        
        # Execute the search
        result = self.search(query)
        
        # Calculate aggregations
        return result.get_aggregations()
    
    def get_metric_statistics(self, metric_name: str, time_range: TimeRange) -> Dict[str, Any]:
        """Get statistics for a metric over a time range.
        
        Args:
            metric_name: Name of the metric
            time_range: Time range to analyze
            
        Returns:
            Dictionary with statistics
        """
        # Get all points for the metric
        points = self.storage.query_points(
            metric_name=metric_name,
            time_range=time_range
        )
        
        if not points:
            return {
                'count': 0,
                'min': None,
                'max': None,
                'avg': None,
                'stddev': None
            }
        
        # Calculate basic statistics
        values = [p.value for p in points]
        
        return {
            'count': len(values),
            'min': min(values) if values else None,
            'max': max(values) if values else None,
            'avg': sum(values) / len(values) if values else None,
            'stddev': statistics.stdev(values) if len(values) > 1 else 0.0,
            'first_timestamp': min(p.timestamp for p in points),
            'last_timestamp': max(p.timestamp for p in points)
        }
    
    def detect_anomalies(
        self,
        metric_name: str,
        time_range: TimeRange,
        method: str = 'zscore',
        threshold: float = 3.0,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """Detect anomalies in a time series.
        
        Args:
            metric_name: Name of the metric to analyze
            time_range: Time range to analyze
            method: Detection method ('zscore', 'iqr', 'threshold')
            threshold: Threshold for anomaly detection
            **kwargs: Additional method-specific parameters
            
        Returns:
            List of detected anomalies
        """
        # Get all points for the metric
        points = self.storage.query_points(
            metric_name=metric_name,
            time_range=time_range
        )
        
        if not points:
            return []
        
        # Extract values and timestamps
        values = [p.value for p in points]
        timestamps = [p.timestamp for p in points]
        
        anomalies = []
        
        if method == 'zscore':
            # Use z-score method
            mean = statistics.mean(values)
            std = statistics.stdev(values) if len(values) > 1 else 0.0
            
            for i, (ts, val) in enumerate(zip(timestamps, values)):
                if std == 0:
                    zscore = 0.0
                else:
                    zscore = abs((val - mean) / std)
                
                if zscore > threshold:
                    anomalies.append({
                        'timestamp': ts,
                        'value': val,
                        'zscore': zscore,
                        'mean': mean,
                        'stddev': std,
                        'metric': metric_name
                    })
        
        elif method == 'iqr':
            # Use IQR (Interquartile Range) method
            q1 = np.percentile(values, 25)
            q3 = np.percentile(values, 75)
            iqr = q3 - q1
            
            lower_bound = q1 - (threshold * iqr)
            upper_bound = q3 + (threshold * iqr)
            
            for i, (ts, val) in enumerate(zip(timestamps, values)):
                if val < lower_bound or val > upper_bound:
                    anomalies.append({
                        'timestamp': ts,
                        'value': val,
                        'lower_bound': lower_bound,
                        'upper_bound': upper_bound,
                        'q1': q1,
                        'q3': q3,
                        'iqr': iqr,
                        'metric': metric_name
                    })
        
        elif method == 'threshold':
            # Simple threshold method
            min_val = kwargs.get('min')
            max_val = kwargs.get('max')
            
            if min_val is None and max_val is None:
                raise ValueError("Either min or max must be specified for threshold method")
            
            for i, (ts, val) in enumerate(zip(timestamps, values)):
                if (min_val is not None and val < min_val) or (max_val is not None and val > max_val):
                    anomalies.append({
                        'timestamp': ts,
                        'value': val,
                        'min_threshold': min_val,
                        'max_threshold': max_val,
                        'metric': metric_name
                    })
        
        else:
            raise ValueError(f"Unsupported anomaly detection method: {method}")
        
        return anomalies

# Example usage
if __name__ == "__main__":
    import tempfile
    import random
    from datetime import datetime, timedelta
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create a temporary directory for testing
    with tempfile.TemporaryDirectory() as temp_dir:
        # Initialize storage
        storage = FileTimeSeriesStorage(
            base_dir=temp_dir,
            shard_duration="1d",
            compress=True
        )
        
        # Generate some test data
        now = datetime.utcnow()
        points = []
        
        for i in range(1000):
            timestamp = now - timedelta(minutes=i)
            value = random.gauss(100, 10)  # Normal distribution around 100
            
            points.append(TimeSeriesPoint(
                timestamp=timestamp,
                value=value,
                metadata={
                    'source': 'test',
                    'entity_id': f"user{i % 10}",
                    'metric_type': 'cpu_usage'
                }
            ))
        
        # Write points
        storage.write_points("test_metric", points)
        
        # Initialize search engine
        search_engine = SearchEngine(storage)
        
        # Example 1: Simple search
        print("\n--- Simple Search ---")
        query = SearchQuery(
            metrics=["test_metric"],
            time_range=TimeRange(
                start_time=now - timedelta(hours=24),
                end_time=now
            ),
            limit=5
        )
        
        result = search_engine.search(query)
        print(f"Found {result.total} points")
        
        for point in result.points[:5]:
            print(f"{point.timestamp}: {point.value:.2f}")
        
        # Example 2: Search with filters
        print("\n--- Search with Filters ---")
        query = (
            SearchQuery(
                metrics=["test_metric"],
                time_range=TimeRange(
                    start_time=now - timedelta(hours=24),
                    end_time=now
                )
            )
            .add_filter('entity_id', 'equals', 'user1')
            .add_filter('value', 'gt', 110)
            .set_limit(5)
        )
        
        result = search_engine.search(query)
        print(f"Found {result.total} points")
        
        for point in result.points:
            print(f"{point.timestamp}: {point.value:.2f} (entity: {point.metadata.get('entity_id')})")
        
        # Example 3: Aggregations
        print("\n--- Aggregations ---")
        query = (
            SearchQuery(
                metrics=["test_metric"],
                time_range=TimeRange(
                    start_time=now - timedelta(hours=24),
                    end_time=now
                )
            )
            .add_aggregation('avg', 'value', 'avg_value')
            .add_aggregation('max', 'value', 'max_value')
            .add_aggregation('min', 'value', 'min_value')
        )
        
        result = search_engine.search(query)
        print("Aggregations:", result.get_aggregations())
        
        # Example 4: Group by
        print("\n--- Group By ---")
        query = (
            SearchQuery(
                metrics=["test_metric"],
                time_range=TimeRange(
                    start_time=now - timedelta(hours=24),
                    end_time=now
                )
            )
            .set_group_by('entity_id')
            .add_aggregation('avg', 'value', 'avg_value')
            .add_aggregation('count', 'value', 'count')
        )
        
        result = search_engine.search(query)
        print("Grouped results:")
        
        for point in result.points:
            print(f"Entity {point.metadata['entity_id']}: {point.metadata['avg_value_avg']:.2f} (count: {point.metadata['count_count']})")
        
        # Example 5: Anomaly detection
        print("\n--- Anomaly Detection ---")
        anomalies = search_engine.detect_anomalies(
            metric_name="test_metric",
            time_range=TimeRange(
                start_time=now - timedelta(hours=24),
                end_time=now
            ),
            method='zscore',
            threshold=2.5
        )
        
        print(f"Found {len(anomalies)} anomalies:")
        
        for i, anomaly in enumerate(anomalies[:5]):  # Show first 5 anomalies
            print(f"{i+1}. {anomaly['timestamp']}: {anomaly['value']:.2f} (z-score: {anomaly['zscore']:.2f})")
