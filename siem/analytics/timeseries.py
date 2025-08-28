"""
Time Series Data Storage and Analysis Module

This module provides functionality for storing, querying, and analyzing time-series data
for security events, behavior profiles, and anomaly scores.
"""
import os
import json
import gzip
import shutil
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple, Iterator, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import time
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Third-party imports
import numpy as np
import pandas as pd
from dateutil.parser import parse as parse_date

# Local imports
from ..ueba.profiling import EntityType

logger = logging.getLogger(__name__)

class TimeGranularity(Enum):
    """Supported time granularities for time-series data."""
    SECOND = "1s"
    MINUTE = "1m"
    HOUR = "1h"
    DAY = "1d"
    WEEK = "1w"
    MONTH = "1M"
    YEAR = "1y"

@dataclass
class TimeRange:
    """Represents a time range for queries."""
    start_time: datetime
    end_time: datetime
    
    @classmethod
    def from_relative(
        cls, 
        duration: str, 
        end_time: Optional[datetime] = None
    ) -> 'TimeRange':
        """Create a time range from a relative duration.
        
        Args:
            duration: Duration string (e.g., '1h', '7d', '30d')
            end_time: End time (default: now)
            
        Returns:
            TimeRange object
        """
        end_time = end_time or datetime.utcnow()
        duration = duration.lower()
        
        if duration.endswith('s'):
            delta = timedelta(seconds=float(duration[:-1]))
        elif duration.endswith('m'):
            delta = timedelta(minutes=float(duration[:-1]))
        elif duration.endswith('h'):
            delta = timedelta(hours=float(duration[:-1]))
        elif duration.endswith('d'):
            delta = timedelta(days=float(duration[:-1]))
        elif duration.endswith('w'):
            delta = timedelta(weeks=float(duration[:-1]))
        else:
            raise ValueError(f"Invalid duration format: {duration}")
        
        return cls(start_time=end_time - delta, end_time=end_time)
    
    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary with ISO format timestamps."""
        return {
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TimeRange':
        """Create from dictionary with ISO format timestamps."""
        return cls(
            start_time=parse_date(data['start_time']) if isinstance(data['start_time'], str) else data['start_time'],
            end_time=parse_date(data['end_time']) if isinstance(data['end_time'], str) else data['end_time']
        )

@dataclass
class TimeSeriesPoint:
    """A single data point in a time series."""
    timestamp: datetime
    value: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'value': self.value,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TimeSeriesPoint':
        """Create from dictionary."""
        return cls(
            timestamp=parse_date(data['timestamp']) if isinstance(data['timestamp'], str) else data['timestamp'],
            value=float(data['value']),
            metadata=data.get('metadata', {})
        )

class TimeSeriesStorage:
    """Base class for time series storage backends."""
    
    def write_points(
        self, 
        metric_name: str, 
        points: List[TimeSeriesPoint],
        **tags
    ) -> None:
        """Write multiple data points to the storage.
        
        Args:
            metric_name: Name of the metric
            points: List of TimeSeriesPoint objects
            **tags: Additional tags to associate with the data points
        """
        raise NotImplementedError
    
    def query_points(
        self,
        metric_name: str,
        time_range: TimeRange,
        granularity: Optional[TimeGranularity] = None,
        aggregation: Optional[str] = None,
        **filters
    ) -> List[TimeSeriesPoint]:
        """Query time series data.
        
        Args:
            metric_name: Name of the metric to query
            time_range: Time range for the query
            granularity: Time granularity for downsampling
            aggregation: Aggregation function (e.g., 'mean', 'sum', 'count', 'max', 'min')
            **filters: Tag filters to apply to the query
            
        Returns:
            List of TimeSeriesPoint objects
        """
        raise NotImplementedError
    
    def delete_points(
        self,
        metric_name: str,
        time_range: TimeRange,
        **filters
    ) -> int:
        """Delete time series data.
        
        Args:
            metric_name: Name of the metric
            time_range: Time range for deletion
            **filters: Tag filters to apply to the deletion
            
        Returns:
            Number of points deleted
        """
        raise NotImplementedError
    
    def list_metrics(self, prefix: str = "") -> List[str]:
        """List available metrics.
        
        Args:
            prefix: Optional prefix to filter metrics by
            
        Returns:
            List of metric names
        """
        raise NotImplementedError
    
    def get_metric_metadata(self, metric_name: str) -> Dict[str, Any]:
        """Get metadata for a metric.
        
        Args:
            metric_name: Name of the metric
            
        Returns:
            Dictionary of metadata
        """
        raise NotImplementedError

class FileTimeSeriesStorage(TimeSeriesStorage):
    """File-based time series storage implementation.
    
    This implementation stores time series data in a directory structure like:
    
    base_dir/
        metrics/
            metric_name1/
                YYYY/MM/DD/
                    data_<shard_id>.json.gz
            metric_name2/
                ...
    """
    
    def __init__(
        self, 
        base_dir: str,
        shard_duration: str = "1d",
        compress: bool = True,
        max_shard_size: int = 10 * 1024 * 1024,  # 10MB
        flush_interval: float = 60.0,  # seconds
        retention_period: Optional[str] = None  # e.g., "30d"
    ):
        """Initialize the file-based time series storage.
        
        Args:
            base_dir: Base directory for storing time series data
            shard_duration: Duration of each shard (e.g., "1d", "1h")
            compress: Whether to compress shard files with gzip
            max_shard_size: Maximum size of a shard file in bytes
            flush_interval: Interval for flushing in-memory buffers to disk (seconds)
            retention_period: How long to retain data (e.g., "30d", "1y")
        """
        self.base_dir = Path(base_dir)
        self.shard_duration = shard_duration
        self.compress = compress
        self.max_shard_size = max_shard_size
        self.retention_period = retention_period
        
        # In-memory buffer for writes
        self._buffers: Dict[str, List[Dict[str, Any]]] = {}
        self._buffer_lock = threading.RLock()
        
        # Background thread for flushing buffers
        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._stop_event = threading.Event()
        self._flush_interval = flush_interval
        self._flush_thread.start()
        
        # Thread pool for parallel operations
        self._thread_pool = ThreadPoolExecutor(max_workers=4)
        
        logger.info(f"Initialized FileTimeSeriesStorage at {self.base_dir}")
    
    def __del__(self):
        """Clean up resources."""
        self.close()
    
    def close(self):
        """Close the storage and flush any pending writes."""
        if hasattr(self, '_stop_event'):
            self._stop_event.set()
            if hasattr(self, '_flush_thread') and self._flush_thread.is_alive():
                self._flush_thread.join(timeout=5.0)
            
            # Flush any remaining buffers
            self._flush_buffers()
            
            if hasattr(self, '_thread_pool'):
                self._thread_pool.shutdown(wait=True)
    
    def _flush_loop(self):
        """Background thread that periodically flushes buffers to disk."""
        while not self._stop_event.is_set():
            try:
                self._stop_event.wait(self._flush_interval)
                if self._stop_event.is_set():
                    break
                    
                self._flush_buffers()
                
                # Run retention policy
                if self.retention_period:
                    self._apply_retention_policy()
                    
            except Exception as e:
                logger.error(f"Error in flush loop: {e}", exc_info=True)
                # Sleep a bit to avoid tight error loops
                time.sleep(5)
    
    def _flush_buffers(self):
        """Flush all in-memory buffers to disk."""
        with self._buffer_lock:
            if not self._buffers:
                return
                
            buffers = self._buffers
            self._buffers = {}
        
        # Process each buffer in a separate thread
        futures = []
        for shard_path, points in buffers.items():
            if not points:
                continue
                
            future = self._thread_pool.submit(
                self._write_shard, 
                shard_path=shard_path,
                points=points
            )
            futures.append(future)
        
        # Wait for all writes to complete
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"Error writing shard: {e}", exc_info=True)
    
    def _get_shard_path(
        self, 
        metric_name: str, 
        timestamp: datetime
    ) -> Tuple[Path, str]:
        """Get the file path for a shard.
        
        Args:
            metric_name: Name of the metric
            timestamp: Timestamp of the data point
            
        Returns:
            Tuple of (directory_path, shard_filename)
        """
        # Determine shard boundaries based on shard_duration
        if self.shard_duration.endswith('d'):
            days = int(self.shard_duration[:-1])
            shard_time = timestamp.replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            shard_time += timedelta(days=(timestamp - shard_time).days // days * days)
        elif self.shard_duration.endswith('h'):
            hours = int(self.shard_duration[:-1])
            shard_time = timestamp.replace(
                minute=0, second=0, microsecond=0
            )
            shard_time += timedelta(hours=((timestamp - shard_time).seconds // 3600) // hours * hours)
        else:
            raise ValueError(f"Unsupported shard duration: {self.shard_duration}")
        
        # Create directory structure: metrics/metric_name/YYYY/MM/DD
        dir_path = (
            self.base_dir / 
            "metrics" / 
            metric_name / 
            f"{shard_time.year:04d}" / 
            f"{shard_time.month:02d}" / 
            f"{shard_time.day:02d}"
        )
        
        # Create shard filename
        shard_id = f"{shard_time.strftime('%Y%m%dT%H%M%S')}_{hashlib.md5(str(shard_time.timestamp()).encode()).hexdigest()[:8]}"
        shard_filename = f"data_{shard_id}.json"
        
        if self.compress:
            shard_filename += ".gz"
        
        return dir_path, shard_filename
    
    def _write_shard(
        self, 
        shard_path: str, 
        points: List[Dict[str, Any]]
    ) -> None:
        """Write points to a shard file.
        
        Args:
            shard_path: Path to the shard file
            points: List of point dictionaries
        """
        path = Path(shard_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        # Sort points by timestamp
        points.sort(key=lambda p: p['timestamp'])
        
        # Write to file
        if self.compress:
            with gzip.open(path, 'wt', encoding='utf-8') as f:
                json.dump(points, f, indent=2, default=str)
        else:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(points, f, indent=2, default=str)
        
        logger.debug(f"Wrote {len(points)} points to {path}")
    
    def _read_shard(
        self, 
        path: Path
    ) -> List[Dict[str, Any]]:
        """Read points from a shard file.
        
        Args:
            path: Path to the shard file
            
        Returns:
            List of point dictionaries
        """
        if not path.exists():
            return []
        
        try:
            if str(path).endswith('.gz'):
                with gzip.open(path, 'rt', encoding='utf-8') as f:
                    return json.load(f)
            else:
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except (json.JSONDecodeError, gzip.BadGzipFile) as e:
            logger.error(f"Error reading shard {path}: {e}")
            return []
    
    def _apply_retention_policy(self):
        """Apply the retention policy by deleting old data."""
        if not self.retention_period:
            return
        
        try:
            cutoff_time = datetime.utcnow() - self._parse_duration(self.retention_period)
            metrics_dir = self.base_dir / "metrics"
            
            if not metrics_dir.exists():
                return
            
            # Walk through all metric directories
            for metric_dir in metrics_dir.iterdir():
                if not metric_dir.is_dir():
                    continue
                
                # Check year directories
                for year_dir in metric_dir.iterdir():
                    if not year_dir.is_dir() or not year_dir.name.isdigit():
                        continue
                    
                    year = int(year_dir.name)
                    if year < cutoff_time.year:
                        # Delete entire year directory
                        shutil.rmtree(year_dir, ignore_errors=True)
                        logger.info(f"Deleted directory {year_dir} (retention policy)")
                        continue
                    
                    # Check month directories
                    for month_dir in year_dir.iterdir():
                        if not month_dir.is_dir() or not month_dir.name.isdigit():
                            continue
                        
                        month = int(month_dir.name)
                        dir_date = datetime(year, month, 1)
                        
                        # If the entire month is before the cutoff, delete it
                        if (dir_date + timedelta(days=32)).replace(day=1) <= cutoff_time:
                            shutil.rmtree(month_dir, ignore_errors=True)
                            logger.info(f"Deleted directory {month_dir} (retention policy)")
                            continue
                        
                        # Check day directories
                        for day_dir in month_dir.iterdir():
                            if not day_dir.is_dir() or not day_dir.name.isdigit():
                                continue
                            
                            day = int(day_dir.name)
                            try:
                                dir_date = datetime(year, month, day)
                                
                                # If the day is before the cutoff, delete it
                                if dir_date.date() < cutoff_time.date():
                                    shutil.rmtree(day_dir, ignore_errors=True)
                                    logger.info(f"Deleted directory {day_dir} (retention policy)")
                                    continue
                                
                                # Check individual shard files
                                for shard_file in day_dir.glob("data_*.json*"):
                                    # Extract timestamp from filename: data_YYYYMMDDTHHMMSS_<hash>.json[.gz]
                                    try:
                                        ts_str = shard_file.stem.split('_')[1]
                                        if ts_str.endswith('.json'):
                                            ts_str = ts_str[:-5]  # Remove .json
                                        
                                        shard_time = datetime.strptime(ts_str, "%Y%m%dT%H%M%S")
                                        
                                        if shard_time < cutoff_time:
                                            shard_file.unlink(missing_ok=True)
                                            logger.debug(f"Deleted shard {shard_file} (retention policy)")
                                    except (IndexError, ValueError) as e:
                                        logger.warning(f"Invalid shard filename format: {shard_file}: {e}")
                                        continue
                                
                            except ValueError as e:
                                logger.warning(f"Invalid day directory: {day_dir}: {e}")
                                continue
        
        except Exception as e:
            logger.error(f"Error applying retention policy: {e}", exc_info=True)
    
    def _parse_duration(self, duration: str) -> timedelta:
        """Parse a duration string into a timedelta."""
        duration = duration.lower()
        
        if duration.endswith('s'):
            return timedelta(seconds=float(duration[:-1]))
        elif duration.endswith('m'):
            return timedelta(minutes=float(duration[:-1]))
        elif duration.endswith('h'):
            return timedelta(hours=float(duration[:-1]))
        elif duration.endswith('d'):
            return timedelta(days=float(duration[:-1]))
        elif duration.endswith('w'):
            return timedelta(weeks=float(duration[:-1]))
        elif duration.endswith('y'):
            return timedelta(days=float(duration[:-1]) * 365.25)  # Approximate
        else:
            raise ValueError(f"Invalid duration format: {duration}")
    
    def write_points(
        self, 
        metric_name: str, 
        points: List[TimeSeriesPoint],
        **tags
    ) -> None:
        """Write multiple data points to the storage."""
        if not points:
            return
        
        # Group points by shard
        shard_map = {}
        
        for point in points:
            # Add tags to point metadata
            point_dict = point.to_dict()
            if tags:
                point_dict['metadata'].update(tags)
            
            # Determine shard for this point
            dir_path, shard_filename = self._get_shard_path(metric_name, point.timestamp)
            shard_path = str(dir_path / shard_filename)
            
            if shard_path not in shard_map:
                shard_map[shard_path] = []
            
            shard_map[shard_path].append(point_dict)
        
        # Add to in-memory buffers
        with self._buffer_lock:
            for shard_path, shard_points in shard_map.items():
                if shard_path not in self._buffers:
                    self._buffers[shard_path] = []
                self._buffers[shard_path].extend(shard_points)
    
    def query_points(
        self,
        metric_name: str,
        time_range: Union[TimeRange, Dict[str, Any]],
        granularity: Optional[Union[str, TimeGranularity]] = None,
        aggregation: Optional[str] = None,
        **filters
    ) -> List[TimeSeriesPoint]:
        """Query time series data."""
        if isinstance(time_range, dict):
            time_range = TimeRange.from_dict(time_range)
        
        if isinstance(granularity, str):
            granularity = TimeGranularity(granularity)
        
        # Get all shards that could contain data for this time range
        shard_paths = self._find_shards(metric_name, time_range)
        
        # Read and filter points from shards
        points = []
        
        for shard_path in shard_paths:
            shard_points = self._read_shard(shard_path)
            
            for point_dict in shard_points:
                try:
                    point = TimeSeriesPoint.from_dict(point_dict)
                    
                    # Filter by time range
                    if not (time_range.start_time <= point.timestamp <= time_range.end_time):
                        continue
                    
                    # Filter by tags
                    if filters:
                        metadata = point.metadata or {}
                        if not all(
                            metadata.get(k) == v 
                            for k, v in filters.items()
                        ):
                            continue
                    
                    points.append(point)
                except (KeyError, ValueError) as e:
                    logger.warning(f"Invalid point in shard {shard_path}: {e}")
                    continue
        
        # Sort by timestamp
        points.sort(key=lambda p: p.timestamp)
        
        # Apply downsampling if requested
        if granularity is not None:
            points = self._downsample(points, granularity, aggregation)
        
        return points
    
    def _find_shards(
        self, 
        metric_name: str, 
        time_range: TimeRange
    ) -> List[Path]:
        """Find all shards that could contain data for the given time range."""
        # Get the directory for this metric
        metric_dir = self.base_dir / "metrics" / metric_name
        
        if not metric_dir.exists():
            return []
        
        # Generate all possible date paths that could contain data for the time range
        start_date = time_range.start_time.date()
        end_date = time_range.end_time.date()
        
        date = start_date
        date_dirs = []
        
        while date <= end_date:
            date_dir = (
                metric_dir / 
                f"{date.year:04d}" / 
                f"{date.month:02d}" / 
                f"{date.day:02d}"
            )
            
            if date_dir.exists():
                date_dirs.append(date_dir)
            
            date += timedelta(days=1)
        
        # Find all shard files in these directories
        shard_paths = []
        
        for date_dir in date_dirs:
            for ext in ['.json', '.json.gz']:
                shard_paths.extend(date_dir.glob(f"data_*{ext}"))
        
        return shard_paths
    
    def _downsample(
        self, 
        points: List[TimeSeriesPoint], 
        granularity: TimeGranularity,
        aggregation: Optional[str] = 'mean'
    ) -> List[TimeSeriesPoint]:
        """Downsample points to a coarser time granularity."""
        if not points:
            return []
        
        # Convert to DataFrame for easier manipulation
        df = pd.DataFrame([{
            'timestamp': p.timestamp,
            'value': p.value,
            'metadata': p.metadata
        } for p in points])
        
        # Set timestamp as index
        df = df.set_index('timestamp')
        
        # Resample to the target granularity
        if aggregation == 'sum':
            resampled = df['value'].resample(granularity.value).sum()
        elif aggregation == 'count':
            resampled = df['value'].resample(granularity.value).count()
        elif aggregation == 'max':
            resampled = df['value'].resample(granularity.value).max()
        elif aggregation == 'min':
            resampled = df['value'].resample(granularity.value).min()
        else:  # mean is default
            resampled = df['value'].resample(granularity.value).mean()
        
        # Convert back to TimeSeriesPoint objects
        result = []
        
        for timestamp, value in resampled.items():
            if pd.isna(value):
                continue
                
            result.append(TimeSeriesPoint(
                timestamp=timestamp.to_pydatetime(),
                value=float(value),
                metadata={
                    'granularity': granularity.value,
                    'aggregation': aggregation or 'mean'
                }
            ))
        
        return result
    
    def delete_points(
        self,
        metric_name: str,
        time_range: Union[TimeRange, Dict[str, Any]],
        **filters
    ) -> int:
        """Delete time series data."""
        if isinstance(time_range, dict):
            time_range = TimeRange.from_dict(time_range)
        
        # Get all shards that could contain data for this time range
        shard_paths = self._find_shards(metric_name, time_range)
        
        deleted_count = 0
        
        for shard_path in shard_paths:
            # Read existing points
            points = self._read_shard(shard_path)
            if not points:
                continue
            
            # Filter out points that match the criteria
            filtered_points = []
            
            for point_dict in points:
                try:
                    point = TimeSeriesPoint.from_dict(point_dict)
                    
                    # Check if point matches the criteria
                    if not (time_range.start_time <= point.timestamp <= time_range.end_time):
                        filtered_points.append(point_dict)
                        continue
                    
                    if filters:
                        metadata = point.metadata or {}
                        if not all(
                            metadata.get(k) == v 
                            for k, v in filters.items()
                        ):
                            filtered_points.append(point_dict)
                            continue
                    
                    # This point matches all criteria, skip it (delete it)
                    deleted_count += 1
                    
                except (KeyError, ValueError) as e:
                    logger.warning(f"Invalid point in shard {shard_path}: {e}")
                    filtered_points.append(point_dict)
                    continue
            
            # Write back the filtered points
            if filtered_points:
                self._write_shard(shard_path, filtered_points)
            else:
                # No points left in this shard, delete it
                shard_path.unlink(missing_ok=True)
        
        return deleted_count
    
    def list_metrics(self, prefix: str = "") -> List[str]:
        """List available metrics."""
        metrics_dir = self.base_dir / "metrics"
        
        if not metrics_dir.exists():
            return []
        
        metrics = []
        
        for metric_dir in metrics_dir.iterdir():
            if not metric_dir.is_dir():
                continue
            
            metric_name = metric_dir.name
            
            if prefix and not metric_name.startswith(prefix):
                continue
            
            metrics.append(metric_name)
        
        return sorted(metrics)
    
    def get_metric_metadata(self, metric_name: str) -> Dict[str, Any]:
        """Get metadata for a metric."""
        metric_dir = self.base_dir / "metrics" / metric_name
        
        if not metric_dir.exists():
            raise ValueError(f"Metric not found: {metric_name}")
        
        # Count the number of data points
        point_count = 0
        time_range = None
        
        for shard_path in metric_dir.rglob("data_*.json*"):
            try:
                points = self._read_shard(shard_path)
                point_count += len(points)
                
                if points:
                    first_point = TimeSeriesPoint.from_dict(points[0])
                    last_point = TimeSeriesPoint.from_dict(points[-1])
                    
                    if time_range is None:
                        time_range = {
                            'start_time': first_point.timestamp,
                            'end_time': last_point.timestamp
                        }
                    else:
                        if first_point.timestamp < time_range['start_time']:
                            time_range['start_time'] = first_point.timestamp
                        if last_point.timestamp > time_range['end_time']:
                            time_range['end_time'] = last_point.timestamp
            
            except Exception as e:
                logger.warning(f"Error reading shard {shard_path}: {e}")
                continue
        
        # Convert timestamps to ISO format
        if time_range:
            time_range = {
                'start_time': time_range['start_time'].isoformat(),
                'end_time': time_range['end_time'].isoformat()
            }
        
        return {
            'name': metric_name,
            'point_count': point_count,
            'time_range': time_range,
            'storage_path': str(metric_dir)
        }

# Example usage
if __name__ == "__main__":
    import tempfile
    import random
    from datetime import datetime, timedelta
    
    # Create a temporary directory for testing
    with tempfile.TemporaryDirectory() as temp_dir:
        # Initialize storage
        storage = FileTimeSeriesStorage(
            base_dir=temp_dir,
            shard_duration="1d",
            compress=True,
            retention_period="7d"
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
        
        # Flush to ensure data is written
        storage._flush_buffers()
        
        # Query data
        time_range = TimeRange(
            start_time=now - timedelta(hours=24),
            end_time=now
        )
        
        results = storage.query_points(
            metric_name="test_metric",
            time_range=time_range,
            granularity=TimeGranularity.HOUR,
            aggregation='mean',
            source='test'
        )
        
        print(f"Retrieved {len(results)} data points")
        for point in results[:5]:  # Print first 5 points
            print(f"{point.timestamp}: {point.value:.2f}")
        
        # List metrics
        print("\nAvailable metrics:")
        for metric in storage.list_metrics():
            print(f"- {metric}")
        
        # Get metric metadata
        print("\nMetric metadata:")
        print(storage.get_metric_metadata("test_metric"))
        
        # Clean up
        storage.close()
