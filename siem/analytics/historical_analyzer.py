"""
Historical data analysis and retention for SIEM.
"""
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import logging
import json
from pathlib import Path
import pandas as pd
import numpy as np
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import zstandard as zstd
import gzip
import os

class HistoricalAnalyzer:
    """
    Handles historical data analysis and retention for SIEM.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the historical analyzer."""
        self.config = config or {}
        self.logger = logging.getLogger("siem.analytics.historical")
        
        # Storage configuration
        self.data_dir = Path(self.config.get('data_dir', 'data/historical'))
        self.retention_days = int(self.config.get('retention_days', 365))
        self.compression = self.config.get('compression', 'zstd')  # 'zstd', 'gzip', or None
        
        # Create data directory if it doesn't exist
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # In-memory cache for recent data (e.g., last 24h)
        self.recent_events = defaultdict(list)
        self.cache_window_hours = 24
    
    def store_event(self, event: Dict[str, Any]) -> None:
        """
        Store an event in the historical database.
        
        Args:
            event: The event to store (must be JSON serializable)
        """
        try:
            # Add timestamp if not present
            if '@timestamp' not in event:
                event['@timestamp'] = datetime.utcnow().isoformat() + 'Z'
            
            # Add to in-memory cache
            timestamp = datetime.fromisoformat(event['@timestamp'].replace('Z', '+00:00'))
            date_key = timestamp.strftime('%Y-%m-%d')
            self.recent_events[date_key].append(event)
            
            # Periodically flush to disk
            if len(self.recent_events[date_key]) >= 1000:  # Batch size
                self._flush_to_disk(date_key)
                
        except Exception as e:
            self.logger.error(f"Error storing event: {e}", exc_info=True)
    
    def _flush_to_disk(self, date_key: str) -> None:
        """Flush in-memory events to disk."""
        if not self.recent_events[date_key]:
            return
            
        try:
            file_path = self._get_file_path(date_key)
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Convert to newline-delimited JSON
            json_data = '\n'.join(
                json.dumps(event) for event in self.recent_events[date_key]
            )
            
            # Apply compression if enabled
            if self.compression == 'zstd':
                file_path = file_path.with_suffix('.zstd')
                cctx = zstd.ZstdCompressor(level=3)
                with open(file_path, 'ab') as f:
                    f.write(cctx.compress(json_data.encode('utf-8')))
            elif self.compression == 'gzip':
                file_path = file_path.with_suffix('.gz')
                with gzip.open(file_path, 'at', encoding='utf-8') as f:
                    f.write(json_data + '\n')
            else:
                file_path = file_path.with_suffix('.jsonl')
                with open(file_path, 'a', encoding='utf-8') as f:
                    f.write(json_data + '\n')
            
            # Clear in-memory cache for this date
            self.recent_events[date_key] = []
            
        except Exception as e:
            self.logger.error(f"Error flushing events to disk: {e}", exc_info=True)
    
    def _get_file_path(self, date_str: str) -> Path:
        """Get the file path for storing events of a specific date."""
        year, month, day = date_str.split('-')
        return self.data_dir / year / month / f"events_{date_str}"
    
    def query_events(self, start_time: datetime, end_time: datetime, 
                    filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Query historical events within a time range.
        
        Args:
            start_time: Start of time range (inclusive)
            end_time: End of time range (inclusive)
            filters: Dictionary of field-value pairs to filter by
            
        Returns:
            List of matching events
        """
        results = []
        current = start_time.date()
        end_date = end_time.date()
        
        while current <= end_date:
            date_key = current.strftime('%Y-%m-%d')
            
            # Check in-memory cache first
            if date_key in self.recent_events:
                date_events = self.recent_events[date_key]
            else:
                # Load from disk if not in cache
                date_events = self._load_events_for_date(date_key)
            
            # Filter events by time and other criteria
            for event in date_events:
                event_time = datetime.fromisoformat(event['@timestamp'].replace('Z', '+00:00'))
                if start_time <= event_time <= end_time:
                    if self._matches_filters(event, filters):
                        results.append(event)
            
            current += timedelta(days=1)
        
        return results
    
    def _load_events_for_date(self, date_str: str) -> List[Dict[str, Any]]:
        """Load events for a specific date from disk."""
        file_path = self._get_file_path(date_str)
        
        # Try different compression extensions
        for ext in ['.zstd', '.gz', '.jsonl']:
            test_path = file_path.with_suffix(ext)
            if test_path.exists():
                try:
                    if ext == '.zstd':
                        cctx = zstd.ZstdDecompressor()
                        with open(test_path, 'rb') as f:
                            data = cctx.decompress(f.read()).decode('utf-8')
                    elif ext == '.gz':
                        with gzip.open(test_path, 'rt', encoding='utf-8') as f:
                            data = f.read()
                    else:
                        with open(test_path, 'r', encoding='utf-8') as f:
                            data = f.read()
                    
                    return [json.loads(line) for line in data.strip().split('\n') if line]
                except Exception as e:
                    self.logger.error(f"Error loading {test_path}: {e}")
                    return []
        
        return []
    
    def _matches_filters(self, event: Dict[str, Any], filters: Optional[Dict[str, Any]]) -> bool:
        """Check if an event matches all the given filters."""
        if not filters:
            return True
            
        for field, value in filters.items():
            # Support nested fields with dot notation (e.g., 'source.ip')
            current = event
            for part in field.split('.'):
                if part not in current:
                    return False
                current = current[part]
            
            if current != value:
                return False
                
        return True
    
    def run_retention_policy(self) -> None:
        """Apply retention policy to delete old data."""
        cutoff_date = datetime.utcnow() - timedelta(days=self.retention_days)
        cutoff_date = cutoff_date.replace(hour=0, minute=0, second=0, microsecond=0)
        
        for year_dir in self.data_dir.glob('*'):
            if not year_dir.is_dir():
                continue
                
            for month_dir in year_dir.glob('*'):
                if not month_dir.is_dir():
                    continue
                    
                for file_path in month_dir.glob('*'):
                    try:
                        # Extract date from filename (format: events_YYYY-MM-DD)
                        date_str = file_path.stem.split('_')[-1]
                        file_date = datetime.strptime(date_str, '%Y-%m-%d')
                        
                        if file_date < cutoff_date:
                            file_path.unlink()
                            self.logger.info(f"Deleted old data file: {file_path}")
                            
                    except (ValueError, IndexError) as e:
                        self.logger.warning(f"Unexpected file format: {file_path}")
                    except Exception as e:
                        self.logger.error(f"Error processing {file_path}: {e}")
        
        # Clean up empty directories
        self._cleanup_empty_dirs()
    
    def _cleanup_empty_dirs(self) -> None:
        """Recursively remove empty directories."""
        for root, dirs, files in os.walk(self.data_dir, topdown=False):
            for dir_name in dirs:
                dir_path = Path(root) / dir_name
                try:
                    if not any(dir_path.iterdir()):
                        dir_path.rmdir()
                except OSError:
                    pass  # Directory not empty or permission denied
    
    def get_anomaly_scores(self, time_window: str = '1d') -> Dict[str, float]:
        """
        Calculate anomaly scores for different event types over a time window.
        
        Args:
            time_window: Time window to analyze (e.g., '1d', '7d', '30d')
            
        Returns:
            Dictionary mapping event types to anomaly scores (0-1)
        """
        # This is a simplified example - implement your own anomaly detection logic
        end_time = datetime.utcnow()
        start_time = end_time - self._parse_time_window(time_window)
        
        # Get event counts by type
        event_counts = defaultdict(int)
        for event in self.query_events(start_time, end_time):
            event_type = event.get('event', {}).get('type', 'unknown')
            event_counts[event_type] += 1
        
        # Simple anomaly detection: compare to historical baseline
        # In a real implementation, you'd use more sophisticated statistical methods
        total_events = sum(event_counts.values())
        anomaly_scores = {}
        
        for event_type, count in event_counts.items():
            # Simple ratio of this event type to total events
            ratio = count / total_events if total_events > 0 else 0
            
            # Compare to historical baseline (simplified)
            baseline_ratio = 0.1  # This would come from historical analysis
            score = min(1.0, ratio / baseline_ratio) if baseline_ratio > 0 else 0
            
            anomaly_scores[event_type] = round(score, 2)
        
        return anomaly_scores
    
    def _parse_time_window(self, time_window: str) -> timedelta:
        """Parse a time window string into a timedelta."""
        unit = time_window[-1].lower()
        value = int(time_window[:-1])
        
        if unit == 'm':
            return timedelta(minutes=value)
        elif unit == 'h':
            return timedelta(hours=value)
        elif unit == 'd':
            return timedelta(days=value)
        elif unit == 'w':
            return timedelta(weeks=value)
        else:
            raise ValueError(f"Unknown time unit: {unit}")
    
    def generate_trend_report(self, metric: str, time_window: str = '30d') -> Dict[str, Any]:
        """
        Generate a trend report for a specific metric over time.
        
        Args:
            metric: The metric to analyze (e.g., 'login.failed', 'alert.severity')
            time_window: Time window to analyze (e.g., '7d', '30d')
            
        Returns:
            Dictionary containing trend data
        """
        end_time = datetime.utcnow()
        start_time = end_time - self._parse_time_window(time_window)
        
        # Group events by day
        daily_counts = defaultdict(int)
        for event in self.query_events(start_time, end_time):
            # Extract the metric value (supports nested fields with dot notation)
            value = event
            for part in metric.split('.'):
                if not isinstance(value, dict) or part not in value:
                    value = None
                    break
                value = value[part]
            
            if value is not None:
                event_time = datetime.fromisoformat(event['@timestamp'].replace('Z', '+00:00'))
                day_key = event_time.strftime('%Y-%m-%d')
                daily_counts[day_key] += 1
        
        # Convert to sorted list of dates and counts
        dates = []
        counts = []
        current = start_time.date()
        
        while current <= end_time.date():
            day_key = current.strftime('%Y-%m-%d')
            dates.append(day_key)
            counts.append(daily_counts.get(day_key, 0))
            current += timedelta(days=1)
        
        return {
            'metric': metric,
            'time_window': time_window,
            'start_date': start_time.isoformat(),
            'end_date': end_time.isoformat(),
            'data': {
                'dates': dates,
                'counts': counts
            },
            'stats': {
                'total': sum(counts),
                'avg_per_day': round(sum(counts) / len(counts), 2) if counts else 0,
                'max_per_day': max(counts) if counts else 0,
                'min_per_day': min(counts) if counts else 0
            }
        }
