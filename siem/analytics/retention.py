"""
Data Retention and Archiving Module

This module handles data retention policies, archiving, and cleanup for time-series data.
"""
import os
import logging
import shutil
import gzip
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Local imports
from .timeseries import TimeRange, FileTimeSeriesStorage

logger = logging.getLogger(__name__)

class RetentionPolicy:
    """Defines a data retention policy for time-series data."""
    
    def __init__(
        self,
        name: str,
        metric_pattern: str,
        retention_period: str,
        archive: bool = False,
        archive_format: str = "parquet",  # or "csv", "json"
        archive_location: Optional[str] = None,
        compression: str = "gzip",
        enabled: bool = True
    ):
        """Initialize a retention policy.
        
        Args:
            name: Name of the retention policy
            metric_pattern: Pattern to match metric names (supports glob)
            retention_period: How long to retain data (e.g., "30d", "1y")
            archive: Whether to archive data before deletion
            archive_format: Format for archived data (parquet, csv, json)
            archive_location: Where to store archives (default: <storage>/archives)
            compression: Compression format for archives (gzip, bz2, xz, none)
            enabled: Whether this policy is enabled
        """
        self.name = name
        self.metric_pattern = metric_pattern
        self.retention_period = retention_period
        self.archive = archive
        self.archive_format = archive_format.lower()
        self.archive_location = archive_location
        self.compression = compression.lower()
        self.enabled = enabled
        self.last_run: Optional[datetime] = None
        self.next_run: Optional[datetime] = None
        self._lock = threading.RLock()
        
        # Validate archive format
        if self.archive_format not in ("parquet", "csv", "json"):
            raise ValueError(f"Unsupported archive format: {self.archive_format}")
        
        # Validate compression
        if self.compression not in ("gzip", "bz2", "xz", "none"):
            raise ValueError(f"Unsupported compression format: {self.compression}")
        
        # Calculate next run time (run daily by default)
        self._update_next_run()
    
    def _update_next_run(self) -> None:
        """Update the next run time for this policy."""
        now = datetime.utcnow()
        self.last_run = now
        
        # Default to running once per day
        self.next_run = now + timedelta(days=1)
    
    def should_run(self) -> bool:
        """Check if this policy should run now."""
        if not self.enabled:
            return False
            
        if self.next_run is None:
            return True
            
        return datetime.utcnow() >= self.next_run
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert policy to a dictionary."""
        return {
            'name': self.name,
            'metric_pattern': self.metric_pattern,
            'retention_period': self.retention_period,
            'archive': self.archive,
            'archive_format': self.archive_format,
            'archive_location': self.archive_location,
            'compression': self.compression,
            'enabled': self.enabled,
            'last_run': self.last_run.isoformat() if self.last_run else None,
            'next_run': self.next_run.isoformat() if self.next_run else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RetentionPolicy':
        """Create a policy from a dictionary."""
        policy = cls(
            name=data['name'],
            metric_pattern=data['metric_pattern'],
            retention_period=data['retention_period'],
            archive=data.get('archive', False),
            archive_format=data.get('archive_format', 'parquet'),
            archive_location=data.get('archive_location'),
            compression=data.get('compression', 'gzip'),
            enabled=data.get('enabled', True)
        )
        
        if 'last_run' in data and data['last_run']:
            policy.last_run = datetime.fromisoformat(data['last_run'])
        if 'next_run' in data and data['next_run']:
            policy.next_run = datetime.fromisoformat(data['next_run'])
        
        return policy

class RetentionManager:
    """Manages data retention policies for time-series data."""
    
    def __init__(
        self,
        storage: FileTimeSeriesStorage,
        config_dir: Optional[str] = None,
        check_interval: int = 3600,  # seconds
        max_workers: int = 4
    ):
        """Initialize the retention manager.
        
        Args:
            storage: TimeSeriesStorage instance
            config_dir: Directory to store policy configurations (default: <storage>/retention)
            check_interval: How often to check for policies that need to run (seconds)
            max_workers: Maximum number of worker threads for parallel processing
        """
        self.storage = storage
        self.config_dir = Path(config_dir) if config_dir else Path(storage.base_dir) / "retention"
        self.check_interval = check_interval
        self.max_workers = max_workers
        
        self.policies: Dict[str, RetentionPolicy] = {}
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._thread_pool = ThreadPoolExecutor(max_workers=max_workers)
        
        # Create config directory if it doesn't exist
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Load existing policies
        self._load_policies()
    
    def start(self) -> None:
        """Start the retention manager background thread."""
        if self._thread and self._thread.is_alive():
            logger.warning("Retention manager is already running")
            return
        
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="RetentionManager",
            daemon=True
        )
        self._thread.start()
        logger.info("Retention manager started")
    
    def stop(self) -> None:
        """Stop the retention manager."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)
        
        self._thread_pool.shutdown(wait=True)
        logger.info("Retention manager stopped")
    
    def _run_loop(self) -> None:
        """Main loop for the retention manager."""
        logger.info("Retention manager started")
        
        while not self._stop_event.is_set():
            try:
                self._check_policies()
                
                # Sleep, but check for stop event frequently
                for _ in range(self.check_interval):
                    if self._stop_event.is_set():
                        break
                    time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error in retention manager: {e}", exc_info=True)
                time.sleep(60)  # Avoid tight error loops
    
    def _load_policies(self) -> None:
        """Load policies from the config directory."""
        self.policies = {}
        
        for policy_file in self.config_dir.glob("*.json"):
            try:
                with open(policy_file, 'r') as f:
                    policy_data = json.load(f)
                
                policy = RetentionPolicy.from_dict(policy_data)
                self.policies[policy.name] = policy
                
                logger.info(f"Loaded retention policy: {policy.name}")
                
            except Exception as e:
                logger.error(f"Error loading policy from {policy_file}: {e}")
    
    def _save_policy(self, policy: RetentionPolicy) -> None:
        """Save a policy to disk."""
        policy_file = self.config_dir / f"{policy.name}.json"
        
        try:
            with open(policy_file, 'w') as f:
                json.dump(policy.to_dict(), f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error saving policy {policy.name}: {e}")
    
    def add_policy(self, policy: RetentionPolicy) -> None:
        """Add or update a retention policy."""
        with self._thread_pool._lock:
            self.policies[policy.name] = policy
            self._save_policy(policy)
        
        logger.info(f"Added/updated retention policy: {policy.name}")
    
    def remove_policy(self, name: str) -> bool:
        """Remove a retention policy by name."""
        with self._thread_pool._lock:
            if name not in self.policies:
                return False
            
            # Delete the policy file
            policy_file = self.config_dir / f"{name}.json"
            if policy_file.exists():
                try:
                    policy_file.unlink()
                except Exception as e:
                    logger.error(f"Error deleting policy file {policy_file}: {e}")
            
            # Remove from memory
            del self.policies[name]
            
            logger.info(f"Removed retention policy: {name}")
            return True
    
    def _check_policies(self) -> None:
        """Check which policies need to run and execute them."""
        policies_to_run = []
        
        with self._thread_pool._lock:
            for policy in self.policies.values():
                if policy.should_run():
                    policies_to_run.append(policy)
        
        # Execute policies in parallel
        futures = []
        
        for policy in policies_to_run:
            future = self._thread_pool.submit(self._execute_policy, policy)
            futures.append(future)
        
        # Wait for all policies to complete
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"Error executing policy: {e}", exc_info=True)
    
    def _execute_policy(self, policy: RetentionPolicy) -> None:
        """Execute a retention policy."""
        logger.info(f"Executing retention policy: {policy.name}")
        
        try:
            # Calculate cutoff time
            cutoff_time = datetime.utcnow() - self._parse_duration(policy.retention_period)
            
            # Find metrics that match the pattern
            matching_metrics = [
                metric for metric in self.storage.list_metrics()
                if self._match_pattern(metric, policy.metric_pattern)
            ]
            
            if not matching_metrics:
                logger.info(f"No metrics match pattern: {policy.metric_pattern}")
                return
            
            logger.info(f"Found {len(matching_metrics)} metrics matching pattern: {policy.metric_pattern}")
            
            # Process each matching metric
            for metric in matching_metrics:
                try:
                    self._process_metric(metric, policy, cutoff_time)
                except Exception as e:
                    logger.error(f"Error processing metric {metric}: {e}", exc_info=True)
            
            # Update last run time
            policy._update_next_run()
            self._save_policy(policy)
            
            logger.info(f"Completed retention policy: {policy.name}")
            
        except Exception as e:
            logger.error(f"Error executing policy {policy.name}: {e}", exc_info=True)
    
    def _process_metric(
        self, 
        metric: str, 
        policy: RetentionPolicy, 
        cutoff_time: datetime
    ) -> None:
        """Process a single metric according to the retention policy."""
        logger.info(f"Processing metric: {metric} (cutoff: {cutoff_time.isoformat()})")
        
        # Get time range for data to be processed
        time_range = TimeRange(
            start_time=datetime.min.replace(tzinfo=cutoff_time.tzinfo),
            end_time=cutoff_time
        )
        
        # Archive data if enabled
        if policy.archive:
            try:
                self._archive_metric(metric, time_range, policy)
            except Exception as e:
                logger.error(f"Error archiving metric {metric}: {e}", exc_info=True)
                if policy.archive:
                    # If archiving is required, don't delete the data
                    return
        
        # Delete old data
        try:
            deleted_count = self.storage.delete_points(
                metric_name=metric,
                time_range=time_range
            )
            
            logger.info(f"Deleted {deleted_count} data points for metric: {metric}")
            
        except Exception as e:
            logger.error(f"Error deleting data for metric {metric}: {e}", exc_info=True)
    
    def _archive_metric(
        self, 
        metric: str, 
        time_range: TimeRange,
        policy: RetentionPolicy
    ) -> None:
        """Archive data for a metric."""
        logger.info(f"Archiving metric: {metric} ({time_range.start_time} to {time_range.end_time})")
        
        # Determine archive location
        if policy.archive_location:
            archive_dir = Path(policy.archive_location) / metric.replace('.', '/')
        else:
            archive_dir = Path(self.storage.base_dir) / "archives" / metric.replace('.', '/')
        
        archive_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate archive filename
        start_str = time_range.start_time.strftime("%Y%m%d")
        end_str = time_range.end_time.strftime("%Y%m%d")
        archive_file = archive_dir / f"{start_str}_{end_str}.{policy.archive_format}"
        
        if policy.compression != 'none':
            archive_file = archive_file.with_suffix(f".{policy.archive_format}.{policy.compression}")
        
        # Check if archive already exists
        if archive_file.exists():
            logger.info(f"Archive already exists: {archive_file}")
            return
        
        # Query the data to be archived
        points = self.storage.query_points(
            metric_name=metric,
            time_range=time_range,
            granularity=None  # Get raw data
        )
        
        if not points:
            logger.info(f"No data to archive for metric: {metric}")
            return
        
        logger.info(f"Archiving {len(points)} data points to {archive_file}")
        
        # Convert to DataFrame for easier serialization
        import pandas as pd
        
        df = pd.DataFrame([{
            'timestamp': p.timestamp,
            'value': p.value,
            **p.metadata
        } for p in points])
        
        # Write to archive file
        archive_file.parent.mkdir(parents=True, exist_ok=True)
        
        if policy.archive_format == 'parquet':
            df.to_parquet(archive_file, compression=policy.compression if policy.compression != 'none' else None)
        elif policy.archive_format == 'csv':
            if policy.compression == 'gzip':
                df.to_csv(archive_file, index=False, compression='gzip')
            elif policy.compression == 'bz2':
                df.to_csv(archive_file, index=False, compression='bz2')
            elif policy.compression == 'xz':
                df.to_csv(archive_file, index=False, compression='xz')
            else:
                df.to_csv(archive_file, index=False)
        elif policy.archive_format == 'json':
            if policy.compression == 'gzip':
                with gzip.open(archive_file, 'wt', encoding='utf-8') as f:
                    df.to_json(f, orient='records', lines=True)
            else:
                df.to_json(archive_file, orient='records', lines=True, compression=policy.compression if policy.compression != 'none' else None)
        
        logger.info(f"Archived {len(points)} data points to {archive_file}")
    
    @staticmethod
    def _match_pattern(name: str, pattern: str) -> bool:
        """Check if a name matches a pattern (supports glob)."""
        from fnmatch import fnmatch
        return fnmatch(name, pattern)
    
    @staticmethod
    def _parse_duration(duration: str) -> timedelta:
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

# Example usage
if __name__ == "__main__":
    import tempfile
    import time
    
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
        
        # Initialize retention manager
        retention = RetentionManager(
            storage=storage,
            config_dir=os.path.join(temp_dir, "retention_config"),
            check_interval=5,  # seconds for testing
            max_workers=2
        )
        
        # Add a sample retention policy
        policy = RetentionPolicy(
            name="30_day_retention",
            metric_pattern="*",  # Match all metrics
            retention_period="30d",
            archive=True,
            archive_format="parquet",
            compression="gzip"
        )
        
        retention.add_policy(policy)
        
        # Start the retention manager
        retention.start()
        
        try:
            print("Retention manager started. Press Ctrl+C to stop.")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping retention manager...")
        finally:
            retention.stop()
            print("Done.")
