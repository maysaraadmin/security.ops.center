"""
AWS CloudTrail Log Source for Enhanced Log Collector.
"""

import os
import time
import json
import gzip
import io
import logging
import boto3
from typing import Dict, List, Optional, Callable, Any, Iterator
from datetime import datetime, timedelta, timezone
from threading import Thread, Event, Lock
from queue import Queue

from ..core.enhanced_log_collector import LogSource, LogSourceType

class AWSCloudTrailSource(LogSource):
    """Log source for AWS CloudTrail logs stored in S3."""
    
    def __init__(self, source_id: str, **kwargs):
        """Initialize the AWS CloudTrail source.
        
        Args:
            source_id: Unique identifier for this source
            **kwargs: Additional configuration options
        """
        config = {
            'bucket_name': kwargs.get('bucket_name'),
            'prefix': kwargs.get('prefix', 'AWSLogs/'),
            'profile_name': kwargs.get('profile_name'),
            'region_name': kwargs.get('region_name', 'us-east-1'),
            'poll_interval': kwargs.get('poll_interval', 300),  # 5 minutes
            'start_time': kwargs.get('start_time'),  # If None, starts from now
            'account_ids': kwargs.get('account_ids', []),  # List of AWS account IDs to monitor
            'process_old_logs': kwargs.get('process_old_logs', False),
            's3_endpoint_url': kwargs.get('s3_endpoint_url'),  # For S3-compatible storage
            'max_workers': kwargs.get('max_workers', 5)
        }
        super().__init__(source_id, LogSourceType.CLOUD, config)
        
        # Initialize AWS clients
        self._init_aws_clients()
        
        # State tracking
        self._stop_event = Event()
        self._last_processed_time = self._parse_start_time(config['start_time'])
        self._processed_files = set()
        self._processed_files_lock = Lock()
        self._state_file = f'cloudtrail_state_{source_id}.json'
        self._load_state()
        
        # Thread pool for processing files
        self._executor = ThreadPoolExecutor(max_workers=config['max_workers'])
        self._file_queue = Queue(maxsize=100)
        
        # Start the file processor thread
        self._processor_thread = Thread(
            target=self._process_files_loop,
            name=f"CloudTrailProcessor-{source_id}",
            daemon=True
        )
    
    def _init_aws_clients(self):
        """Initialize AWS clients with the provided configuration."""
        session_params = {}
        if self.config['profile_name']:
            session_params['profile_name'] = self.config['profile_name']
        if self.config['region_name']:
            session_params['region_name'] = self.config['region_name']
            
        session = boto3.Session(**session_params)
        
        # Initialize S3 client
        s3_params = {}
        if self.config['s3_endpoint_url']:
            s3_params['endpoint_url'] = self.config['s3_endpoint_url']
            
        self.s3 = session.client('s3', **s3_params)
        
        # Initialize CloudTrail client for LookupEvents if needed
        self.cloudtrail = session.client('cloudtrail')
    
    def _parse_start_time(self, start_time) -> datetime:
        """Parse the start time from config."""
        if isinstance(start_time, str):
            return datetime.fromisoformat(start_time).replace(tzinfo=timezone.utc)
        elif isinstance(start_time, (int, float)):
            return datetime.fromtimestamp(start_time, tz=timezone.utc)
        elif start_time is None:
            return datetime.now(timezone.utc) - timedelta(minutes=5)  # Default: last 5 minutes
        else:
            return start_time.replace(tzinfo=timezone.utc) if start_time.tzinfo is None else start_time
    
    def start(self):
        """Start collecting AWS CloudTrail logs."""
        super().start()
        
        try:
            # Start the processor thread
            self._processor_thread.start()
            
            # Start the poller thread
            self._poller_thread = Thread(
                target=self._poll_loop,
                name=f"CloudTrailPoller-{self.source_id}",
                daemon=True
            )
            self._poller_thread.start()
            
            self.logger.info(f"Started AWS CloudTrail source for bucket: {self.config['bucket_name']}")
            
        except Exception as e:
            self.logger.error(f"Failed to start AWS CloudTrail source: {e}")
            self.stop()
    
    def stop(self):
        """Stop collecting AWS CloudTrail logs."""
        self._stop_event.set()
        
        # Save state before stopping
        self._save_state()
        
        # Shutdown the executor
        self._executor.shutdown(wait=False)
        
        super().stop()
    
    def _poll_loop(self):
        """Main loop for polling CloudTrail logs."""
        while not self._stop_event.is_set():
            try:
                self._poll_logs()
                
                # Wait for the next poll interval
                self._stop_event.wait(self.config['poll_interval'])
                
            except Exception as e:
                self.logger.error(f"Error in poll loop: {e}")
                time.sleep(60)  # Wait before retrying
    
    def _poll_logs(self):
        """Poll for new CloudTrail logs."""
        try:
            # First, check for new files in S3
            self._process_s3_logs()
            
            # Then, check for recent events using LookupEvents
            self._process_recent_events()
            
        except Exception as e:
            self.logger.error(f"Error polling CloudTrail logs: {e}")
    
    def _process_s3_logs(self):
        """Process CloudTrail logs from S3."""
        try:
            # List objects in the S3 bucket
            paginator = self.s3.get_paginator('list_objects_v2')
            
            # Build the prefix based on account IDs if specified
            prefix = self.config['prefix']
            if self.config['account_ids']:
                # If specific account IDs are provided, we need to check each one
                for account_id in self.config['account_ids']:
                    account_prefix = f"{prefix}{account_id}/"
                    self._process_s3_prefix(account_prefix)
            else:
                # Otherwise, process all accounts
                self._process_s3_prefix(prefix)
                
        except Exception as e:
            self.logger.error(f"Error processing S3 logs: {e}")
    
    def _process_s3_prefix(self, prefix: str):
        """Process objects in S3 with the given prefix."""
        paginator = self.s3.get_paginator('list_objects_v2')
        
        for page in paginator.paginate(
            Bucket=self.config['bucket_name'],
            Prefix=prefix,
            StartAfter=self._last_processed_time.strftime('%Y/%m/%d') if not self.config['process_old_logs'] else None
        ):
            if 'Contents' in page:
                for obj in page['Contents']:
                    if self._stop_event.is_set():
                        return
                        
                    # Skip if we've already processed this file
                    if obj['Key'] in self._processed_files:
                        continue
                        
                    # Check if the file is a CloudTrail log file
                    if not obj['Key'].endswith('.json.gz'):
                        continue
                        
                    # Add to processing queue
                    self._file_queue.put(obj['Key'])
                    
                    # Update last processed time
                    file_time = obj['LastModified']
                    if file_time > self._last_processed_time:
                        self._last_processed_time = file_time
    
    def _process_recent_events(self):
        """Process recent events using CloudTrail LookupEvents API."""
        try:
            # Only look back a certain amount of time to avoid duplicate events
            start_time = datetime.now(timezone.utc) - timedelta(minutes=15)
            
            # Use the LookupEvents API to get recent events
            paginator = self.cloudtrail.get_paginator('lookup_events')
            
            for page in paginator.paginate(
                LookupAttributes=[],
                StartTime=start_time,
                EndTime=datetime.now(timezone.utc),
                MaxResults=50
            ):
                if 'Events' in page:
                    for event in page['Events']:
                        if self._stop_event.is_set():
                            return
                            
                        # Process the event
                        self._process_cloudtrail_event(event)
                        
        except Exception as e:
            self.logger.error(f"Error processing recent events: {e}")
    
    def _process_files_loop(self):
        """Process files from the queue."""
        while not self._stop_event.is_set():
            try:
                key = self._file_queue.get(timeout=1.0)
                self._executor.submit(self._process_file, key)
                self._file_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error in file processor: {e}")
    
    def _process_file(self, key: str):
        """Process a single CloudTrail log file from S3."""
        try:
            # Skip if we've already processed this file
            with self._processed_files_lock:
                if key in self._processed_files:
                    return
                self._processed_files.add(key)
            
            # Download the file
            response = self.s3.get_object(
                Bucket=self.config['bucket_name'],
                Key=key
            )
            
            # Decompress the gzipped content
            with gzip.GzipFile(fileobj=response['Body']) as gz_file:
                content = gz_file.read().decode('utf-8')
                
                # Parse the JSON content (it's one JSON object per line)
                for line in content.splitlines():
                    if not line.strip():
                        continue
                        
                    try:
                        event = json.loads(line)
                        self._process_cloudtrail_event(event)
                    except json.JSONDecodeError as e:
                        self.logger.error(f"Error parsing JSON from {key}: {e}")
            
            # Save state periodically
            self._save_state()
            
        except Exception as e:
            self.logger.error(f"Error processing file {key}: {e}")
    
    def _process_cloudtrail_event(self, event: dict):
        """Process a single CloudTrail event."""
        try:
            # Standardize the event format
            if 'CloudTrailEvent' in event and isinstance(event['CloudTrailEvent'], str):
                # This is from the LookupEvents API
                event_data = json.loads(event['CloudTrailEvent'])
                event_time = event.get('EventTime', datetime.now(timezone.utc))
            else:
                # This is from S3 log files
                event_data = event
                event_time = datetime.strptime(
                    event_data.get('eventTime', ''),
                    '%Y-%m-%dT%H:%M:%SZ'
                ).replace(tzinfo=timezone.utc)
            
            # Skip if the event is too old
            if not self.config['process_old_logs'] and event_time < self._last_processed_time:
                return
            
            # Create the log entry
            entry = {
                '@timestamp': event_time.isoformat(),
                'source': self.source_id,
                'event': event_data,
                'raw': json.dumps(event_data, default=str)
            }
            
            # Notify callbacks
            self._notify_callbacks(entry)
            
        except Exception as e:
            self.logger.error(f"Error processing CloudTrail event: {e}")
    
    def _load_state(self):
        """Load the state from disk."""
        try:
            if os.path.exists(self._state_file):
                with open(self._state_file, 'r') as f:
                    state = json.load(f)
                    
                    self._last_processed_time = datetime.fromisoformat(state['last_processed_time'])
                    self._processed_files = set(state['processed_files'])
                    
                    self.logger.info(f"Loaded state from {self._state_file}")
                    
        except Exception as e:
            self.logger.error(f"Error loading state: {e}")
    
    def _save_state(self):
        """Save the state to disk."""
        try:
            with self._processed_files_lock:
                state = {
                    'last_processed_time': self._last_processed_time.isoformat(),
                    'processed_files': list(self._processed_files)
                }
                
                with open(self._state_file, 'w') as f:
                    json.dump(state, f)
                
                self.logger.debug(f"Saved state to {self._state_file}")
                
        except Exception as e:
            self.logger.error(f"Error saving state: {e}")

# Example usage
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    # Create an AWS CloudTrail source
    source = AWSCloudTrailSource(
        source_id='aws_cloudtrail',
        bucket_name='your-cloudtrail-bucket',
        profile_name='your-aws-profile',
        region_name='us-east-1',
        account_ids=['123456789012'],  # Optional: specify AWS account IDs
        poll_interval=300,  # 5 minutes
        process_old_logs=False  # Set to True to process old logs
    )
    
    # Register a callback to print events
    def print_event(entry):
        event = entry.get('event', {})
        print(f"[{entry.get('@timestamp')}] {event.get('eventName', '')} - {event.get('sourceIPAddress', '')}")
    
    source.register_callback(print_event)
    
    # Start the source
    source.start()
    
    try:
        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping AWS CloudTrail source...")
        source.stop()
