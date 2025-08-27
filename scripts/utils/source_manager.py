"""
Log Source Manager

Manages multiple log sources with load balancing and backpressure handling.
"""

import time
import logging
import threading
from typing import Dict, List, Optional, Callable, Any, Set
from queue import Queue, Empty, Full
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import random
import hashlib
import uuid

logger = logging.getLogger('siem.source_manager')

@dataclass
class SourceStats:
    """Statistics for a log source."""
    name: str
    total_events: int = 0
    processed_events: int = 0
    error_count: int = 0
    last_error: Optional[str] = None
    last_activity: Optional[datetime] = None
    bytes_processed: int = 0
    processing_time: float = 0.0

@dataclass
class SourceConfig:
    """Configuration for a log source."""
    name: str
    source_type: str
    enabled: bool = True
    priority: int = 5  # 1-10, higher is more important
    max_retries: int = 3
    retry_delay: float = 5.0  # seconds
    batch_size: int = 100
    batch_timeout: float = 5.0  # seconds
    tags: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)

class LogSourceManager:
    """Manages multiple log sources with load balancing and backpressure."""
    
    def __init__(self, max_queue_size: int = 10000, 
                 max_workers: int = 10,
                 backpressure_threshold: float = 0.9):
        """
        Initialize the log source manager.
        
        Args:
            max_queue_size: Maximum number of log entries in the processing queue
            max_workers: Maximum number of worker threads
            backpressure_threshold: Queue fill ratio (0-1) at which to apply backpressure
        """
        self.sources: Dict[str, SourceConfig] = {}
        self.stats: Dict[str, SourceStats] = {}
        self.queue = Queue(maxsize=max_queue_size)
        self.backpressure_threshold = backpressure_threshold
        self.max_workers = max_workers
        self.workers: List[threading.Thread] = []
        self.running = False
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._worker_pool = None
        self._last_balance = time.time()
        self._load_balance_interval = 30.0  # seconds
    
    def add_source(self, name: str, source_type: str, **kwargs) -> bool:
        """
        Add a new log source.
        
        Args:
            name: Unique name for the source
            source_type: Type of the source (e.g., 'file', 'syslog', 'api')
            **kwargs: Additional configuration options (see SourceConfig)
            
        Returns:
            True if the source was added, False if it already exists
        """
        with self._lock:
            if name in self.sources:
                logger.warning(f"Source '{name}' already exists")
                return False
                
            config = SourceConfig(name=name, source_type=source_type, **kwargs)
            self.sources[name] = config
            self.stats[name] = SourceStats(name=name)
            logger.info(f"Added source '{name}' of type '{source_type}'")
            return True
    
    def remove_source(self, name: str) -> bool:
        """Remove a log source."""
        with self._lock:
            if name not in self.sources:
                return False
                
            del self.sources[name]
            del self.stats[name]
            logger.info(f"Removed source '{name}'")
            return True
    
    def update_source(self, name: str, **kwargs) -> bool:
        """Update source configuration."""
        with self._lock:
            if name not in self.sources:
                logger.warning(f"Cannot update non-existent source '{name}'")
                return False
                
            config = self.sources[name]
            for key, value in kwargs.items():
                if hasattr(config, key):
                    setattr(config, key, value)
                else:
                    config.metadata[key] = value
            
            logger.info(f"Updated source '{name}' with {kwargs}")
            return True
    
    def get_source_stats(self, name: Optional[str] = None) -> Dict:
        """Get statistics for a source or all sources."""
        with self._lock:
            if name:
                return {name: self._serialize_stats(self.stats.get(name))}
            return {n: self._serialize_stats(s) for n, s in self.stats.items()}
    
    def _serialize_stats(self, stats: Optional[SourceStats]) -> Optional[Dict]:
        """Convert SourceStats to a serializable dictionary."""
        if not stats:
            return None
            
        return {
            'name': stats.name,
            'total_events': stats.total_events,
            'processed_events': stats.processed_events,
            'error_count': stats.error_count,
            'last_error': stats.last_error,
            'last_activity': stats.last_activity.isoformat() if stats.last_activity else None,
            'bytes_processed': stats.bytes_processed,
            'processing_time': stats.processing_time,
            'avg_processing_time': (
                stats.processing_time / stats.processed_events 
                if stats.processed_events > 0 else 0.0
            ),
            'queue_size': self.queue.qsize(),
            'queue_capacity': self.queue.maxsize,
            'queue_usage': self.queue.qsize() / self.queue.maxsize if self.queue.maxsize > 0 else 0.0
        }
    
    def start(self) -> None:
        """Start the source manager and worker threads."""
        if self.running:
            logger.warning("Source manager is already running")
            return
            
        self.running = True
        self._stop_event.clear()
        
        # Start worker threads
        for i in range(self.max_workers):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f'source_worker_{i}',
                daemon=True
            )
            worker.start()
            self.workers.append(worker)
        
        # Start load balancer
        self._load_balancer_thread = threading.Thread(
            target=self._load_balancer_loop,
            name='load_balancer',
            daemon=True
        )
        self._load_balancer_thread.start()
        
        logger.info(f"Started source manager with {self.max_workers} workers")
    
    def stop(self, timeout: Optional[float] = None) -> None:
        """Stop the source manager and wait for workers to finish."""
        if not self.running:
            return
            
        logger.info("Stopping source manager...")
        self.running = False
        self._stop_event.set()
        
        # Wait for workers to finish
        for worker in self.workers:
            try:
                worker.join(timeout=timeout)
            except Exception as e:
                logger.error(f"Error stopping worker: {e}")
        
        # Clear the queue
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
                self.queue.task_done()
            except Empty:
                break
        
        logger.info("Source manager stopped")
    
    def _worker_loop(self) -> None:
        """Worker thread main loop."""
        while not self._stop_event.is_set():
            try:
                # Get next batch of logs to process
                batch = self._get_next_batch()
                if not batch:
                    time.sleep(0.1)
                    continue
                
                # Process the batch
                self._process_batch(batch)
                
            except Exception as e:
                logger.error(f"Error in worker thread: {e}", exc_info=True)
                time.sleep(1)  # Prevent tight loop on errors
    
    def _get_next_batch(self) -> List[Dict]:
        """Get the next batch of logs to process."""
        batch = []
        batch_start = time.time()
        
        while len(batch) < self._get_batch_size():
            try:
                # Use a short timeout to allow batching multiple entries
                entry = self.queue.get(timeout=0.1)
                batch.append(entry)
                
                # Check if we've reached batch size or timeout
                if (len(batch) >= self._get_batch_size() or 
                        (time.time() - batch_start) >= 5.0):
                    break
                    
            except Empty:
                if batch:  # Return partial batch if we have entries
                    break
                time.sleep(0.1)
        
        return batch
    
    def _get_batch_size(self) -> int:
        """Get the target batch size, considering backpressure."""
        queue_ratio = self.queue.qsize() / self.queue.maxsize
        if queue_ratio > self.backpressure_threshold:
            # Reduce batch size under backpressure
            return max(1, int(10 * (1.0 - queue_ratio)))
        return 100  # Default batch size
    
    def _process_batch(self, batch: List[Dict]) -> None:
        """Process a batch of log entries."""
        if not batch:
            return
            
        # Group by source for batch processing
        by_source = {}
        for entry in batch:
            source = entry.get('source', 'unknown')
            if source not in by_source:
                by_source[source] = []
            by_source[source].append(entry)
        
        # Process each source's batch
        for source, entries in by_source.items():
            self._process_source_batch(source, entries)
    
    def _process_source_batch(self, source: str, entries: List[Dict]) -> None:
        """Process a batch of entries from a single source."""
        start_time = time.time()
        stats = self.stats.get(source)
        
        if not stats:
            logger.warning(f"Received logs from unknown source: {source}")
            return
            
        try:
            # Update statistics
            stats.total_events += len(entries)
            stats.processed_events += len(entries)
            stats.last_activity = datetime.utcnow()
            
            # Calculate bytes processed
            bytes_processed = sum(len(str(e).encode('utf-8')) for e in entries)
            stats.bytes_processed += bytes_processed
            
            # TODO: Process the batch (e.g., send to pipeline)
            
            # Update processing time
            stats.processing_time += (time.time() - start_time)
            
        except Exception as e:
            logger.error(f"Error processing batch from {source}: {e}", exc_info=True)
            stats.error_count += 1
            stats.last_error = str(e)
    
    def _load_balancer_loop(self) -> None:
        """Periodically balance load across sources."""
        while not self._stop_event.is_set():
            try:
                current_time = time.time()
                
                # Balance load at regular intervals
                if (current_time - self._last_balance) >= self._load_balance_interval:
                    self._balance_load()
                    self._last_balance = current_time
                
                # Sleep with small increments to be responsive to shutdown
                for _ in range(10):
                    if self._stop_event.is_set():
                        break
                    time.sleep(0.1)
                    
            except Exception as e:
                logger.error(f"Error in load balancer: {e}", exc_info=True)
                time.sleep(1)
    
    def _balance_load(self) -> None:
        """Adjust source priorities and processing based on load."""
        with self._lock:
            # Simple round-robin balancing for now
            # In a real implementation, this would consider:
            # - Source priority
            # - Processing rates
            # - Error rates
            # - Backpressure
            pass
    
    def submit_logs(self, source: str, logs: List[Dict]) -> int:
        """
        Submit logs from a source for processing.
        
        Args:
            source: Name of the source
            logs: List of log entries
            
        Returns:
            Number of logs successfully submitted
        """
        if not self.running:
            logger.warning(f"Cannot submit logs: source manager is not running")
            return 0
            
        if source not in self.sources:
            logger.warning(f"Cannot submit logs: unknown source '{source}'")
            return 0
            
        if not self.sources[source].enabled:
            logger.debug(f"Skipping logs from disabled source: {source}")
            return 0
        
        submitted = 0
        
        for log in logs:
            # Add source metadata
            log['_source'] = source
            log['_timestamp'] = datetime.utcnow().isoformat()
            log['_id'] = str(uuid.uuid4())
            
            # Apply backpressure if queue is full
            queue_ratio = self.queue.qsize() / self.queue.maxsize
            if queue_ratio > self.backpressure_threshold:
                # Apply backpressure based on source priority
                source_priority = self.sources[source].priority
                if random.random() > (1.0 / source_priority):
                    logger.warning(f"Applying backpressure to source {source} (priority: {source_priority})")
                    break
            
            try:
                self.queue.put(log, timeout=0.1)
                submitted += 1
                
                # Update statistics
                stats = self.stats[source]
                stats.total_events += 1
                stats.last_activity = datetime.utcnow()
                
            except Full:
                logger.warning(f"Queue full, dropping log from {source}")
                self.stats[source].error_count += 1
                break
            except Exception as e:
                logger.error(f"Error submitting log from {source}: {e}")
                self.stats[source].error_count += 1
                self.stats[source].last_error = str(e)
        
        return submitted
