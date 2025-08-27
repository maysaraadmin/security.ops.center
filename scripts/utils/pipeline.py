"""
Log Processing Pipeline

This module implements a flexible and scalable log processing pipeline
with support for multiple processing stages, batching, and backpressure handling.
"""

import time
import logging
import json
import gzip
import zlib
import lzma
from typing import Dict, List, Any, Optional, Callable, Tuple, Union
from queue import Queue, Empty, Full
from threading import Thread, Event, Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
import hashlib
import uuid

logger = logging.getLogger('siem.log_pipeline')

class ProcessingStage:
    """Base class for log processing stages."""
    
    def process(self, log_entry: Dict) -> Optional[Dict]:
        """Process a single log entry."""
        raise NotImplementedError
    
    def process_batch(self, log_entries: List[Dict]) -> List[Dict]:
        """Process a batch of log entries (default implementation processes one at a time)."""
        results = []
        for entry in log_entries:
            try:
                result = self.process(entry)
                if result is not None:
                    results.append(result)
            except Exception as e:
                logger.error(f"Error processing log entry: {e}", exc_info=True)
        return results
    
    def flush(self) -> List[Dict]:
        """Flush any buffered entries."""
        return []


class FieldExtractor(ProcessingStage):
    """Extract and transform fields from log entries."""
    
    def __init__(self, field_mappings: Dict[str, Union[str, Callable]]):
        """
        Initialize field extractor with field mappings.
        
        Args:
            field_mappings: Dictionary mapping output field names to either:
                           - Input field name (string)
                           - Callable that takes the log entry and returns the field value
        """
        self.field_mappings = field_mappings
    
    def process(self, log_entry: Dict) -> Dict:
        result = log_entry.copy()
        
        for output_field, mapping in self.field_mappings.items():
            try:
                if callable(mapping):
                    result[output_field] = mapping(log_entry)
                elif isinstance(mapping, str) and mapping in log_entry:
                    result[output_field] = log_entry[mapping]
            except Exception as e:
                logger.warning(f"Failed to extract field {output_field}: {e}")
        
        return result


class Enricher(ProcessingStage):
    """Enhance log entries with additional context."""
    
    def __init__(self, enrichments: Dict[str, Any]):
        """
        Initialize enricher with enrichment rules.
        
        Args:
            enrichments: Dictionary of enrichment rules
        """
        self.enrichments = enrichments
    
    def process(self, log_entry: Dict) -> Dict:
        result = log_entry.copy()
        
        for field, value in self.enrichments.items():
            if field not in result:  # Don't overwrite existing fields
                result[field] = value
        
        return result


class Filter(ProcessingStage):
    """Filter log entries based on conditions."""
    
    def __init__(self, condition: Callable[[Dict], bool], drop: bool = False):
        """
        Initialize filter with a condition function.
        
        Args:
            condition: Function that takes a log entry and returns True to keep it
            drop: If True, drop entries that match the condition instead of keeping them
        """
        self.condition = condition
        self.drop = drop
    
    def process(self, log_entry: Dict) -> Optional[Dict]:
        matches = bool(self.condition(log_entry))
        if (matches and not self.drop) or (not matches and self.drop):
            return log_entry
        return None


class BatchProcessor(ProcessingStage):
    """Process log entries in batches."""
    
    def __init__(self, batch_size: int = 100, timeout: float = 5.0):
        """
        Initialize batch processor.
        
        Args:
            batch_size: Maximum number of entries per batch
            timeout: Maximum time to wait for a batch to fill (seconds)
        """
        self.batch_size = batch_size
        self.timeout = timeout
        self.buffer: List[Dict] = []
        self.last_flush = time.time()
    
    def process(self, log_entry: Dict) -> Optional[Dict]:
        self.buffer.append(log_entry)
        
        current_time = time.time()
        if (len(self.buffer) >= self.batch_size or 
                (current_time - self.last_flush) >= self.timeout):
            return self.flush()
        
        return None
    
    def flush(self) -> List[Dict]:
        """Process and return all buffered entries."""
        if not self.buffer:
            return []
            
        results = self.process_batch(self.buffer)
        self.buffer = []
        self.last_flush = time.time()
        return results


class LogPipeline:
    """A pipeline for processing log entries through multiple stages."""
    
    def __init__(self, stages: Optional[List[ProcessingStage]] = None):
        """
        Initialize the log processing pipeline.
        
        Args:
            stages: List of processing stages to apply in order
        """
        self.stages = stages or []
        self._lock = Lock()
    
    def add_stage(self, stage: ProcessingStage) -> 'LogPipeline':
        """Add a processing stage to the pipeline."""
        with self._lock:
            self.stages.append(stage)
        return self
    
    def process(self, log_entry: Dict) -> Optional[Dict]:
        """Process a single log entry through the pipeline."""
        current = log_entry
        
        for stage in self.stages:
            if current is None:
                break
            try:
                current = stage.process(current)
            except Exception as e:
                logger.error(f"Error in pipeline stage {stage.__class__.__name__}: {e}", 
                            exc_info=True)
                return None
        
        return current
    
    def process_batch(self, log_entries: List[Dict]) -> List[Dict]:
        """Process a batch of log entries through the pipeline."""
        results = log_entries
        
        for stage in self.stages:
            if not results:
                break
                
            try:
                # Try to use batch processing if available
                if hasattr(stage, 'process_batch'):
                    results = stage.process_batch(results)
                else:
                    # Fall back to processing one at a time
                    processed = []
                    for entry in results:
                        result = stage.process(entry)
                        if result is not None:
                            processed.append(result)
                    results = processed
            except Exception as e:
                logger.error(f"Error in batch processing stage {stage.__class__.__name__}: {e}", 
                            exc_info=True)
                results = []
        
        return results
    
    def flush(self) -> List[Dict]:
        """Flush all stages and return any remaining entries."""
        results = []
        
        for stage in self.stages:
            try:
                if hasattr(stage, 'flush'):
                    flushed = stage.flush()
                    if flushed:
                        if results:
                            # Process flushed entries through remaining stages
                            remaining_stages = self.stages[self.stages.index(stage) + 1:]
                            if remaining_stages:
                                temp_pipeline = LogPipeline(remaining_stages)
                                processed = temp_pipeline.process_batch(flushed)
                                results.extend(processed)
                            else:
                                results.extend(flushed)
                        else:
                            results = flushed
            except Exception as e:
                logger.error(f"Error flushing stage {stage.__class__.__name__}: {e}", 
                            exc_info=True)
        
        return results
