"""
Tiered storage management for historical data with lifecycle policies.
"""
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
import logging
import shutil
import json
from typing import Dict, List, Optional, Any, Iterator
import zstandard as zstd
import gzip
import hashlib
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

class StorageTier(Enum):
    """Storage tiers with different performance characteristics."""
    HOT = "hot"      # Fast storage (SSD), recent data
    WARM = "warm"    # Balanced storage, mid-term data
    COLD = "cold"    # Slow storage (HDD/object), long-term data
    ARCHIVE = "archive"  # Very slow storage (tape/glacier), archival data

class RetentionPolicy:
    """Defines retention policies for different data types."""
    
    def __init__(
        self,
        hot_days: int = 7,
        warm_days: int = 30,
        cold_days: int = 365,
        archive_days: int = 3650,
        compression: str = 'zstd',
        encryption_key: Optional[bytes] = None
    ):
        """Initialize retention policy.
        
        Args:
            hot_days: Days to keep data in hot storage
            warm_days: Days to keep data in warm storage
            cold_days: Days to keep data in cold storage
            archive_days: Days to keep data in archive
            compression: Compression algorithm ('zstd', 'gzip', None)
            encryption_key: Optional encryption key
        """
        self.hot_days = hot_days
        self.warm_days = warm_days
        self.cold_days = cold_days
        self.archive_days = archive_days
        self.compression = compression
        self.encryption_key = encryption_key
        
        # Validate retention periods
        if not (hot_days <= warm_days <= cold_days <= archive_days):
            raise ValueError("Retention periods must be in ascending order")

class DataChunk:
    """Represents a chunk of data with metadata."""
    
    def __init__(
        self,
        data: bytes,
        data_type: str,
        timestamp: datetime,
        retention_policy: RetentionPolicy
    ):
        """Initialize a data chunk."""
        self.data = data
        self.data_type = data_type
        self.timestamp = timestamp
        self.retention_policy = retention_policy
        self.size = len(data)
        self.checksum = self._calculate_checksum()
        
    def _calculate_checksum(self) -> str:
        """Calculate checksum of the data."""
        return hashlib.sha256(self.data).hexdigest()
    
    def compress(self) -> None:
        """Compress the data according to the retention policy."""
        if self.retention_policy.compression == 'zstd':
            cctx = zstd.ZstdCompressor(level=3)
            self.data = cctx.compress(self.data)
        elif self.retention_policy.compression == 'gzip':
            self.data = gzip.compress(self.data)
    
    def decompress(self) -> None:
        """Decompress the data."""
        if self.retention_policy.compression == 'zstd':
            dctx = zstd.ZstdDecompressor()
            self.data = dctx.decompress(self.data)
        elif self.retention_policy.compression == 'gzip':
            self.data = gzip.decompress(self.data)
    
    def verify_integrity(self) -> bool:
        """Verify data integrity using checksum."""
        return self.checksum == self._calculate_checksum()

class TieredStorageManager:
    """Manages tiered storage for historical data."""
    
    def __init__(
        self,
        base_path: str,
        policies: Dict[str, RetentionPolicy],
        max_workers: int = 4
    ):
        """Initialize the tiered storage manager.
        
        Args:
            base_path: Base directory for all storage tiers
            policies: Dictionary mapping data types to retention policies
            max_workers: Maximum number of worker threads for background tasks
        """
        self.base_path = Path(base_path)
        self.policies = policies
        self.max_workers = max_workers
        self.logger = logging.getLogger("siem.storage.tiered")
        
        # Create base directories if they don't exist
        for tier in StorageTier:
            (self.base_path / tier.value).mkdir(parents=True, exist_ok=True)
    
    def store_chunk(self, chunk: DataChunk) -> str:
        """Store a data chunk in the appropriate tier.
        
        Args:
            chunk: DataChunk to store
            
        Returns:
            Path to the stored chunk
        """
        # Determine the appropriate tier based on age
        tier = self._get_tier_for_chunk(chunk)
        chunk_path = self._get_chunk_path(chunk, tier)
        
        # Ensure directory exists
        chunk_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Compress if needed
        if chunk.retention_policy.compression:
            chunk.compress()
        
        # Write the chunk
        with open(chunk_path, 'wb') as f:
            f.write(chunk.data)
        
        # Write metadata
        metadata = {
            'data_type': chunk.data_type,
            'timestamp': chunk.timestamp.isoformat(),
            'size': chunk.size,
            'compression': chunk.retention_policy.compression,
            'checksum': chunk.checksum,
            'tier': tier.value
        }
        with open(f"{chunk_path}.meta", 'w') as f:
            json.dump(metadata, f)
        
        return str(chunk_path)
    
    def retrieve_chunk(self, chunk_path: str) -> Optional[DataChunk]:
        """Retrieve a data chunk.
        
        Args:
            chunk_path: Path to the chunk
            
        Returns:
            DataChunk if found and valid, None otherwise
        """
        chunk_path = Path(chunk_path)
        meta_path = chunk_path.with_suffix(chunk_path.suffix + '.meta')
        
        if not (chunk_path.exists() and meta_path.exists()):
            return None
        
        # Load metadata
        with open(meta_path) as f:
            metadata = json.load(f)
        
        # Read data
        with open(chunk_path, 'rb') as f:
            data = f.read()
        
        # Create chunk
        chunk = DataChunk(
            data=data,
            data_type=metadata['data_type'],
            timestamp=datetime.fromisoformat(metadata['timestamp']),
            retention_policy=self.policies.get(metadata['data_type']) or RetentionPolicy()
        )
        
        # Verify integrity
        if not chunk.verify_integrity():
            self.logger.error(f"Checksum mismatch for chunk {chunk_path}")
            return None
        
        # Decompress if needed
        if chunk.retention_policy.compression:
            chunk.decompress()
        
        return chunk
    
    def manage_lifecycle(self) -> Dict[str, int]:
        """Manage data lifecycle across all tiers.
        
        Returns:
            Dictionary with count of processed items per action
        """
        stats = {'moved': 0, 'deleted': 0, 'errors': 0}
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            # Process each tier except archive
            for tier in [t for t in StorageTier if t != StorageTier.ARCHIVE]:
                tier_path = self.base_path / tier.value
                if not tier_path.exists():
                    continue
                    
                for data_type in self.policies.keys():
                    type_path = tier_path / data_type
                    if not type_path.exists():
                        continue
                        
                    for chunk_file in type_path.glob('*.bin'):
                        futures.append(executor.submit(
                            self._process_chunk_lifecycle,
                            chunk_file,
                            tier
                        ))
            
            # Process results
            for future in as_completed(futures):
                try:
                    result = future.result()
                    stats[result] = stats.get(result, 0) + 1
                except Exception as e:
                    self.logger.error(f"Error processing chunk: {e}")
                    stats['errors'] += 1
        
        return stats
    
    def _process_chunk_lifecycle(self, chunk_path: Path, current_tier: StorageTier) -> str:
        """Process a single chunk's lifecycle."""
        try:
            # Load metadata
            meta_path = chunk_path.with_suffix(chunk_path.suffix + '.meta')
            with open(meta_path) as f:
                metadata = json.load(f)
            
            # Skip if already in the right tier
            if metadata.get('tier') == current_tier.value:
                return 'skipped'
            
            # Get the appropriate tier based on age
            timestamp = datetime.fromisoformat(metadata['timestamp'])
            age_days = (datetime.utcnow() - timestamp).days
            
            policy = self.policies.get(metadata['data_type']) or RetentionPolicy()
            target_tier = self._get_tier_for_age(age_days, policy)
            
            # If already in the right tier, update metadata and return
            if target_tier == current_tier:
                metadata['tier'] = target_tier.value
                with open(meta_path, 'w') as f:
                    json.dump(metadata, f)
                return 'skipped'
            
            # Move to target tier
            target_path = self._get_chunk_path(
                DataChunk(
                    data=b'',  # Dummy data, we're just moving the file
                    data_type=metadata['data_type'],
                    timestamp=timestamp,
                    retention_policy=policy
                ),
                target_tier
            )
            
            # Ensure target directory exists
            target_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Move the chunk and its metadata
            shutil.move(str(chunk_path), str(target_path))
            shutil.move(
                str(meta_path),
                str(target_path.with_suffix(target_path.suffix + '.meta'))
            )
            
            return 'moved'
            
        except Exception as e:
            self.logger.error(f"Error processing {chunk_path}: {e}")
            return 'error'
    
    def _get_tier_for_chunk(self, chunk: DataChunk) -> StorageTier:
        """Determine the appropriate tier for a chunk."""
        age = (datetime.utcnow() - chunk.timestamp).days
        return self._get_tier_for_age(age, chunk.retention_policy)
    
    def _get_tier_for_age(self, age_days: int, policy: RetentionPolicy) -> StorageTier:
        """Determine the appropriate tier based on age."""
        if age_days <= policy.hot_days:
            return StorageTier.HOT
        elif age_days <= policy.warm_days:
            return StorageTier.WARM
        elif age_days <= policy.cold_days:
            return StorageTier.COLD
        else:
            return StorageTier.ARCHIVE
    
    def _get_chunk_path(self, chunk: DataChunk, tier: StorageTier) -> Path:
        """Generate a path for a chunk in the given tier."""
        # Format: <base>/<tier>/<data_type>/<year>/<month>/<day>/<timestamp>_<hash>.<ext>
        ext = {
            'zstd': '.zst',
            'gzip': '.gz',
            None: '.bin'
        }.get(chunk.retention_policy.compression, '.bin')
        
        timestamp_str = chunk.timestamp.strftime('%Y%m%d_%H%M%S')
        chunk_hash = chunk.checksum[:8]  # Use first 8 chars of checksum for filename
        
        return (
            self.base_path / 
            tier.value / 
            chunk.data_type / 
            str(chunk.timestamp.year) / 
            f"{chunk.timestamp.month:02d}" /
            f"{chunk.timestamp.day:02d}" /
            f"{timestamp_str}_{chunk_hash}{ext}"
        )
    
    def cleanup_expired(self) -> Dict[str, int]:
        """Clean up expired data based on retention policies.
        
        Returns:
            Dictionary with count of deleted items per data type
        """
        stats = {}
        now = datetime.utcnow()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for data_type, policy in self.policies.items():
                for tier in StorageTier:
                    type_path = self.base_path / tier.value / data_type
                    if not type_path.exists():
                        continue
                    
                    for root, _, files in os.walk(type_path):
                        for file in files:
                            if file.endswith('.meta'):
                                meta_path = Path(root) / file
                                futures.append(executor.submit(
                                    self._process_expired_chunk,
                                    meta_path,
                                    policy,
                                    now
                                ))
            
            # Process results
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        data_type, action = result
                        key = f"{data_type}_{action}"
                        stats[key] = stats.get(key, 0) + 1
                except Exception as e:
                    self.logger.error(f"Error processing expired chunk: {e}")
                    stats['errors'] = stats.get('errors', 0) + 1
        
        return stats
    
    def _process_expired_chunk(
        self,
        meta_path: Path,
        policy: RetentionPolicy,
        now: datetime
    ) -> Optional[tuple]:
        """Process a single chunk for expiration."""
        try:
            # Load metadata
            with open(meta_path) as f:
                metadata = json.load(f)
            
            # Skip if not a metadata file
            if not isinstance(metadata, dict) or 'timestamp' not in metadata:
                return None
            
            # Calculate age
            timestamp = datetime.fromisoformat(metadata['timestamp'])
            age_days = (now - timestamp).days
            
            # Check if expired
            max_age = policy.archive_days if metadata.get('tier') == StorageTier.ARCHIVE.value else policy.cold_days
            
            if age_days > max_age:
                # Delete the chunk and its metadata
                chunk_path = meta_path.with_suffix('')
                if chunk_path.exists():
                    chunk_path.unlink()
                meta_path.unlink()
                
                # Try to remove empty directories
                try:
                    meta_path.parent.rmdir()  # day
                    meta_path.parent.parent.rmdir()  # month
                    meta_path.parent.parent.parent.rmdir()  # year
                    meta_path.parent.parent.parent.parent.rmdir()  # data_type
                except OSError:
                    pass  # Directory not empty
                
                return (metadata.get('data_type', 'unknown'), 'deleted')
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error processing {meta_path}: {e}")
            return ('error', str(e))
