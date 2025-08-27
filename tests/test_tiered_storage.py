"""
Tests for the tiered storage system.
"""
import os
import sys
import pytest
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from siem.storage.tiered_storage import (
    TieredStorageManager,
    StorageTier,
    RetentionPolicy,
    DataChunk
)

@pytest.fixture
def temp_storage():
    """Create a temporary storage directory for testing."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)

@pytest.fixture
def sample_policies():
    """Return sample retention policies for testing."""
    return {
        'test_data': RetentionPolicy(
            hot_days=1,
            warm_days=3,
            cold_days=7,
            archive_days=30,
            compression='zstd'
        )
    }

def test_storage_initialization(temp_storage, sample_policies):
    """Test that storage manager initializes correctly."""
    storage = TieredStorageManager(temp_storage, sample_policies)
    
    # Check that all tier directories were created
    for tier in StorageTier:
        tier_dir = Path(temp_storage) / tier.value
        assert tier_dir.exists() and tier_dir.is_dir()

def test_store_and_retrieve_chunk(temp_storage, sample_policies):
    """Test storing and retrieving a data chunk."""
    storage = TieredStorageManager(temp_storage, sample_policies)
    
    # Create a test chunk
    test_data = b"This is a test data chunk"
    chunk = DataChunk(
        data=test_data,
        data_type='test_data',
        timestamp=datetime.utcnow(),
        retention_policy=sample_policies['test_data']
    )
    
    # Store the chunk
    chunk_path = storage.store_chunk(chunk)
    assert os.path.exists(chunk_path)
    assert os.path.exists(f"{chunk_path}.meta")
    
    # Retrieve the chunk
    retrieved_chunk = storage.retrieve_chunk(chunk_path)
    assert retrieved_chunk is not None
    assert retrieved_chunk.data == test_data
    assert retrieved_chunk.data_type == 'test_data'

def test_lifecycle_management(temp_storage, sample_policies):
    """Test automatic tier movement based on age."""
    storage = TieredStorageManager(temp_storage, sample_policies)
    now = datetime.utcnow()
    
    # Create chunks of different ages
    chunks = []
    for days_ago in [0, 2, 5, 10, 20]:
        chunk = DataChunk(
            data=f"Test data from {days_ago} days ago".encode(),
            data_type='test_data',
            timestamp=now - timedelta(days=days_ago),
            retention_policy=sample_policies['test_data']
        )
        storage.store_chunk(chunk)
    
    # Run lifecycle management
    stats = storage.manage_lifecycle()
    
    # Check that chunks were moved to appropriate tiers
    hot_dir = Path(temp_storage) / 'hot' / 'test_data'
    warm_dir = Path(temp_storage) / 'warm' / 'test_data'
    cold_dir = Path(temp_storage) / 'cold' / 'test_data'
    archive_dir = Path(temp_storage) / 'archive' / 'test_data'
    
    # Count chunks in each tier
    hot_count = sum(1 for _ in hot_dir.rglob('*.zst') if _.name.endswith('.zst'))
    warm_count = sum(1 for _ in warm_dir.rglob('*.zst') if _.name.endswith('.zst'))
    cold_count = sum(1 for _ in cold_dir.rglob('*.zst') if _.name.endswith('.zst'))
    archive_count = sum(1 for _ in archive_dir.rglob('*.zst') if _.name.endswith('.zst'))
    
    # Should have 1 in hot (0 days), 1 in warm (2 days), 1 in cold (5 days), 2 in archive (10, 20 days)
    assert hot_count == 1
    assert warm_count == 1
    assert cold_count == 1
    assert archive_count == 2

def test_cleanup_expired(temp_storage, sample_policies):
    """Test cleanup of expired data."""
    storage = TieredStorageManager(temp_storage, sample_policies)
    now = datetime.utcnow()
    
    # Create chunks with different expiration dates
    for days_ago in [5, 15, 35]:  # Will be cold, archive, and expired
        chunk = DataChunk(
            data=f"Old test data from {days_ago} days ago".encode(),
            data_type='test_data',
            timestamp=now - timedelta(days=days_ago),
            retention_policy=sample_policies['test_data']
        )
        storage.store_chunk(chunk)
    
    # Run lifecycle management to move to appropriate tiers
    storage.manage_lifecycle()
    
    # Run cleanup
    cleanup_stats = storage.cleanup_expired()
    
    # Check that only the expired chunk was deleted
    assert cleanup_stats.get('test_data_deleted', 0) == 1
    
    # Verify the remaining chunks
    cold_dir = Path(temp_storage) / 'cold' / 'test_data'
    archive_dir = Path(temp_storage) / 'archive' / 'test_data'
    
    cold_count = sum(1 for _ in cold_dir.rglob('*.zst') if _.name.endswith('.zst'))
    archive_count = sum(1 for _ in archive_dir.rglob('*.zst') if _.name.endswith('.zst'))
    
    assert cold_count == 1  # 5 days old
    assert archive_count == 1  # 15 days old

def test_compression(temp_storage, sample_policies):
    """
    Test that compression works correctly.
    """
    storage = TieredStorageManager(temp_storage, sample_policies)
    
    # Create a test chunk with compressible data
    test_data = b"a" * 1000  # Highly compressible
    chunk = DataChunk(
        data=test_data,
        data_type='test_data',
        timestamp=datetime.utcnow(),
        retention_policy=sample_policies['test_data']
    )
    
    # Store the chunk
    chunk_path = storage.store_chunk(chunk)
    
    # Check that the file is compressed
    assert os.path.exists(chunk_path)
    assert chunk_path.endswith('.zst')
    
    # Check that the compressed file is smaller than original
    original_size = len(test_data)
    compressed_size = os.path.getsize(chunk_path)
    assert compressed_size < original_size * 0.5  # Should compress to less than half
    
    # Test retrieval
    retrieved_chunk = storage.retrieve_chunk(chunk_path)
    assert retrieved_chunk is not None
    assert retrieved_chunk.data == test_data

def test_integrity_check(temp_storage, sample_policies):
    """Test data integrity verification."""
    storage = TieredStorageManager(temp_storage, sample_policies)
    
    # Create a test chunk
    test_data = b"Important data that must not be corrupted"
    chunk = DataChunk(
        data=test_data,
        data_type='test_data',
        timestamp=datetime.utcnow(),
        retention_policy=sample_policies['test_data']
    )
    
    # Store the chunk
    chunk_path = storage.store_chunk(chunk)
    
    # Corrupt the file
    with open(chunk_path, 'r+b') as f:
        f.seek(5)
        f.write(b'CORRUPTED')
    
    # Try to retrieve - should detect corruption
    with pytest.raises(Exception):
        storage.retrieve_chunk(chunk_path)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
