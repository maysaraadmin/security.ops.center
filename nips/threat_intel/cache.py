"""
IOC Cache for NIPS

Provides caching functionality for threat intelligence lookups and enrichment.
"""
import time
import json
import hashlib
from typing import Dict, Any, Optional, TypeVar, Type, Generic, Union
from datetime import datetime, timedelta
import logging
from dataclasses import dataclass, field, asdict

logger = logging.getLogger('nips.cache')

T = TypeVar('T')

@dataclass
class CacheEntry(Generic[T]):
    """A single cache entry with expiration."""
    value: T
    expires_at: float
    created_at: float = field(default_factory=time.time)
    access_count: int = 0
    
    def is_expired(self) -> bool:
        """Check if the cache entry has expired."""
        return time.time() > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the cache entry to a dictionary."""
        return {
            'value': self.value,
            'expires_at': self.expires_at,
            'created_at': self.created_at,
            'access_count': self.access_count
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CacheEntry[T]':
        """Create a cache entry from a dictionary."""
        return cls(
            value=data['value'],
            expires_at=data['expires_at'],
            created_at=data.get('created_at', time.time()),
            access_count=data.get('access_count', 0)
        )

class IOCache:
    """In-memory cache for IOC lookups and enrichment results."""
    
    def __init__(self, max_size: int = 10000, default_ttl: int = 3600):
        """Initialize the cache.
        
        Args:
            max_size: Maximum number of items to store in the cache
            default_ttl: Default time-to-live in seconds for cache entries
        """
        self._cache: Dict[str, CacheEntry] = {}
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.hits = 0
        self.misses = 0
        self._lock = None  # Would be a threading.Lock in a multi-threaded environment
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a value from the cache.
        
        Args:
            key: Cache key
            default: Default value to return if key is not found or expired
            
        Returns:
            The cached value or default if not found/expired
        """
        if key in self._cache:
            entry = self._cache[key]
            if not entry.is_expired():
                entry.access_count += 1
                self.hits += 1
                return entry.value
            else:
                # Remove expired entry
                del self._cache[key]
        
        self.misses += 1
        return default
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set a value in the cache.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Optional time-to-live in seconds (defaults to default_ttl)
        """
        if len(self._cache) >= self.max_size:
            self._evict()
            
        expires_at = time.time() + (ttl if ttl is not None else self.default_ttl)
        self._cache[key] = CacheEntry(value=value, expires_at=expires_at)
    
    def delete(self, key: str) -> bool:
        """Delete a key from the cache.
        
        Args:
            key: Cache key to delete
            
        Returns:
            True if the key was deleted, False if it didn't exist
        """
        if key in self._cache:
            del self._cache[key]
            return True
        return False
    
    def clear(self) -> None:
        """Clear all items from the cache."""
        self._cache.clear()
        self.hits = 0
        self.misses = 0
    
    def _evict(self) -> None:
        """Evict entries from the cache when it's full."""
        if not self._cache:
            return
            
        # Simple LRU eviction based on access count and expiration
        now = time.time()
        
        # First, remove all expired entries
        expired_keys = [k for k, v in self._cache.items() if v.expires_at <= now]
        for k in expired_keys:
            del self._cache[k]
            
        # If we still need more space, remove the least recently used
        if len(self._cache) >= self.max_size:
            # Sort by access count (lowest first) and then by creation time (oldest first)
            lru_key = min(
                self._cache.items(),
                key=lambda item: (item[1].access_count, item[1].created_at)
            )[0]
            del self._cache[lru_key]
    
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        now = time.time()
        expired_count = sum(1 for v in self._cache.values() if v.expires_at <= now)
        
        return {
            'size': len(self._cache),
            'max_size': self.max_size,
            'hits': self.hits,
            'misses': self.misses,
            'hit_ratio': self.hits / (self.hits + self.misses) if (self.hits + self.misses) > 0 else 0,
            'expired_count': expired_count,
            'default_ttl': self.default_ttl
        }
    
    def save_to_file(self, filename: str) -> bool:
        """Save the cache to a file.
        
        Args:
            filename: Path to the file to save to
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(filename, 'w') as f:
                data = {
                    'entries': {
                        k: v.to_dict()
                        for k, v in self._cache.items()
                        if not v.is_expired()
                    },
                    'stats': {
                        'hits': self.hits,
                        'misses': self.misses
                    },
                    'meta': {
                        'version': '1.0',
                        'saved_at': datetime.utcnow().isoformat()
                    }
                }
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to save cache to {filename}: {e}")
            return False
    
    @classmethod
    def load_from_file(cls, filename: str, max_size: int = 10000, default_ttl: int = 3600) -> 'IOCache':
        """Load a cache from a file.
        
        Args:
            filename: Path to the file to load from
            max_size: Maximum cache size
            default_ttl: Default time-to-live in seconds
            
        Returns:
            A new IOCache instance
        """
        cache = cls(max_size=max_size, default_ttl=default_ttl)
        
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                
                for k, entry_data in data.get('entries', {}).items():
                    entry = CacheEntry.from_dict(entry_data)
                    if not entry.is_expired():
                        cache._cache[k] = entry
                
                stats = data.get('stats', {})
                cache.hits = stats.get('hits', 0)
                cache.misses = stats.get('misses', 0)
                
        except FileNotFoundError:
            logger.info(f"Cache file {filename} not found, starting with empty cache")
        except Exception as e:
            logger.error(f"Failed to load cache from {filename}: {e}")
            
        return cache

def generate_cache_key(ioc_type: str, value: str) -> str:
    """Generate a consistent cache key for an IOC.
    
    Args:
        ioc_type: Type of IOC (ip, domain, hash, etc.)
        value: The IOC value
        
    Returns:
        A string that can be used as a cache key
    """
    # Normalize the value (lowercase and strip whitespace)
    normalized_value = str(value).lower().strip()
    
    # Create a hash of the type and value to ensure consistent key format
    key = f"{ioc_type}:{normalized_value}"
    return hashlib.sha256(key.encode('utf-8')).hexdigest()

# Example usage
if __name__ == "__main__":
    # Create a cache with max 100 entries and 1-hour default TTL
    cache = IOCache(max_size=100, default_ttl=3600)
    
    # Add some items
    cache.set("ip:8.8.8.8", {"type": "ip", "threat": "none", "source": "test"})
    cache.set("domain:example.com", {"type": "domain", "threat": "malicious", "source": "test"})
    
    # Get an item
    print("Looking up 8.8.8.8:", cache.get("ip:8.8.8.8"))
    print("Looking up example.com:", cache.get("domain:example.com"))
    
    # Get cache stats
    print("\nCache stats:", cache.stats())
    
    # Test key generation
    key = generate_cache_key("ip", "8.8.8.8")
    print(f"\nGenerated cache key for 8.8.8.8: {key}")
