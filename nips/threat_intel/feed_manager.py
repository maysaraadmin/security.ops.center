"""
Threat Feed Manager for NIPS

Manages multiple threat intelligence feeds and provides a unified interface for IoC lookups.
"""
import os
import json
import time
import logging
import threading
import hashlib
from typing import Dict, List, Optional, Set, Any, Callable
from datetime import datetime, timedelta
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logger = logging.getLogger('nips.threat_intel')

class ThreatFeed:
    """Base class for threat intelligence feeds."""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        """Initialize the threat feed.
        
        Args:
            name: Name of the feed
            config: Configuration dictionary
        """
        self.name = name
        self.config = config
        self.last_updated: Optional[datetime] = None
        self.iocs: Dict[str, Dict] = {}
        self.enabled = config.get('enabled', True)
        self.update_interval = config.get('update_interval', 3600)  # Default: 1 hour
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """Create a requests session with retry logic."""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session
    
    def fetch(self) -> bool:
        """Fetch the latest IOCs from the feed.
        
        Returns:
            bool: True if the update was successful, False otherwise
        """
        raise NotImplementedError("Subclasses must implement fetch()")
    
    def should_update(self) -> bool:
        """Check if the feed should be updated.
        
        Returns:
            bool: True if the feed should be updated
        """
        if not self.last_updated:
            return True
        return (datetime.utcnow() - self.last_updated).total_seconds() > self.update_interval
    
    def lookup(self, value: str, ioc_type: str) -> Optional[Dict]:
        """Look up an IOC in the feed.
        
        Args:
            value: The IOC value to look up
            ioc_type: The type of IOC (ip, domain, hash, etc.)
            
        Returns:
            Optional[Dict]: The IOC details if found, None otherwise
        """
        # Normalize the value for consistent lookups
        normalized = self._normalize_ioc(value, ioc_type)
        return self.iocs.get(normalized)
    
    def _normalize_ioc(self, value: str, ioc_type: str) -> str:
        """Normalize an IOC value for consistent storage and lookup."""
        value = value.strip().lower()
        
        # Handle different IOC types
        if ioc_type == 'ip':
            # Normalize IPv6 addresses
            if ':' in value:
                import ipaddress
                try:
                    return str(ipaddress.IPv6Address(value)).lower()
                except ipaddress.AddressValueError:
                    pass
            return value
            
        elif ioc_type == 'domain':
            # Remove URL schemes and paths
            if '://' in value:
                value = value.split('://', 1)[1]
            # Remove port numbers
            value = value.split(':', 1)[0]
            # Remove paths and query strings
            value = value.split('/', 1)[0]
            # Remove leading/trailing dots
            return value.strip('.').lower()
            
        elif ioc_type in ('md5', 'sha1', 'sha256'):
            return value.lower()
            
        return value
    
    def _add_ioc(self, ioc_type: str, value: str, data: Dict):
        """Add an IOC to the feed."""
        normalized = self._normalize_ioc(value, ioc_type)
        self.iocs[normalized] = {
            'value': normalized,
            'type': ioc_type,
            'source': self.name,
            'first_seen': data.get('first_seen', datetime.utcnow().isoformat()),
            'last_seen': datetime.utcnow().isoformat(),
            'confidence': data.get('confidence', 50),
            'severity': data.get('severity', 'medium'),
            'tags': data.get('tags', []),
            'raw': data
        }


class AlienVaultOTXFeed(ThreatFeed):
    """AlienVault OTX threat feed integration."""
    
    BASE_URL = "https://otx.alienvault.com/api/v1"
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__('alienvault_otx', config)
        self.api_key = config.get('api_key')
        if not self.api_key:
            logger.warning("No API key provided for AlienVault OTX, disabling feed")
            self.enabled = False
    
    def fetch(self) -> bool:
        """Fetch IOCs from AlienVault OTX."""
        if not self.enabled:
            return False
            
        try:
            # Get user's subscribed pulses
            pulses = []
            url = f"{self.BASE_URL}/pulses/subscribed"
            
            while url:
                headers = {
                    'X-OTX-API-KEY': self.api_key,
                    'User-Agent': 'NIPS/1.0'
                }
                
                response = self.session.get(url, headers=headers, timeout=30)
                response.raise_for_status()
                data = response.json()
                
                # Add pulses to our list
                pulses.extend(data.get('results', []))
                
                # Check for next page
                url = data.get('next', '')
                if url and not url.startswith('http'):
                    url = f"{self.BASE_URL}{url}"
            
            # Process pulses
            for pulse in pulses:
                self._process_pulse(pulse)
            
            self.last_updated = datetime.utcnow()
            logger.info(f"Updated {self.name} feed with {len(self.iocs)} IOCs")
            return True
            
        except Exception as e:
            logger.error(f"Failed to fetch AlienVault OTX feed: {e}")
            return False
    
    def _process_pulse(self, pulse: Dict):
        """Process a single pulse from AlienVault OTX."""
        pulse_id = pulse.get('id')
        pulse_name = pulse.get('name', 'unknown')
        pulse_tags = pulse.get('tags', [])
        
        # Process indicators
        for indicator in pulse.get('indicators', []):
            try:
                ioc_type = indicator.get('type')
                ioc_value = indicator.get('indicator', '').strip()
                
                if not ioc_value:
                    continue
                
                # Map OTX types to our internal types
                type_map = {
                    'IPv4': 'ip',
                    'IPv6': 'ip',
                    'domain': 'domain',
                    'hostname': 'domain',
                    'url': 'url',
                    'md5': 'md5',
                    'sha1': 'sha1',
                    'sha256': 'sha256',
                    'email': 'email'
                }
                
                internal_type = type_map.get(ioc_type)
                if not internal_type:
                    continue
                
                # Add the IOC
                self._add_ioc(
                    ioc_type=internal_type,
                    value=ioc_value,
                    data={
                        'pulse_id': pulse_id,
                        'pulse_name': pulse_name,
                        'tags': pulse_tags + indicator.get('tags', []),
                        'first_seen': indicator.get('created'),
                        'confidence': 100 - indicator.get('falsepositives', 0),
                        'severity': pulse.get('tlp', 'amber').lower(),
                        'raw': indicator
                    }
                )
                
            except Exception as e:
                logger.error(f"Error processing OTX indicator: {e}")


class MITREAttackFeed(ThreatFeed):
    """MITRE ATT&CK threat feed integration."""
    
    ENTERPRISE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__('mitre_attack', config)
        self.techniques: Dict[str, Dict] = {}
    
    def fetch(self) -> bool:
        """Fetch MITRE ATT&CK data."""
        try:
            # Download the latest ATT&CK data
            response = self.session.get(self.ENTERPRISE_URL, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            # Process techniques
            self.techniques = {}
            for item in data.get('objects', []):
                if item.get('type') == 'attack-pattern':
                    technique_id = item.get('external_references', [{}])[0].get('external_id', '')
                    if technique_id.startswith('T'):
                        self.techniques[technique_id] = {
                            'id': technique_id,
                            'name': item.get('name'),
                            'description': item.get('description'),
                            'tactics': [t['phase_name'] for t in item.get('kill_chain_phases', [])],
                            'platforms': item.get('x_mitre_platforms', []),
                            'data_sources': item.get('x_mitre_data_sources', []),
                            'url': next((ref['url'] for ref in item.get('external_references', [])
                                      if ref.get('source_name') == 'mitre-attack' and 'url' in ref), '')
                        }
            
            self.last_updated = datetime.utcnow()
            logger.info(f"Updated {self.name} feed with {len(self.techniques)} techniques")
            return True
            
        except Exception as e:
            logger.error(f"Failed to fetch MITRE ATT&CK feed: {e}")
            return False
    
    def lookup(self, technique_id: str, _=None) -> Optional[Dict]:
        """Look up a MITRE ATT&CK technique by ID."""
        return self.techniques.get(technique_id.upper())


class FileHashFeed(ThreatFeed):
    """File hash feed from a local file or URL."""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.source = config.get('source')
        self.hash_type = config.get('hash_type', 'md5').lower()
        
        if not self.source:
            logger.warning(f"No source specified for {name}, disabling feed")
            self.enabled = False
    
    def fetch(self) -> bool:
        """Fetch hashes from the source."""
        if not self.enabled:
            return False
            
        try:
            # Check if source is a URL or file path
            if self.source.startswith(('http://', 'https://')):
                response = self.session.get(self.source, timeout=30)
                response.raise_for_status()
                lines = response.text.splitlines()
            else:
                with open(self.source, 'r') as f:
                    lines = f.readlines()
            
            # Process hashes
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                # Extract hash (handle CSV or plain text)
                if ',' in line:
                    parts = line.split(',')
                    if len(parts) > 1:
                        hash_value = parts[0].strip()
                        tags = [t.strip() for t in parts[1:]]
                    else:
                        hash_value = line
                        tags = []
                else:
                    hash_value = line
                    tags = []
                
                # Validate hash format
                if not self._is_valid_hash(hash_value):
                    continue
                
                # Add the hash
                self._add_ioc(
                    ioc_type=self.hash_type,
                    value=hash_value,
                    data={
                        'source': self.name,
                        'tags': tags,
                        'first_seen': datetime.utcnow().isoformat(),
                        'confidence': 90,
                        'severity': 'high'
                    }
                )
            
            self.last_updated = datetime.utcnow()
            logger.info(f"Updated {self.name} feed with {len(self.iocs)} hashes")
            return True
            
        except Exception as e:
            logger.error(f"Failed to fetch {self.name} feed: {e}")
            return False
    
    def _is_valid_hash(self, value: str) -> bool:
        """Check if a string is a valid hash of the configured type."""
        if not value:
            return False
            
        if self.hash_type == 'md5':
            return len(value) == 32 and all(c in '0123456789abcdef' for c in value.lower())
        elif self.hash_type == 'sha1':
            return len(value) == 40 and all(c in '0123456789abcdef' for c in value.lower())
        elif self.hash_type == 'sha256':
            return len(value) == 64 and all(c in '0123456789abcdef' for c in value.lower())
            
        return True  # For unknown hash types, just accept the value


class ThreatFeedManager:
    """Manages multiple threat intelligence feeds."
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the threat feed manager.
        
        Args:
            config: Configuration dictionary with feed settings
        """
        self.config = config
        self.feeds: Dict[str, ThreatFeed] = {}
        self.ioc_cache: Dict[str, Dict] = {}
        self.cache_ttl = config.get('cache_ttl', 3600)  # Default: 1 hour
        self.last_cache_cleanup = time.time()
        self.lock = threading.RLock()
        self.running = False
        self.update_thread: Optional[threading.Thread] = None
        
        # Initialize feeds
        self._init_feeds()
    
    def _init_feeds(self):
        """Initialize configured threat feeds."""
        feed_configs = self.config.get('feeds', {})
        
        # Add built-in feeds
        if 'alienvault_otx' in feed_configs:
            self.feeds['alienvault_otx'] = AlienVaultOTXFeed(feed_configs['alienvault_otx'])
        
        if 'mitre_attack' in feed_configs:
            self.feeds['mitre_attack'] = MITREAttackFeed(feed_configs['mitre_attack'])
        
        # Add file hash feeds
        for name, feed_config in feed_configs.items():
            if name.startswith('hashfeed_') and 'source' in feed_config:
                self.feeds[name] = FileHashFeed(name, feed_config)
        
        logger.info(f"Initialized {len(self.feeds)} threat feeds")
    
    def start(self):
        """Start the feed manager and schedule updates."""
        if self.running:
            return
            
        self.running = True
        
        # Initial feed update
        self.update_feeds()
        
        # Start background update thread
        self.update_thread = threading.Thread(
            target=self._update_loop,
            name="ThreatFeedUpdater",
            daemon=True
        )
        self.update_thread.start()
        
        logger.info("Threat feed manager started")
    
    def _update_loop(self):
        """Background thread to update feeds periodically."""
        while self.running:
            try:
                # Check for feeds that need updating
                now = time.time()
                needs_update = [
                    feed for feed in self.feeds.values() 
                    if feed.enabled and feed.should_update()
                ]
                
                # Update feeds
                for feed in needs_update:
                    try:
                        logger.debug(f"Updating {feed.name} feed...")
                        feed.fetch()
                    except Exception as e:
                        logger.error(f"Error updating {feed.name} feed: {e}")
                
                # Clean up cache periodically
                if now - self.last_cache_cleanup > 3600:  # Every hour
                    self._cleanup_cache()
                    self.last_cache_cleanup = now
                
                # Sleep for a bit before checking again
                time.sleep(60)
                
            except Exception as e:
                logger.error(f"Error in feed update loop: {e}")
                time.sleep(30)  # Avoid tight loop on error
    
    def update_feeds(self) -> bool:
        """Update all enabled feeds.
        
        Returns:
            bool: True if all feeds updated successfully, False otherwise
        """
        success = True
        
        with self.lock:
            for feed in self.feeds.values():
                if not feed.enabled:
                    continue
                    
                try:
                    if not feed.fetch():
                        success = False
                except Exception as e:
                    logger.error(f"Failed to update {feed.name} feed: {e}")
                    success = False
        
        return success
    
    def lookup_ioc(self, value: str, ioc_type: str) -> Optional[Dict]:
        """Look up an IOC across all feeds.
        
        Args:
            value: The IOC value to look up
            ioc_type: The type of IOC (ip, domain, hash, etc.)
            
        Returns:
            Optional[Dict]: The IOC details if found, None otherwise
        """
        # Check cache first
        cache_key = f"{ioc_type}:{value.lower()}"
        
        with self.lock:
            cached = self.ioc_cache.get(cache_key)
            if cached:
                # Check if cache entry is still valid
                if time.time() - cached.get('_cached_at', 0) < self.cache_ttl:
                    return cached
                # Cache entry expired, remove it
                self.ioc_cache.pop(cache_key, None)
            
            # Check each feed
            for feed in self.feeds.values():
                if not feed.enabled:
                    continue
                    
                try:
                    result = feed.lookup(value, ioc_type)
                    if result:
                        # Cache the result
                        result['_cached_at'] = time.time()
                        self.ioc_cache[cache_key] = result
                        return result
                except Exception as e:
                    logger.error(f"Error looking up IOC in {feed.name}: {e}")
            
            # Not found in any feed
            return None
    
    def _cleanup_cache(self):
        """Remove expired cache entries."""
        now = time.time()
        expired = [
            k for k, v in self.ioc_cache.items()
            if now - v.get('_cached_at', 0) > self.cache_ttl
        ]
        
        with self.lock:
            for key in expired:
                self.ioc_cache.pop(key, None)
            
            if expired:
                logger.debug(f"Cleaned up {len(expired)} expired cache entries")
    
    def get_feed_status(self) -> List[Dict]:
        """Get the status of all feeds.
        
        Returns:
            List[Dict]: Status information for each feed
        """
        status = []
        
        with self.lock:
            for name, feed in self.feeds.items():
                status.append({
                    'name': name,
                    'enabled': feed.enabled,
                    'last_updated': feed.last_updated.isoformat() if feed.last_updated else None,
                    'ioc_count': len(feed.iocs) if hasattr(feed, 'iocs') else 0,
                    'next_update_in': max(0, feed.update_interval - (time.time() - (feed.last_updated or datetime.min).timestamp()))
                })
        
        return status
    
    def shutdown(self):
        """Shut down the feed manager."""
        self.running = False
        
        if self.update_thread and self.update_thread.is_alive():
            self.update_thread.join(timeout=10)
        
        logger.info("Threat feed manager shut down")
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()


# Example usage
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    config = {
        'cache_ttl': 3600,
        'feeds': {
            'alienvault_otx': {
                'enabled': True,
                'api_key': 'your_otx_api_key',
                'update_interval': 3600  # 1 hour
            },
            'mitre_attack': {
                'enabled': True,
                'update_interval': 86400  # 1 day
            },
            'hashfeed_malware_hashes': {
                'enabled': True,
                'source': 'https://example.com/malware_hashes.txt',
                'hash_type': 'md5',
                'update_interval': 3600
            }
        }
    }
    
    with ThreatFeedManager(config) as manager:
        # Look up some IOCs
        print(manager.lookup_ioc('8.8.8.8', 'ip'))
        print(manager.lookup_ioc('example.com', 'domain'))
        print(manager.lookup_ioc('T1059', 'mitre_technique'))
        
        # Print feed status
        for status in manager.get_feed_status():
            print(f"{status['name']}: {status['ioc_count']} IOCs, last updated: {status['last_updated']}")
        
        # Keep running to allow background updates
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
