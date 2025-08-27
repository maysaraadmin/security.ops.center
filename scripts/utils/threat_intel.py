"""
Threat Intelligence Integration for NIPS

This module provides integration with various threat intelligence feeds and services
to enhance the detection capabilities of the Network Intrusion Prevention System.
"""

import logging
import requests
import json
import time
import os
import random
from typing import Dict, List, Set, Optional, Any, Tuple
from datetime import datetime, timedelta
import hashlib
import ipaddress
import socket
import re
from urllib.parse import urlparse
import concurrent.futures
import threading

# Configure retry strategy for requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

logger = logging.getLogger('nips.threat_intel')

class ThreatIntelligence:
    """Manages threat intelligence feeds and lookups."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the threat intelligence module.
        
        Args:
            config: Configuration dictionary containing API keys and feed URLs
        """
        self.config = config or {}
        self.last_updated: Dict[str, datetime] = {}
        self.cache_ttl = timedelta(minutes=30)  # Default cache TTL
        self.lock = threading.Lock()
        
        # Initialize data structures for different types of IOCs with max size limits
        self.max_iocs = self.config.get('max_iocs_per_category', 100000)  # Default max 100K per category
        self.malicious_ips: Set[str] = set()
        self.malicious_domains: Set[str] = set()
        self.malicious_hashes: Set[str] = set()
        self.malicious_urls: Set[str] = set()
        self.c2_indicators: Dict[str, Dict] = {}
        
        # Configure HTTP session with retries
        self.session = self._create_http_session()
        
        # Feed configurations with validation
        self.feeds = {
            'alienvault_otx': {
                'enabled': bool(self.config.get('alienvault_otx_api_key')),
                'url': 'https://otx.alienvault.com/api/v1/indicators/export',
                'api_key': self.config.get('alienvault_otx_api_key', ''),
                'types': ['IPv4', 'domain', 'hostname', 'URL', 'FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256'],
                'last_updated': None,
                'update_frequency': 3600,  # 1 hour
                'timeout': 30,
                'verify_ssl': True
            },
            'abuseipdb': {
                'enabled': bool(self.config.get('abuseipdb_api_key')),
                'url': 'https://api.abuseipdb.com/api/v2/blacklist',
                'api_key': self.config.get('abuseipdb_api_key', ''),
                'last_updated': None,
                'update_frequency': 10800,  # 3 hours
                'timeout': 30,
                'verify_ssl': True,
                'confidence_minimum': 90  # Only high confidence indicators
            },
            'emerging_threats': {
                'enabled': True,  # No API key required for public feed
                'url': 'https://rules.emergingthreats.net/open/suricata/rules/',
                'api_key': self.config.get('emerging_threats_api_key', ''),
                'last_updated': None,
                'update_frequency': 14400,  # 4 hours
                'timeout': 60,
                'verify_ssl': True
            }
        }
        
        # Create data directory if it doesn't exist
        data_dir = os.path.dirname(os.path.abspath(self.config.get('data_file', 'threat_intel_data.json')))
        os.makedirs(data_dir, exist_ok=True)
        
        # Load any existing threat data
        self._load_threat_data()
        
        # Start background update thread
        self.running = True
        self.update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self.update_thread.start()
        
        logger.info("Threat Intelligence module initialized with %d IPs, %d domains, %d hashes, and %d URLs",
                   len(self.malicious_ips), len(self.malicious_domains), 
                   len(self.malicious_hashes), len(self.malicious_urls))

    def _load_threat_data(self) -> None:
        """Load threat data from persistent storage if available."""
        try:
            data_file = self.config.get('data_file', 'threat_intel_data.json')
            if not os.path.exists(data_file):
                logger.info("No existing threat data found, starting fresh")
                return
                
            with open(data_file, 'r') as f:
                data = json.load(f)
                
            with self.lock:
                self.malicious_ips.update(set(data.get('malicious_ips', [])))
                self.malicious_domains.update(set(data.get('malicious_domains', [])))
                self.malicious_hashes.update(set(data.get('malicious_hashes', [])))
                self.malicious_urls.update(set(data.get('malicious_urls', [])))
                self.c2_indicators.update(data.get('c2_indicators', {}))
                
                # Update last_updated timestamps for feeds
                for feed_name, last_updated in data.get('feed_timestamps', {}).items():
                    if feed_name in self.feeds:
                        self.feeds[feed_name]['last_updated'] = datetime.fromisoformat(last_updated)
                
            logger.info(f"Loaded {len(self.malicious_ips)} IPs, {len(self.malicious_domains)} domains, "
                      f"{len(self.malicious_hashes)} hashes, and {len(self.malicious_urls)} URLs from persistent storage")
                      
        except Exception as e:
            logger.error(f"Error loading threat data: {e}")
            # Continue with empty data rather than failing
        
    def _save_threat_data(self) -> None:
        """Save threat data to persistent storage."""
        try:
            data_file = self.config.get('data_file', 'threat_intel_data.json')
            temp_file = f"{data_file}.tmp"
            
            with self.lock:
                data = {
                    'malicious_ips': list(self.malicious_ips),
                    'malicious_domains': list(self.malicious_domains),
                    'malicious_hashes': list(self.malicious_hashes),
                    'malicious_urls': list(self.malicious_urls),
                    'c2_indicators': self.c2_indicators,
                    'feed_timestamps': {
                        feed: config['last_updated'].isoformat() 
                        for feed, config in self.feeds.items() 
                        if config.get('last_updated')
                    },
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            # Write to temporary file first, then rename (atomic operation)
            with open(temp_file, 'w') as f:
                json.dump(data, f, indent=2)
                
            # On Windows, we need to remove the destination file first if it exists
            if os.path.exists(data_file):
                os.replace(temp_file, data_file)
            else:
                os.rename(temp_file, data_file)
                
            logger.debug("Successfully saved threat data to persistent storage")
            
        except Exception as e:
            logger.error(f"Error saving threat data: {e}")
            # Clean up any temporary files on error
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except:
                    pass

    def _create_http_session(self) -> requests.Session:
        """Create a configured HTTP session with retry logic."""
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        
        # Mount the retry adapter
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
        
    def _update_loop(self) -> None:
        """Background thread for updating threat intelligence feeds."""
        update_interval = 300  # 5 minutes between update checks
        
        while self.running:
            try:
                start_time = time.time()
                
                # Update all feeds
                self.update_feeds()
                
                # Calculate sleep time, ensuring we don't sleep for a negative duration
                elapsed = time.time() - start_time
                sleep_time = max(0, update_interval - elapsed)
                
                # Sleep in smaller chunks to be more responsive to shutdown requests
                while sleep_time > 0 and self.running:
                    time.sleep(min(1, sleep_time))
                    sleep_time -= 1
                    
            except Exception as e:
                logger.error(f"Error in threat intelligence update loop: {e}", exc_info=True)
                time.sleep(60)  # Wait a minute before retrying on error

    def stop(self) -> None:
        """Stop the threat intelligence update thread."""
        self.running = False
        if self.update_thread.is_alive():
            self.update_thread.join(timeout=5)
        self._save_threat_data()

    def update_feeds(self) -> None:
        """Update all enabled threat intelligence feeds with rate limiting."""
        try:
            # Use a thread pool with a maximum of 3 concurrent updates
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                futures = []
                
                # Schedule updates for all enabled feeds
                for feed_name, feed_config in self.feeds.items():
                    if not feed_config.get('enabled', False):
                        logger.debug(f"Skipping disabled feed: {feed_name}")
                        continue
                        
                    # Submit the feed update task
                    future = executor.submit(self._update_feed, feed_name, feed_config)
                    futures.append(future)
                    
                    # Add a small delay between starting updates to avoid overwhelming the system
                    time.sleep(0.5)
                
                # Wait for all updates to complete with a timeout
                logger.debug(f"Waiting for {len(futures)} feed updates to complete...")
                done, not_done = concurrent.futures.wait(
                    futures, 
                    timeout=300,  # 5 minute timeout
                    return_when=concurrent.futures.ALL_COMPLETED
                )
                
                # Log any incomplete updates
                if not_done:
                    logger.warning(f"{len(not_done)} feed updates did not complete within timeout")
                
                # Check for exceptions in completed tasks
                for future in done:
                    try:
                        future.result()  # This will raise any exceptions from the task
                    except Exception as e:
                        logger.error(f"Error in feed update task: {e}", exc_info=True)
                        
        except Exception as e:
            logger.error(f"Error in update_feeds: {e}", exc_info=True)
            raise

    def _update_feed(self, feed_name: str, feed_config: Dict) -> None:
        """Update a single threat intelligence feed with retries and error handling.
        
        Args:
            feed_name: Name of the feed to update
            feed_config: Configuration for the feed
        """
        max_retries = 3
        base_delay = 5  # seconds
        
        for attempt in range(max_retries):
            try:
                now = datetime.utcnow()
                last_updated = feed_config.get('last_updated')
                
                # Skip if not enough time has passed since last update
                if (last_updated and 
                    (now - last_updated).total_seconds() < feed_config.get('update_frequency', 3600)):
                    logger.debug(f"Skipping {feed_name} update - too soon since last update")
                    return
                
                logger.info(f"Updating threat feed: {feed_name} (attempt {attempt + 1}/{max_retries})")
                
                # Update the specific feed
                if feed_name == 'alienvault_otx':
                    if not feed_config.get('api_key'):
                        logger.warning(f"Skipping {feed_name} - API key not configured")
                        return
                    self._update_alienvault_otx(feed_config)
                elif feed_name == 'abuseipdb':
                    if not feed_config.get('api_key'):
                        logger.warning(f"Skipping {feed_name} - API key not configured")
                        return
                    self._update_abuseipdb(feed_config)
                elif feed_name == 'emerging_threats':
                    self._update_emerging_threats(feed_config)
                else:
                    logger.warning(f"Unknown feed type: {feed_name}")
                    return
                
                # Update last_updated only on success
                feed_config['last_updated'] = now
                logger.info(f"Successfully updated threat feed: {feed_name}")
                
                # Save the updated data
                self._save_threat_data()
                return
                
            except requests.exceptions.RequestException as e:
                if attempt == max_retries - 1:  # Last attempt
                    logger.error(f"Failed to update {feed_name} after {max_retries} attempts: {e}")
                    return
                    
                # Exponential backoff
                delay = base_delay * (2 ** attempt) + (random.random() * 2)  # Add jitter
                logger.warning(f"Error updating {feed_name} (attempt {attempt + 1}): {e}. Retrying in {delay:.1f}s...")
                time.sleep(delay)
                
            except Exception as e:
                logger.error(f"Unexpected error updating {feed_name}: {e}", exc_info=True)
                return

    def _update_alienvault_otx(self, feed_config: Dict) -> None:
        """Update AlienVault OTX threat feed with error handling and rate limiting."""
        if not feed_config.get('api_key'):
            logger.warning("Skipping AlienVault OTX update - API key not configured")
            return
            
        headers = {'X-OTX-API-KEY': feed_config['api_key']}
        timeout = feed_config.get('timeout', 30)
        
        for indicator_type in feed_config.get('types', []):
            try:
                logger.debug(f"Fetching {indicator_type} indicators from AlienVault OTX")
                
                # Add rate limiting
                time.sleep(1)  # Be nice to the API
                
                params = {'indicator_type': indicator_type}
                response = self.session.get(
                    feed_config['url'],
                    headers=headers,
                    params=params,
                    timeout=timeout,
                    verify=feed_config.get('verify_ssl', True)
                )
                
                # Check for rate limiting
                if response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', 60))
                    logger.warning(f"AlienVault OTX rate limit reached. Waiting {retry_after} seconds...")
                    time.sleep(retry_after)
                    continue
                    
                response.raise_for_status()
                
                data = response.json()
                indicators = data.get('data', [])
                
                if not indicators:
                    logger.warning(f"No indicators found for type {indicator_type}")
                    continue
                    
                logger.info(f"Processing {len(indicators)} {indicator_type} indicators from AlienVault OTX")
                self._process_otx_indicators(indicators, indicator_type)
                
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 401:
                    logger.error("Invalid AlienVault OTX API key. Please check your configuration.")
                    feed_config['enabled'] = False  # Disable future updates
                    break
                logger.error(f"HTTP error fetching AlienVault OTX {indicator_type} indicators: {e}")
            except requests.exceptions.RequestException as e:
                logger.error(f"Request error fetching AlienVault OTX {indicator_type} indicators: {e}")
            except Exception as e:
                logger.error(f"Error processing AlienVault OTX {indicator_type} indicators: {e}", exc_info=True)

    def _process_otx_indicators(self, indicators: List[Dict], indicator_type: str) -> None:
        """Process indicators from AlienVault OTX.
        
        Args:
            indicators: List of indicator dictionaries
            indicator_type: Type of indicators (IPv4, domain, etc.)
        """
        with self.lock:
            for indicator in indicators:
                try:
                    value = indicator.get('indicator', '').strip()
                    if not value:
                        continue
                        
                    if indicator_type == 'IPv4' and self._is_valid_ip(value):
                        self.malicious_ips.add(value)
                    elif indicator_type in ['domain', 'hostname'] and self._is_valid_domain(value):
                        self.malicious_domains.add(value.lower())
                    elif indicator_type == 'URL' and self._is_valid_url(value):
                        self.malicious_urls.add(value.lower())
                    elif indicator_type.startswith('FileHash-'):
                        self.malicious_hashes.add(value.lower())
                        
                except Exception as e:
                    logger.error(f"Error processing OTX indicator {indicator}: {e}")

    def _update_abuseipdb(self, feed_config: Dict) -> None:
        """Update AbuseIPDB threat feed with error handling and rate limiting."""
        if not feed_config.get('api_key'):
            logger.warning("Skipping AbuseIPDB update - API key not configured")
            return
            
        headers = {
            'Key': feed_config['api_key'],
            'Accept': 'application/json'
        }
        
        timeout = feed_config.get('timeout', 30)
        confidence_min = feed_config.get('confidence_minimum', 90)
        
        try:
            logger.debug("Fetching indicators from AbuseIPDB")
            
            # Add rate limiting
            time.sleep(1)  # Be nice to the API
            
            response = self.session.get(
                feed_config['url'],
                headers=headers,
                params={
                    'limit': 10000,
                    'confidenceMinimum': confidence_min  # Only high confidence indicators
                },
                timeout=timeout,
                verify=feed_config.get('verify_ssl', True)
            )
            
            # Check for rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 60))
                logger.warning(f"AbuseIPDB rate limit reached. Waiting {retry_after} seconds...")
                time.sleep(retry_after)
                return
                
            response.raise_for_status()
            
            data = response.json().get('data', [])
            if not data:
                logger.warning("No indicators found in AbuseIPDB response")
                return
                
            logger.info(f"Processing {len(data)} IPs from AbuseIPDB")
            
            new_ips = []
            with self.lock:
                for item in data:
                    ip = item.get('ipAddress')
                    if ip and self._is_valid_ip(ip):
                        if len(self.malicious_ips) < self.max_iocs:
                            self.malicious_ips.add(ip)
                            new_ips.append(ip)
                        else:
                            logger.warning(f"Max IPs limit ({self.max_iocs}) reached, skipping additional IPs")
                            break
            
            logger.info(f"Added {len(new_ips)} new malicious IPs from AbuseIPDB")
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                logger.error("Invalid AbuseIPDB API key. Please check your configuration.")
                feed_config['enabled'] = False  # Disable future updates
            else:
                logger.error(f"HTTP error fetching AbuseIPDB indicators: {e}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error fetching AbuseIPDB indicators: {e}")
        except Exception as e:
            logger.error(f"Error processing AbuseIPDB indicators: {e}", exc_info=True)

    def _update_emerging_threats(self, feed_config: Dict) -> None:
        """Update Emerging Threats feed with error handling and rate limiting."""
        timeout = feed_config.get('timeout', 60)  # Longer timeout for large rule sets
        
        try:
            logger.debug("Fetching indicators from Emerging Threats")
            
            # Add rate limiting
            time.sleep(1)  # Be nice to the server
            
            response = self.session.get(
                feed_config['url'],
                timeout=timeout,
                verify=feed_config.get('verify_ssl', True)
            )
            
            # Check for rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 60))
                logger.warning(f"Emerging Threats rate limit reached. Waiting {retry_after} seconds...")
                time.sleep(retry_after)
                return
                
            response.raise_for_status()
            
            # Parse Suricata rules for IOCs
            rules = response.text.split('\n')
            if not rules or len(rules) < 10:  # Arbitrary threshold for minimum rules
                logger.warning("Unexpectedly small number of rules from Emerging Threats")
                return
                
            logger.info(f"Processing {len(rules)} rules from Emerging Threats")
            self._process_suricata_rules(rules)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error fetching Emerging Threats indicators: {e}")
        except Exception as e:
            logger.error(f"Error processing Emerging Threats indicators: {e}", exc_info=True)

    def _process_suricata_rules(self, rules: List[str]) -> None:
        """Process Suricata rules to extract IOCs.
        
        Args:
            rules: List of Suricata rule strings
        """
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b'
        domain_pattern = r'(?:^|\s)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?=\s|$)'
        
        with self.lock:
            for rule in rules:
                try:
                    # Extract IPs
                    for ip_match in re.finditer(ip_pattern, rule):
                        ip = ip_match.group(0)
                        if self._is_valid_ip(ip.split('/')[0]):  # Handle CIDR notation
                            self.malicious_ips.add(ip.split('/')[0])
                    
                    # Extract domains
                    for domain_match in re.finditer(domain_pattern, rule):
                        domain = domain_match.group(0).strip()
                        if self._is_valid_domain(domain):
                            self.malicious_domains.add(domain.lower())
                            
                except Exception as e:
                    logger.error(f"Error processing Suricata rule: {e}")

    def is_malicious_ip(self, ip: str) -> bool:
        """Check if an IP address is known to be malicious.
        
        Args:
            ip: IP address to check
            
        Returns:
            bool: True if the IP is known to be malicious
        """
        with self.lock:
            return ip in self.malicious_ips

    def is_malicious_domain(self, domain: str) -> bool:
        """Check if a domain is known to be malicious.
        
        Args:
            domain: Domain to check
            
        Returns:
            bool: True if the domain is known to be malicious
        """
        with self.lock:
            return domain.lower() in self.malicious_domains

    def is_malicious_hash(self, file_hash: str) -> bool:
        """Check if a file hash is known to be malicious.
        
        Args:
            file_hash: File hash to check (MD5, SHA1, or SHA256)
            
        Returns:
            bool: True if the hash is known to be malicious
        """
        with self.lock:
            return file_hash.lower() in self.malicious_hashes

    def is_malicious_url(self, url: str) -> bool:
        """Check if a URL is known to be malicious.
        
        Args:
            url: URL to check
            
        Returns:
            bool: True if the URL is known to be malicious
        """
        with self.lock:
            return url.lower() in self.malicious_urls

    def get_c2_indicators(self, protocol: Optional[str] = None) -> Dict[str, Any]:
        """Get command and control indicators.
        
        Args:
            protocol: Optional protocol filter (e.g., 'http', 'dns', 'tcp')
            
        Returns:
            Dictionary of C2 indicators
        """
        with self.lock:
            if protocol:
                return {k: v for k, v in self.c2_indicators.items() 
                        if v.get('protocol') == protocol}
            return self.c2_indicators

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Check if a string is a valid IP address.
        
        Args:
            ip: IP address to validate
            
        Returns:
            bool: True if the IP is valid
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_valid_domain(domain: str) -> bool:
        """Check if a string is a valid domain name.
        
        Args:
            domain: Domain to validate
            
        Returns:
            bool: True if the domain is valid
        """
        if not domain or len(domain) > 253:
            return False
            
        # Remove any leading/trailing dots
        domain = domain.strip('.')
        
        # Split into labels
        labels = domain.split('.')
        if len(labels) < 2:
            return False
            
        # Check each label
        for label in labels:
            if not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$', label, re.IGNORECASE):
                return False
                
        return True

    @staticmethod
    def _is_valid_url(url: str) -> bool:
        """Check if a string is a valid URL.
        
        Args:
            url: URL to validate
            
        Returns:
            bool: True if the URL is valid
        """
        try:
            result = urlparse(url)
            return all([result.scheme in ['http', 'https'], result.netloc])
        except:
            return False

# Example usage
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Example configuration
    config = {
        'alienvault_otx_api_key': 'your_otx_api_key',
        'abuseipdb_api_key': 'your_abuseipdb_api_key',
        'emerging_threats_api_key': 'your_emerging_threats_api_key'
    }
    
    # Initialize threat intelligence
    threat_intel = ThreatIntelligence(config)
    
    # Example lookups
    print(f"Is 1.1.1.1 malicious? {threat_intel.is_malicious_ip('1.1.1.1')}")
    print(f"Is example.com malicious? {threat_intel.is_malicious_domain('example.com')}")
    
    # Keep the script running to allow background updates
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        threat_intel.stop()
