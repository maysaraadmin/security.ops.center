"""
Threat Intelligence Client for NIPS

Provides a client interface for querying threat intelligence feeds.
"""
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import json
import time

logger = logging.getLogger('nips.intel_client')

class ThreatIntelClient:
    """Client for querying threat intelligence feeds."""
    
    def __init__(self, feed_manager):
        """Initialize the threat intelligence client.
        
        Args:
            feed_manager: Instance of ThreatFeedManager
        """
        self.feed_manager = feed_manager
    
    def lookup_ioc(self, value: str, ioc_type: str) -> Optional[Dict]:
        """Look up an IOC in the threat intelligence feeds.
        
        Args:
            value: The IOC value to look up
            ioc_type: Type of IOC (ip, domain, hash, url, etc.)
            
        Returns:
            Dict containing threat information if found, None otherwise
        """
        return self.feed_manager.lookup_ioc(value, ioc_type)
    
    def bulk_lookup(self, iocs: List[Dict[str, str]]) -> Dict[str, Dict]:
        """Look up multiple IOCs at once.
        
        Args:
            iocs: List of dicts with 'value' and 'type' keys
            
        Returns:
            Dict mapping IOC values to their threat information
        """
        results = {}
        for ioc in iocs:
            result = self.lookup_ioc(ioc['value'], ioc['type'])
            if result:
                results[ioc['value']] = result
        return results
    
    def get_feed_status(self) -> List[Dict[str, Any]]:
        """Get the status of all threat feeds.
        
        Returns:
            List of dicts containing feed status information
        """
        return self.feed_manager.get_feed_status()
    
    def is_malicious(self, value: str, ioc_type: str) -> bool:
        """Check if an IOC is known to be malicious.
        
        Args:
            value: The IOC value to check
            ioc_type: Type of IOC
            
        Returns:
            bool: True if the IOC is known to be malicious
        """
        result = self.lookup_ioc(value, ioc_type)
        return result is not None and result.get('malicious', False)
    
    def get_malicious_indicators(self, ioc_type: Optional[str] = None) -> List[Dict]:
        """Get all known malicious indicators.
        
        Args:
            ioc_type: Optional filter for indicator type
            
        Returns:
            List of malicious indicators
        """
        indicators = []
        for feed_name, feed in self.feed_manager.feeds.items():
            if hasattr(feed, 'iocs'):
                for ioc_type_key, iocs in feed.iocs.items():
                    if ioc_type and ioc_type_key != ioc_type:
                        continue
                    for ioc_value, ioc_data in iocs.items():
                        if ioc_data.get('malicious', False):
                            indicators.append({
                                'value': ioc_value,
                                'type': ioc_type_key,
                                'source': feed_name,
                                'first_seen': ioc_data.get('first_seen'),
                                'last_seen': ioc_data.get('last_seen'),
                                'tags': ioc_data.get('tags', [])
                            })
        return indicators

# Example usage
if __name__ == "__main__":
    # Initialize feed manager with configuration
    from feed_manager import ThreatFeedManager
    
    config = {
        'cache_ttl': 3600,
        'feeds': {
            'alienvault_otx': {
                'enabled': False,  # Disabled for testing
            },
            'mitre_attack': {
                'enabled': True
            }
        }
    }
    
    with ThreatFeedManager(config) as feed_manager:
        # Create client
        client = ThreatIntelClient(feed_manager)
        
        # Example lookups
        print(client.lookup_ioc('8.8.8.8', 'ip'))
        print(client.is_malicious('example.com', 'domain'))
        
        # Get feed status
        for status in client.get_feed_status():
            print(f"{status['name']}: {status['ioc_count']} IOCs")
        
        # Get malicious indicators
        print("Malicious indicators:", client.get_malicious_indicators())
