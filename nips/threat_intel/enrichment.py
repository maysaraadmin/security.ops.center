"""
Threat Intelligence Enrichment for NIPS

Provides enrichment capabilities for threat intelligence data.
"""
import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import socket
import ipaddress
import dns.resolver
import whois
from dataclasses import dataclass, field

logger = logging.getLogger('nips.enrichment')

@dataclass
class EnrichmentResult:
    """Container for enrichment results."""
    success: bool
    data: Dict[str, Any]
    error: Optional[str] = None
    source: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)

class ThreatEnrichment:
    """Provides threat intelligence enrichment capabilities."""
    
    def __init__(self, intel_client=None, config: Optional[Dict[str, Any]] = None):
        """Initialize the enrichment service.
        
        Args:
            intel_client: Optional ThreatIntelClient instance
            config: Configuration dictionary
        """
        self.intel_client = intel_client
        self.config = config or {}
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = self.config.get('dns_timeout', 2.0)
        self.dns_resolver.lifetime = self.config.get('dns_lifetime', 3.0)
        
        # Cache for enrichment results
        self._cache: Dict[str, EnrichmentResult] = {}
        self._cache_ttl = self.config.get('cache_ttl', 300)  # 5 minutes
    
    def enrich_ip(self, ip_address: str) -> EnrichmentResult:
        """Enrich an IP address with additional context.
        
        Args:
            ip_address: IP address to enrich
            
        Returns:
            EnrichmentResult containing enrichment data
        """
        cache_key = f"ip:{ip_address}"
        if cached := self._get_cached(cache_key):
            return cached
            
        result = EnrichmentResult(False, {})
        
        try:
            # Basic IP validation
            ip_obj = ipaddress.ip_address(ip_address)
            
            # Get threat intel if available
            if self.intel_client:
                intel = self.intel_client.lookup_ioc(ip_address, 'ip')
                if intel:
                    result.data['threat_intel'] = intel
            
            # Get reverse DNS
            try:
                hostnames = socket.gethostbyaddr(ip_address)
                result.data['reverse_dns'] = hostnames[0]
                result.data['hostnames'] = hostnames[1]
            except (socket.herror, socket.gaierror):
                pass
                
            # Get ASN and network info
            try:
                asn_info = self._get_asn_info(ip_address)
                if asn_info:
                    result.data.update(asn_info)
            except Exception as e:
                logger.debug(f"Failed to get ASN info for {ip_address}: {e}")
            
            result.success = True
            
        except ValueError as e:
            result.error = f"Invalid IP address: {e}"
        except Exception as e:
            result.error = f"Enrichment failed: {e}"
            logger.exception(f"Error enriching IP {ip_address}")
        
        self._cache_result(cache_key, result)
        return result
    
    def enrich_domain(self, domain: str) -> EnrichmentResult:
        """Enrich a domain name with additional context.
        
        Args:
            domain: Domain name to enrich
            
        Returns:
            EnrichmentResult containing enrichment data
        """
        cache_key = f"domain:{domain.lower()}"
        if cached := self._get_cached(cache_key):
            return cached
            
        result = EnrichmentResult(False, {})
        
        try:
            # Get threat intel if available
            if self.intel_client:
                intel = self.intel_client.lookup_ioc(domain, 'domain')
                if intel:
                    result.data['threat_intel'] = intel
            
            # Get DNS resolution
            try:
                answers = self.dns_resolver.resolve(domain, 'A')
                result.data['a_records'] = [str(r) for r in answers]
                
                # Get MX records if available
                try:
                    mx_answers = self.dns_resolver.resolve(domain, 'MX')
                    result.data['mx_records'] = [str(r.exchange) for r in mx_answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                    pass
                    
                # Get TXT records if available
                try:
                    txt_answers = self.dns_resolver.resolve(domain, 'TXT')
                    result.data['txt_records'] = [r.to_text() for r in txt_answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                    pass
                    
            except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as e:
                result.error = f"DNS resolution failed: {e}"
                self._cache_result(cache_key, result)
                return result
                
            # Get WHOIS information
            try:
                w = whois.whois(domain)
                if w:
                    result.data['whois'] = {
                        'registrar': w.registrar,
                        'creation_date': w.creation_date,
                        'expiration_date': w.expiration_date,
                        'name_servers': w.name_servers,
                        'status': w.status
                    }
            except Exception as e:
                logger.debug(f"WHOIS lookup failed for {domain}: {e}")
            
            result.success = True
            
        except Exception as e:
            result.error = f"Enrichment failed: {e}"
            logger.exception(f"Error enriching domain {domain}")
        
        self._cache_result(cache_key, result)
        return result
    
    def _get_asn_info(self, ip_address: str) -> Dict[str, Any]:
        """Get ASN information for an IP address."""
        # This is a simplified version - in production, you'd use a service like
        # Team Cymru, MaxMind, or IP-API to get more detailed ASN information
        try:
            # Try to get AS info from socket
            asn_info = socket.getnameinfo((ip_address, 0), 0)
            return {
                'asn': asn_info[0],
                'as_org': asn_info[1]
            }
        except (socket.herror, socket.gaierror):
            return {}
    
    def _get_cached(self, key: str) -> Optional[EnrichmentResult]:
        """Get a cached enrichment result if it exists and is fresh."""
        if key in self._cache:
            result = self._cache[key]
            if (datetime.utcnow() - result.timestamp).total_seconds() < self._cache_ttl:
                return result
            del self._cache[key]
        return None
    
    def _cache_result(self, key: str, result: EnrichmentResult) -> None:
        """Cache an enrichment result."""
        if len(self._cache) > self.config.get('max_cache_size', 1000):
            # Remove the oldest entry if cache is full
            oldest_key = next(iter(self._cache))
            self._cache.pop(oldest_key, None)
        self._cache[key] = result

# Example usage
if __name__ == "__main__":
    import json
    from pprint import pprint
    
    # Initialize with a mock intel client
    enrichment = ThreatEnrichment()
    
    # Test IP enrichment
    print("Enriching IP 8.8.8.8...")
    result = enrichment.enrich_ip("8.8.8.8")
    pprint(result.data)
    
    # Test domain enrichment
    print("\nEnriching domain example.com...")
    result = enrichment.enrich_domain("example.com")
    pprint(result.data)
