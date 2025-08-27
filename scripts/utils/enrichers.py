"""
Log Enrichment Module for Enhanced Log Collector.
"""

import os
import json
import socket
import geoip2.database
import requests
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime, timezone
from functools import lru_cache
from ipaddress import ip_address, IPv4Address, IPv6Address

class BaseEnricher:
    """Base class for all log enrichers."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the enricher.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(f'siem.enricher.{self.__class__.__name__}')
    
    def enrich(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a log entry.
        
        Args:
            entry: The log entry to enrich
            
        Returns:
            The enriched log entry
        """
        return entry
    
    def __call__(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Make the enricher callable."""
        return self.enrich(entry)

class GeoIPEnricher(BaseEnricher):
    """Enriches logs with GeoIP information."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the GeoIP enricher.
        
        Args:
            config: Configuration dictionary with 'geoip_db_path' key
        """
        super().__init__(config)
        self.db_path = self.config.get('geoip_db_path', 'GeoLite2-City.mmdb')
        self._reader = None
    
    @property
    def reader(self):
        """Lazy-load the GeoIP database reader."""
        if self._reader is None and os.path.exists(self.db_path):
            try:
                self._reader = geoip2.database.Reader(self.db_path)
            except Exception as e:
                self.logger.error(f"Failed to load GeoIP database: {e}")
        return self._reader
    
    def enrich(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a log entry with GeoIP information."""
        if not self.reader:
            return entry
            
        try:
            # Get the IP address from common fields
            ip_field = self._find_ip_address(entry)
            if not ip_field or not ip_field[1]:
                return entry
                
            ip = ip_field[1]
            
            # Skip private and non-IP addresses
            if not self._is_public_ip(ip):
                return entry
                
            # Look up the IP in the GeoIP database
            try:
                response = self.reader.city(ip)
                
                # Add GeoIP information to the entry
                if 'geoip' not in entry:
                    entry['geoip'] = {}
                    
                entry['geoip'].update({
                    'ip': ip,
                    'country_iso_code': response.country.iso_code,
                    'country_name': response.country.name,
                    'city_name': response.city.name,
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude,
                    'timezone': response.location.time_zone,
                    'continent': response.continent.name,
                    'continent_code': response.continent.code,
                    'postal_code': response.postal.code if response.postal else None,
                    'subdivisions': [sub.name for sub in response.subdivisions],
                    'subdivisions_iso': [sub.iso_code for sub in response.subdivisions]
                })
                
            except Exception as e:
                self.logger.debug(f"GeoIP lookup failed for {ip}: {e}")
                
        except Exception as e:
            self.logger.error(f"Error in GeoIP enrichment: {e}")
            
        return entry
    
    def _find_ip_address(self, entry: Dict[str, Any]) -> Optional[tuple]:
        """Find an IP address in the log entry."""
        ip_fields = [
            'client_ip', 'src_ip', 'source_ip', 'ip', 'remote_ip',
            'source.address', 'client.address', 'source.ip', 'client.ip'
        ]
        
        for field in ip_fields:
            if '.' in field:  # Handle nested fields
                parts = field.split('.')
                value = entry
                for part in parts:
                    if isinstance(value, dict) and part in value:
                        value = value[part]
                    else:
                        value = None
                        break
            else:
                value = entry.get(field)
                
            if value and self._is_valid_ip(value):
                return (field, value)
                
        return None
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if a string is a valid IP address."""
        try:
            ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _is_public_ip(self, ip: str) -> bool:
        """Check if an IP address is public."""
        try:
            ip_obj = ip_address(ip)
            return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local)
        except ValueError:
            return False

class ThreatIntelEnricher(BaseEnricher):
    """Enriches logs with threat intelligence information."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the Threat Intelligence enricher.
        
        Args:
            config: Configuration dictionary with 'api_key' and 'sources' keys
        """
        super().__init__(config)
        self.api_key = self.config.get('api_key')
        self.sources = self.config.get('sources', ['virustotal', 'abuseipdb'])
        self.cache = {}
        self.cache_ttl = self.config.get('cache_ttl', 86400)  # 24 hours
    
    def enrich(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a log entry with threat intelligence information."""
        if not self.api_key:
            self.logger.warning("No API key provided for Threat Intelligence")
            return entry
            
        try:
            # Get the IP address from the entry
            ip_field, ip = self._find_ip_address(entry)
            if not ip or not ip_field:
                return entry
                
            # Check cache first
            cache_key = f"{ip}:{':'.join(self.sources)}"
            if cache_key in self.cache:
                cached = self.cache[cache_key]
                if (datetime.now(timezone.utc) - cached['timestamp']).total_seconds() < self.cache_ttl:
                    self._add_threat_intel(entry, cached['data'], ip_field)
                    return entry
            
            # Query threat intelligence sources
            ti_data = {}
            
            if 'virustotal' in self.sources:
                ti_data.update(self._query_virustotal(ip))
                
            if 'abuseipdb' in self.sources:
                ti_data.update(self._query_abuseipdb(ip))
                
            if 'alienvault' in self.sources:
                ti_data.update(self._query_alienvault(ip))
            
            # Update cache
            self.cache[cache_key] = {
                'timestamp': datetime.now(timezone.utc),
                'data': ti_data
            }
            
            # Add threat intelligence to the entry
            self._add_threat_intel(entry, ti_data, ip_field)
            
        except Exception as e:
            self.logger.error(f"Error in Threat Intelligence enrichment: {e}")
            
        return entry
    
    def _find_ip_address(self, entry: Dict[str, Any]) -> tuple:
        """Find an IP address in the log entry."""
        ip_fields = [
            'client_ip', 'src_ip', 'source_ip', 'ip', 'remote_ip',
            'source.address', 'client.address', 'source.ip', 'client.ip'
        ]
        
        for field in ip_fields:
            if '.' in field:  # Handle nested fields
                parts = field.split('.')
                value = entry
                for part in parts:
                    if isinstance(value, dict) and part in value:
                        value = value[part]
                    else:
                        value = None
                        break
            else:
                value = entry.get(field)
                
            if value and self._is_valid_ip(value):
                return (field, value)
                
        return (None, None)
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if a string is a valid IP address."""
        try:
            ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _query_virustotal(self, ip: str) -> Dict[str, Any]:
        """Query VirusTotal for threat intelligence."""
        result = {}
        
        try:
            headers = {
                'x-apikey': self.api_key,
                'Accept': 'application/json'
            }
            
            response = requests.get(
                f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                result['virustotal'] = {
                    'asn': attributes.get('asn'),
                    'as_owner': attributes.get('as_owner'),
                    'country': attributes.get('country'),
                    'last_analysis_stats': attributes.get('last_analysis_stats', {}),
                    'reputation': attributes.get('reputation'),
                    'tags': attributes.get('tags', []),
                    'total_votes': attributes.get('total_votes', {})
                }
                
        except Exception as e:
            self.logger.warning(f"VirusTotal query failed: {e}")
            
        return result
    
    def _query_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Query AbuseIPDB for threat intelligence."""
        result = {}
        
        try:
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip,
                'maxAgeInDays': '90',
                'verbose': ''
            }
            
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers=headers,
                params=params,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                data = data.get('data', {})
                
                result['abuseipdb'] = {
                    'abuse_confidence_score': data.get('abuseConfidenceScore'),
                    'country_code': data.get('countryCode'),
                    'domain': data.get('domain'),
                    'is_whitelisted': data.get('isWhitelisted'),
                    'isp': data.get('isp'),
                    'is_tor': data.get('isTor'),
                    'total_reports': data.get('totalReports'),
                    'last_reported_at': data.get('lastReportedAt')
                }
                
        except Exception as e:
            self.logger.warning(f"AbuseIPDB query failed: {e}")
            
        return result
    
    def _query_alienvault(self, ip: str) -> Dict[str, Any]:
        """Query AlienVault OTX for threat intelligence."""
        result = {}
        
        try:
            headers = {
                'X-OTX-API-KEY': self.api_key,
                'Accept': 'application/json'
            }
            
            response = requests.get(
                f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general',
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                
                result['alienvault'] = {
                    'pulse_info': {
                        'count': data.get('pulse_info', {}).get('count', 0),
                        'pulses': [p.get('name') for p in data.get('pulse_info', {}).get('pulses', [])]
                    },
                    'reputation': data.get('reputation'),
                    'country_code': data.get('country_code'),
                    'city': data.get('city'),
                    'asn': data.get('asn')
                }
                
        except Exception as e:
            self.logger.warning(f"AlienVault OTX query failed: {e}")
            
        return result
    
    def _add_threat_intel(self, entry: Dict[str, Any], ti_data: Dict[str, Any], ip_field: str) -> None:
        """Add threat intelligence data to the log entry."""
        if not ti_data:
            return
            
        # Add threat intel to the entry
        if 'threat' not in entry:
            entry['threat'] = {}
            
        entry['threat'].update(ti_data)
        
        # Add a threat indicator if any source reported something suspicious
        if any(ti_data.values()):
            entry['threat']['indicator'] = True
            
            # Add the IP field that was used for the lookup
            entry['threat']['indicator_field'] = ip_field

class DomainEnricher(BaseEnricher):
    """Enriches logs with domain information."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the Domain enricher."""
        super().__init__(config)
        self.cache = {}
        self.cache_ttl = self.config.get('cache_ttl', 86400)  # 24 hours
    
    def enrich(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a log entry with domain information."""
        try:
            # Get the domain from the entry
            domain_field, domain = self._find_domain(entry)
            if not domain or not domain_field:
                return entry
                
            # Skip IP addresses
            if self._is_ip_address(domain):
                return entry
                
            # Check cache first
            cache_key = f"domain:{domain}"
            if cache_key in self.cache:
                cached = self.cache[cache_key]
                if (datetime.now(timezone.utc) - cached['timestamp']).total_seconds() < self.cache_ttl:
                    self._add_domain_info(entry, cached['data'], domain_field)
                    return entry
            
            # Get domain information
            domain_info = self._get_domain_info(domain)
            
            # Update cache
            self.cache[cache_key] = {
                'timestamp': datetime.now(timezone.utc),
                'data': domain_info
            }
            
            # Add domain information to the entry
            self._add_domain_info(entry, domain_info, domain_field)
            
        except Exception as e:
            self.logger.error(f"Error in Domain enrichment: {e}")
            
        return entry
    
    def _find_domain(self, entry: Dict[str, Any]) -> tuple:
        """Find a domain in the log entry."""
        domain_fields = [
            'domain', 'hostname', 'url', 'host', 'server_name',
            'http.host', 'url.domain', 'url.host', 'url.domain',
            'source.domain', 'destination.domain', 'dns.question.name'
        ]
        
        for field in domain_fields:
            if '.' in field:  # Handle nested fields
                parts = field.split('.')
                value = entry
                for part in parts:
                    if isinstance(value, dict) and part in value:
                        value = value[part]
                    else:
                        value = None
                        break
            else:
                value = entry.get(field)
                
            if value and isinstance(value, str) and '.' in value and not value.startswith(('http://', 'https://')):
                # Basic domain validation
                if any(c.isalpha() for c in value):
                    return (field, value)
                
        return (None, None)
    
    def _is_ip_address(self, value: str) -> bool:
        """Check if a string is an IP address."""
        try:
            ip_address(value)
            return True
        except ValueError:
            return False
    
    def _get_domain_info(self, domain: str) -> Dict[str, Any]:
        """Get information about a domain."""
        result = {
            'domain': domain,
            'tld': self._get_tld(domain),
            'is_public_suffix': self._is_public_suffix(domain)
        }
        
        # Add DNS resolution
        try:
            result['resolved_ips'] = [str(ip) for ip in self._resolve_dns(domain)]
        except Exception as e:
            self.logger.debug(f"DNS resolution failed for {domain}: {e}")
            result['resolved_ips'] = []
            
        return result
    
    def _get_tld(self, domain: str) -> str:
        """Get the top-level domain."""
        # Simple TLD extraction (can be improved with tldextract)
        return domain.split('.')[-1] if '.' in domain else ''
    
    def _is_public_suffix(self, domain: str) -> bool:
        """Check if a domain is a public suffix."""
        # This is a simplified check
        tld = self._get_tld(domain)
        return tld in ('com', 'org', 'net', 'io', 'co', 'uk', 'de', 'jp')
    
    def _resolve_dns(self, domain: str) -> List[str]:
        """Resolve a domain to IP addresses."""
        try:
            return [addr[4][0] for addr in socket.getaddrinfo(domain, None)]
        except socket.gaierror:
            return []
    
    def _add_domain_info(self, entry: Dict[str, Any], domain_info: Dict[str, Any], domain_field: str) -> None:
        """Add domain information to the log entry."""
        if 'domain_info' not in entry:
            entry['domain_info'] = {}
            
        entry['domain_info'].update(domain_info)
        entry['domain_info']['source_field'] = domain_field

class EnrichmentPipeline:
    """Pipeline for applying multiple enrichers to log entries."""
    
    def __init__(self, enrichers: Optional[List[BaseEnricher]] = None):
        """Initialize the enrichment pipeline.
        
        Args:
            enrichers: List of enrichers to apply
        """
        self.enrichers = enrichers or []
        self.logger = logging.getLogger('siem.enrichment_pipeline')
    
    def add_enricher(self, enricher: BaseEnricher) -> None:
        """Add an enricher to the pipeline."""
        self.enrichers.append(enricher)
    
    def enrich(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Apply all enrichers to a log entry."""
        try:
            for enricher in self.enrichers:
                entry = enricher.enrich(entry)
        except Exception as e:
            self.logger.error(f"Error in enrichment pipeline: {e}")
            
        return entry
    
    def __call__(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Make the pipeline callable."""
        return self.enrich(entry)

# Example usage
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    # Create enrichers
    geoip_enricher = GeoIPEnricher({'geoip_db_path': 'GeoLite2-City.mmdb'})
    threat_intel_enricher = ThreatIntelEnricher({'api_key': 'your-api-key'})
    domain_enricher = DomainEnricher()
    
    # Create pipeline
    pipeline = EnrichmentPipeline([
        geoip_enricher,
        threat_intel_enricher,
        domain_enricher
    ])
    
    # Example log entry
    log_entry = {
        'timestamp': datetime.utcnow().isoformat(),
        'source_ip': '8.8.8.8',
        'destination_domain': 'example.com',
        'event_type': 'connection'
    }
    
    # Enrich the log entry
    enriched_entry = pipeline.enrich(log_entry)
    print(json.dumps(enriched_entry, indent=2))
