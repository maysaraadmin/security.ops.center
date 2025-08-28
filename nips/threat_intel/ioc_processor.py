"""
IOC Processor for NIPS

Processes and matches Indicators of Compromise (IOCs) against network traffic and system events.
"""
import re
import ipaddress
import socket
import hashlib
import base64
from typing import Dict, List, Optional, Tuple, Any, Set, Union, Callable
from urllib.parse import urlparse
import dns.resolver
import logging

# Configure logging
logger = logging.getLogger('nips.threat_intel.ioc_processor')

class IOCProcessor:
    """Processes and matches IOCs against various data types."""
    
    def __init__(self, feed_manager, config: Optional[Dict[str, Any]] = None):
        """Initialize the IOC processor.
        
        Args:
            feed_manager: Instance of ThreatFeedManager
            config: Configuration dictionary
        """
        self.feed_manager = feed_manager
        self.config = config or {}
        self.domain_regex = re.compile(
            r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$',
            re.IGNORECASE
        )
        self.url_regex = re.compile(
            r'^(https?|ftp)://'  # Scheme
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # Domain
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
            r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
            r'(?::\d+)?'  # Optional port
            r'(?:/?|[/?]\S+)$', 
            re.IGNORECASE
        )
        
        # Caches
        self._dns_cache: Dict[str, Tuple[float, List[str]]] = {}
        self._dns_cache_ttl = self.config.get('dns_cache_ttl', 300)  # 5 minutes
        
        # Enable/disable features
        self.enable_dns_lookup = self.config.get('enable_dns_lookup', True)
        self.enable_reverse_dns = self.config.get('enable_reverse_dns', True)
        self.enable_domain_analysis = self.config.get('enable_domain_analysis', True)
        
        # Custom matchers
        self.custom_matchers: List[Callable] = []
    
    def process_network_packet(self, packet: Dict) -> List[Dict]:
        """Process a network packet for IOCs.
        
        Args:
            packet: Dictionary containing packet data
            
        Returns:
            List of match results (empty if no matches)
        """
        matches = []
        
        # Extract packet data
        src_ip = packet.get('src_ip')
        dst_ip = packet.get('dst_ip')
        src_port = packet.get('src_port')
        dst_port = packet.get('dst_port')
        protocol = packet.get('protocol', '').lower()
        
        # Check source and destination IPs
        if src_ip:
            if match := self.check_ip(src_ip):
                match.update({
                    'context': 'source_ip',
                    'packet': {
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'protocol': protocol
                    }
                })
                matches.append(match)
        
        if dst_ip:
            if match := self.check_ip(dst_ip):
                match.update({
                    'context': 'destination_ip',
                    'packet': {
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'protocol': protocol
                    }
                })
                matches.append(match)
        
        # Check DNS queries and responses
        if 'dns' in packet:
            dns_matches = self._check_dns(packet['dns'])
            matches.extend(dns_matches)
        
        # Check HTTP requests
        if 'http' in packet:
            http_matches = self._check_http(packet['http'])
            matches.extend(http_matches)
        
        # Check TLS/SSL data
        if 'tls' in packet:
            tls_matches = self._check_tls(packet['tls'])
            matches.extend(tls_matches)
        
        # Run custom matchers
        for matcher in self.custom_matchers:
            try:
                custom_matches = matcher(packet)
                if custom_matches:
                    if isinstance(custom_matches, dict):
                        matches.append(custom_matches)
                    else:
                        matches.extend(custom_matches)
            except Exception as e:
                logger.error(f"Error in custom matcher: {e}")
        
        return matches
    
    def check_ip(self, ip: str) -> Optional[Dict]:
        """Check an IP address against threat feeds.
        
        Args:
            ip: IP address to check
            
        Returns:
            Match dictionary if found, None otherwise
        """
        # Basic IP validation
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return None
        
        # Check IP in threat feeds
        if match := self.feed_manager.lookup_ioc(ip, 'ip'):
            return {
                'type': 'ip',
                'value': ip,
                'match': match,
                'timestamp': datetime.utcnow().isoformat()
            }
        
        # Optional: Check reverse DNS
        if self.enable_reverse_dns:
            try:
                hostnames = self._reverse_dns_lookup(ip)
                for hostname in hostnames:
                    if domain_match := self.check_domain(hostname):
                        return {
                            'type': 'ip',
                            'value': ip,
                            'hostname': hostname,
                            'match': domain_match['match'],
                            'context': 'reverse_dns',
                            'timestamp': datetime.utcnow().isoformat()
                        }
            except Exception as e:
                logger.debug(f"Reverse DNS lookup failed for {ip}: {e}")
        
        return None
    
    def check_domain(self, domain: str) -> Optional[Dict]:
        """Check a domain name against threat feeds.
        
        Args:
            domain: Domain name to check
            
        Returns:
            Match dictionary if found, None otherwise
        """
        if not self._is_valid_domain(domain):
            return None
        
        # Check domain in threat feeds
        if match := self.feed_manager.lookup_ioc(domain, 'domain'):
            return {
                'type': 'domain',
                'value': domain,
                'match': match,
                'timestamp': datetime.utcnow().isoformat()
            }
        
        # Optional: Check subdomains
        if '.' in domain and self.enable_domain_analysis:
            parts = domain.split('.')
            for i in range(1, len(parts) - 1):  # Skip TLD and full domain
                subdomain = '.'.join(parts[i:])
                if subdomain_match := self.feed_manager.lookup_ioc(subdomain, 'domain'):
                    return {
                        'type': 'domain',
                        'value': domain,
                        'matched_subdomain': subdomain,
                        'match': subdomain_match,
                        'context': 'subdomain_match',
                        'timestamp': datetime.utcnow().isoformat()
                    }
        
        # Optional: Check DNS resolution
        if self.enable_dns_lookup:
            try:
                resolved_ips = self._dns_lookup(domain)
                for ip in resolved_ips:
                    if ip_match := self.feed_manager.lookup_ioc(ip, 'ip'):
                        return {
                            'type': 'domain',
                            'value': domain,
                            'resolved_ip': ip,
                            'match': ip_match,
                            'context': 'dns_resolution',
                            'timestamp': datetime.utcnow().isoformat()
                        }
            except Exception as e:
                logger.debug(f"DNS lookup failed for {domain}: {e}")
        
        return None
    
    def check_url(self, url: str) -> Optional[Dict]:
        """Check a URL against threat feeds.
        
        Args:
            url: URL to check
            
        Returns:
            Match dictionary if found, None otherwise
        """
        if not self._is_valid_url(url):
            return None
        
        # Check full URL
        if match := self.feed_manager.lookup_ioc(url, 'url'):
            return {
                'type': 'url',
                'value': url,
                'match': match,
                'timestamp': datetime.utcnow().isoformat()
            }
        
        # Parse URL components
        try:
            parsed = urlparse(url)
            
            # Check domain
            if domain_match := self.check_domain(parsed.netloc):
                return {
                    'type': 'url',
                    'value': url,
                    'component': 'domain',
                    'matched_value': parsed.netloc,
                    'match': domain_match['match'],
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            # Check path components
            for part in parsed.path.split('/'):
                if not part or len(part) < 4:  # Skip short parts
                    continue
                    
                # Check if part looks like a hash
                if len(part) in (32, 40, 64) and all(c in '0123456789abcdef' for c in part.lower()):
                    hash_type = {32: 'md5', 40: 'sha1', 64: 'sha256'}.get(len(part))
                    if hash_type and (hash_match := self.feed_manager.lookup_ioc(part, hash_type)):
                        return {
                            'type': 'url',
                            'value': url,
                            'component': 'path',
                            'matched_value': part,
                            'match': hash_match,
                            'timestamp': datetime.utcnow().isoformat()
                        }
            
            # Check query parameters
            for param in parsed.query.split('&'):
                if '=' in param:
                    name, value = param.split('=', 1)
                    
                    # Check if parameter value is a URL
                    if self._is_valid_url(value):
                        if nested_match := self.check_url(value):
                            return {
                                'type': 'url',
                                'value': url,
                                'component': f'query_param:{name}',
                                'matched_value': value,
                                'match': nested_match['match'],
                                'timestamp': datetime.utcnow().isoformat()
                            }
                    
                    # Check if parameter value is a domain
                    elif self._is_valid_domain(value):
                        if domain_match := self.check_domain(value):
                            return {
                                'type': 'url',
                                'value': url,
                                'component': f'query_param:{name}',
                                'matched_value': value,
                                'match': domain_match['match'],
                                'timestamp': datetime.utcnow().isoformat()
                            }
            
        except Exception as e:
            logger.error(f"Error parsing URL {url}: {e}")
        
        return None
    
    def check_hash(self, hash_value: str, hash_type: Optional[str] = None) -> Optional[Dict]:
        """Check a file hash against threat feeds.
        
        Args:
            hash_value: The hash value to check
            hash_type: Type of hash (md5, sha1, sha256). If None, will try to detect.
            
        Returns:
            Match dictionary if found, None otherwise
        """
        # Determine hash type if not specified
        if not hash_type:
            hash_length = len(hash_value.strip())
            if hash_length == 32:
                hash_type = 'md5'
            elif hash_length == 40:
                hash_type = 'sha1'
            elif hash_length == 64:
                hash_type = 'sha256'
            else:
                return None
        
        # Check hash in threat feeds
        if match := self.feed_manager.lookup_ioc(hash_value.lower(), hash_type):
            return {
                'type': 'hash',
                'hash_type': hash_type,
                'value': hash_value,
                'match': match,
                'timestamp': datetime.utcnow().isoformat()
            }
        
        return None
    
    def check_email(self, email: str) -> Optional[Dict]:
        """Check an email address against threat feeds.
        
        Args:
            email: Email address to check
            
        Returns:
            Match dictionary if found, None otherwise
        """
        if not self._is_valid_email(email):
            return None
        
        # Check email in threat feeds
        if match := self.feed_manager.lookup_ioc(email, 'email'):
            return {
                'type': 'email',
                'value': email,
                'match': match,
                'timestamp': datetime.utcnow().isoformat()
            }
        
        # Check domain part of email
        domain = email.split('@')[-1]
        if domain_match := self.check_domain(domain):
            return {
                'type': 'email',
                'value': email,
                'component': 'domain',
                'matched_value': domain,
                'match': domain_match['match'],
                'timestamp': datetime.utcnow().isoformat()
            }
        
        return None
    
    def add_custom_matcher(self, matcher: Callable):
        """Add a custom matcher function.
        
        Args:
            matcher: Function that takes a data object and returns a match dict or list of match dicts
        """
        self.custom_matchers.append(matcher)
    
    def _check_dns(self, dns_data: Dict) -> List[Dict]:
        """Check DNS data for IOCs."""
        matches = []
        
        # Check DNS queries
        for query in dns_data.get('queries', []):
            if 'name' in query:
                if domain_match := self.check_domain(query['name']):
                    matches.append({
                        'type': 'dns_query',
                        'query': query['name'],
                        'query_type': query.get('type', 'A'),
                        'match': domain_match['match'],
                        'timestamp': datetime.utcnow().isoformat()
                    })
        
        # Check DNS answers
        for answer in dns_data.get('answers', []):
            if 'data' in answer:
                data = answer['data']
                answer_type = answer.get('type', '')
                
                if answer_type in ('A', 'AAAA') and self._is_valid_ip(data):
                    if ip_match := self.check_ip(data):
                        matches.append({
                            'type': 'dns_answer',
                            'query': answer.get('name', ''),
                            'answer_type': answer_type,
                            'answer': data,
                            'match': ip_match['match'],
                            'timestamp': datetime.utcnow().isoformat()
                        })
                
                elif answer_type == 'CNAME' and self._is_valid_domain(data.rstrip('.')):
                    if domain_match := self.check_domain(data.rstrip('.')):
                        matches.append({
                            'type': 'dns_answer',
                            'query': answer.get('name', ''),
                            'answer_type': 'CNAME',
                            'answer': data,
                            'match': domain_match['match'],
                            'timestamp': datetime.utcnow().isoformat()
                        })
                
                elif answer_type == 'TXT':
                    # Check for URLs in TXT records
                    if 'http' in data:
                        for word in data.split():
                            if self._is_valid_url(word):
                                if url_match := self.check_url(word):
                                    matches.append({
                                        'type': 'dns_txt',
                                        'query': answer.get('name', ''),
                                        'content': data,
                                        'matched_url': word,
                                        'match': url_match['match'],
                                        'timestamp': datetime.utcnow().isoformat()
                                    })
                                    break
        
        return matches
    
    def _check_http(self, http_data: Dict) -> List[Dict]:
        """Check HTTP data for IOCs."""
        matches = []
        
        # Check Host header and URL
        host = http_data.get('host', '')
        uri = http_data.get('uri', '')
        
        # Check Host header
        if host:
            if domain_match := self.check_domain(host):
                matches.append({
                    'type': 'http_host',
                    'host': host,
                    'method': http_data.get('method', ''),
                    'uri': uri,
                    'match': domain_match['match'],
                    'timestamp': datetime.utcnow().isoformat()
                })
        
        # Check URL path and query
        if uri:
            if url_match := self.check_url(f"http://{host}{uri}" if host else uri):
                matches.append({
                    'type': 'http_url',
                    'url': f"{host}{uri}",
                    'method': http_data.get('method', ''),
                    'match': url_match['match'],
                    'timestamp': datetime.utcnow().isoformat()
                })
        
        # Check headers
        for header, value in http_data.get('headers', {}).items():
            # Check for URLs in headers
            if 'http' in value.lower() and '://' in value:
                for word in value.split():
                    if self._is_valid_url(word):
                        if url_match := self.check_url(word):
                            matches.append({
                                'type': 'http_header',
                                'header': header,
                                'value': value,
                                'matched_url': word,
                                'match': url_match['match'],
                                'timestamp': datetime.utcnow().isoformat()
                            })
                            break
            
            # Check for domains in headers
            elif '.' in value and any(x in header.lower() for x in ['host', 'referer', 'origin', 'server']):
                for word in re.findall(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', value):
                    if self._is_valid_domain(word):
                        if domain_match := self.check_domain(word):
                            matches.append({
                                'type': 'http_header',
                                'header': header,
                                'value': value,
                                'matched_domain': word,
                                'match': domain_match['match'],
                                'timestamp': datetime.utcnow().isoformat()
                            })
                            break
        
        # Check request body for IOCs
        if 'body' in http_data:
            body = http_data['body']
            
            # Check for URLs in body
            if isinstance(body, str) and 'http' in body:
                for url in re.findall(r'https?://[^\s\"\'<>\]\),]+', body):
                    if self._is_valid_url(url):
                        if url_match := self.check_url(url):
                            matches.append({
                                'type': 'http_body',
                                'content_type': http_data.get('content_type', ''),
                                'matched_url': url,
                                'match': url_match['match'],
                                'timestamp': datetime.utcnow().isoformat()
                            })
                            break
            
            # Check for base64 encoded data
            if isinstance(body, str) and 'base64' in http_data.get('content_type', '').lower():
                try:
                    # Try to decode base64
                    decoded = base64.b64decode(body).decode('utf-8', errors='ignore')
                    
                    # Check for URLs in decoded data
                    if 'http' in decoded:
                        for url in re.findall(r'https?://[^\s\"\'<>\]\),]+', decoded):
                            if self._is_valid_url(url):
                                if url_match := self.check_url(url):
                                    matches.append({
                                        'type': 'http_body_base64',
                                        'content_type': http_data.get('content_type', ''),
                                        'matched_url': url,
                                        'match': url_match['match'],
                                        'timestamp': datetime.utcnow().isoformat()
                                    })
                                    break
                    
                    # Check for domains in decoded data
                    for domain in re.findall(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', decoded):
                        if self._is_valid_domain(domain):
                            if domain_match := self.check_domain(domain):
                                matches.append({
                                    'type': 'http_body_base64',
                                    'content_type': http_data.get('content_type', ''),
                                    'matched_domain': domain,
                                    'match': domain_match['match'],
                                    'timestamp': datetime.utcnow().isoformat()
                                })
                                break
                    
                except Exception as e:
                    logger.debug(f"Failed to decode base64 content: {e}")
        
        return matches
    
    def _check_tls(self, tls_data: Dict) -> List[Dict]:
        """Check TLS/SSL data for IOCs."""
        matches = []
        
        # Check server name (SNI)
        if 'server_name' in tls_data:
            if domain_match := self.check_domain(tls_data['server_name']):
                matches.append({
                    'type': 'tls_sni',
                    'server_name': tls_data['server_name'],
                    'match': domain_match['match'],
                    'timestamp': datetime.utcnow().isoformat()
                })
        
        # Check certificate subjects and issuers
        if 'certificates' in tls_data:
            for cert in tls_data['certificates']:
                # Check subject common name
                if 'subject' in cert and 'common_name' in cert['subject']:
                    if domain_match := self.check_domain(cert['subject']['common_name']):
                        matches.append({
                            'type': 'tls_cert_subject',
                            'subject': cert['subject']['common_name'],
                            'match': domain_match['match'],
                            'timestamp': datetime.utcnow().isoformat()
                        })
                
                # Check subject alternative names
                if 'extensions' in cert and 'subject_alt_name' in cert['extensions']:
                    for name in cert['extensions']['subject_alt_name']:
                        if isinstance(name, str) and self._is_valid_domain(name):
                            if domain_match := self.check_domain(name):
                                matches.append({
                                    'type': 'tls_cert_san',
                                    'san': name,
                                    'match': domain_match['match'],
                                    'timestamp': datetime.utcnow().isoformat()
                                })
                
                # Check issuer
                if 'issuer' in cert and 'common_name' in cert['issuer']:
                    if domain_match := self.check_domain(cert['issuer']['common_name']):
                        matches.append({
                            'type': 'tls_cert_issuer',
                            'issuer': cert['issuer']['common_name'],
                            'match': domain_match['match'],
                            'timestamp': datetime.utcnow().isoformat()
                        })
                
                # Check certificate fingerprint (SHA-1)
                if 'fingerprint' in cert and 'sha1' in cert['fingerprint']:
                    if hash_match := self.check_hash(cert['fingerprint']['sha1'], 'sha1'):
                        matches.append({
                            'type': 'tls_cert_fingerprint',
                            'fingerprint': cert['fingerprint']['sha1'],
                            'hash_type': 'sha1',
                            'match': hash_match['match'],
                            'timestamp': datetime.utcnow().isoformat()
                        })
        
        return matches
    
    def _dns_lookup(self, domain: str) -> List[str]:
        """Perform DNS lookup with caching."""
        now = time.time()
        
        # Check cache
        if domain in self._dns_cache:
            cached_time, ips = self._dns_cache[domain]
            if now - cached_time < self._dns_cache_ttl:
                return ips
        
        # Perform DNS lookup
        try:
            answers = dns.resolver.resolve(domain, 'A')
            ips = [str(r) for r in answers]
            
            # Update cache
            self._dns_cache[domain] = (now, ips)
            return ips
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException) as e:
            logger.debug(f"DNS lookup failed for {domain}: {e}")
            return []
    
    def _reverse_dns_lookup(self, ip: str) -> List[str]:
        """Perform reverse DNS lookup with caching."""
        try:
            # Check cache first
            if ip in self._dns_cache:
                cached_time, hostnames = self._dns_cache[ip]
                if time.time() - cached_time < self._dns_cache_ttl:
                    return hostnames
            
            # Perform reverse lookup
            hostnames = []
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                if hostname:
                    hostnames.append(hostname)
            except (socket.herror, socket.gaierror):
                pass
            
            # Update cache
            self._dns_cache[ip] = (time.time(), hostnames)
            return hostnames
            
        except Exception as e:
            logger.debug(f"Reverse DNS lookup failed for {ip}: {e}")
            return []
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Check if a string is a valid domain name."""
        if not domain or len(domain) > 253:
            return False
        
        # Check each label
        labels = domain.split('.')
        if len(labels) < 2:  # At least domain.tld
            return False
        
        for label in labels:
            if not label or len(label) > 63:
                return False
            if not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$', label, re.IGNORECASE):
                return False
        
        # Check TLD
        tld = labels[-1]
        if not re.match(r'^[a-z]{2,}$', tld, re.IGNORECASE):
            return False
        
        return True
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if a string is a valid IP address."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if a string is a valid URL."""
        try:
            result = urlparse(url)
            return all([result.scheme in ('http', 'https', 'ftp'), 
                       result.netloc,
                       '.' in result.netloc])
        except (ValueError, AttributeError):
            return False
    
    def _is_valid_email(self, email: str) -> bool:
        """Check if a string is a valid email address."""
        if not email or '@' not in email:
            return False
            
        # Simple regex for basic validation
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))


# Example usage
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    # Example configuration
    config = {
        'enable_dns_lookup': True,
        'enable_reverse_dns': True,
        'enable_domain_analysis': True,
        'dns_cache_ttl': 300  # 5 minutes
    }
    
    # Create a mock feed manager for testing
    class MockFeedManager:
        def lookup_ioc(self, value, ioc_type):
            # Mock some known bad IOCs
            bad_ips = {'8.8.8.8', '1.1.1.1'}
            bad_domains = {'example.com', 'malicious.org'}
            bad_hashes = {
                'md5': {'d41d8cd98f00b204e9800998ecf8427e': 'Test MD5'},
                'sha1': {'da39a3ee5e6b4b0d3255bfef95601890afd80709': 'Test SHA1'},
                'sha256': {'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855': 'Test SHA256'}
            }
            
            if ioc_type == 'ip' and value in bad_ips:
                return {'source': 'test', 'threat': 'malicious_ip', 'confidence': 90}
            elif ioc_type == 'domain' and value in bad_domains:
                return {'source': 'test', 'threat': 'malicious_domain', 'confidence': 85}
            elif ioc_type in bad_hashes and value in bad_hashes[ioc_type]:
                return {'source': 'test', 'threat': bad_hashes[ioc_type][value], 'confidence': 95}
            
            return None
    
    # Initialize IOC processor
    processor = IOCProcessor(MockFeedManager(), config)
    
    # Test some IOCs
    test_cases = [
        ('8.8.8.8', 'ip'),
        ('example.com', 'domain'),
        ('d41d8cd98f00b204e9800998ecf8427e', 'md5'),
        ('http://example.com/path?param=value', 'url'),
        ('test@example.com', 'email')
    ]
    
    for value, ioc_type in test_cases:
        if ioc_type == 'ip':
            result = processor.check_ip(value)
        elif ioc_type == 'domain':
            result = processor.check_domain(value)
        elif ioc_type in ('md5', 'sha1', 'sha256'):
            result = processor.check_hash(value, ioc_type)
        elif ioc_type == 'url':
            result = processor.check_url(value)
        elif ioc_type == 'email':
            result = processor.check_email(value)
        else:
            result = None
        
        if result:
            print(f"Match found for {ioc_type} '{value}': {result}")
        else:
            print(f"No match for {ioc_type} '{value}'")
