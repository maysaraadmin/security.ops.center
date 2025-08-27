"""
DNS protocol analyzer for the NDR system.
"""
from typing import Dict, Any, Optional
from datetime import datetime

class DNSAnalyzer:
    """Analyzes DNS traffic for security events."""
    
    def __init__(self):
        """Initialize the DNS analyzer."""
        self.suspicious_domains = {
            'example-malicious.com',
            'bad-domain.org',
            # Add more suspicious domains as needed
        }
    
    def analyze(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Analyze a DNS packet for suspicious activity.
        
        Args:
            packet: Dictionary containing DNS packet data
            
        Returns:
            Optional[Dict]: Alert details if suspicious activity is detected, None otherwise
        """
        try:
            # Check for DNS query
            if 'dns' in packet and hasattr(packet['dns'], 'qry_name'):
                domain = packet['dns'].qry_name.lower()
                
                # Check against suspicious domains
                if any(suspicious in domain for suspicious in self.suspicious_domains):
                    return {
                        'timestamp': datetime.now(),
                        'event_type': 'suspicious_dns_query',
                        'severity': 'high',
                        'details': {
                            'domain': domain,
                            'query_type': getattr(packet['dns'], 'qry_type', 'A'),
                            'source_ip': packet['ip'].src if 'ip' in packet else 'unknown',
                            'destination_ip': packet['ip'].dst if 'ip' in packet else 'unknown',
                            'message': f'Suspicious DNS query to {domain}'
                        }
                    }
        except Exception as e:
            # Log error but don't crash
            print(f"Error in DNS analyzer: {e}")
        
        return None
