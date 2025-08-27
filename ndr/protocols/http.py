"""
HTTP protocol analyzer for the NDR system.
"""
from typing import Dict, Any, Optional
from datetime import datetime

class HTTPAnalyzer:
    """Analyzes HTTP traffic for security events."""
    
    def __init__(self):
        """Initialize the HTTP analyzer."""
        self.suspicious_user_agents = {
            'nmap', 'sqlmap', 'metasploit', 'nikto', 'wget', 'curl'
        }
    
    def analyze(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Analyze an HTTP packet for suspicious activity.
        
        Args:
            packet: Dictionary containing HTTP packet data
            
        Returns:
            Optional[Dict]: Alert details if suspicious activity is detected, None otherwise
        """
        try:
            if 'http' in packet:
                http = packet['http']
                
                # Check for suspicious user agents
                if hasattr(http, 'user_agent'):
                    user_agent = http.user_agent.lower()
                    for suspicious in self.suspicious_user_agents:
                        if suspicious in user_agent:
                            return {
                                'timestamp': datetime.now(),
                                'event_type': 'suspicious_user_agent',
                                'severity': 'medium',
                                'details': {
                                    'user_agent': user_agent,
                                    'source_ip': packet['ip'].src if 'ip' in packet else 'unknown',
                                    'destination_ip': packet['ip'].dst if 'ip' in packet else 'unknown',
                                    'method': getattr(http, 'request_method', 'UNKNOWN'),
                                    'uri': getattr(http, 'request_uri', 'UNKNOWN'),
                                    'message': f'Suspicious User-Agent detected: {user_agent}'
                                }
                            }
        except Exception as e:
            # Log error but don't crash
            print(f"Error in HTTP analyzer: {e}")
        
        return None
