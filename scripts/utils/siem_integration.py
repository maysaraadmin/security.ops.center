"""
SIEM Integration Module

This module provides integration with various SIEM solutions to forward security events
and alerts from the EDR system.
"""
import json
import logging
import requests
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)

class SIEMType(Enum):
    """Supported SIEM types"""
    SPLUNK = "splunk"
    ELK = "elastic"
    QRADAR = "qradar"
    ARCSIGHT = "arcsight"
    MICROSOFT_SENTINEL = "azure_sentinel"
    CUSTOM = "custom"

class SIEMEvent:
    """Represents a security event to be sent to SIEM"""
    
    def __init__(
        self,
        event_type: str,
        timestamp: Optional[datetime] = None,
        source: str = "edr_system",
        severity: str = "medium",
        details: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        """
        Initialize a SIEM event.
        
        Args:
            event_type: Type of the event (e.g., 'malware_detected', 'login_failed')
            timestamp: When the event occurred (defaults to now)
            source: Source of the event (e.g., 'edr_agent', 'edr_server')
            severity: Severity level (critical, high, medium, low, info)
            details: Additional event details
            **kwargs: Additional fields to include in the event
        """
        self.event_type = event_type
        self.timestamp = timestamp or datetime.utcnow()
        self.source = source
        self.severity = severity.lower()
        self.details = details or {}
        self.additional_fields = kwargs
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the event to a dictionary"""
        event = {
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "severity": self.severity,
            "details": self.details,
            **self.additional_fields
        }
        return event
    
    def to_json(self) -> str:
        """Convert the event to a JSON string"""
        return json.dumps(self.to_dict(), default=str)

class SIEMIntegration:
    """Base class for SIEM integrations"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the SIEM integration.
        
        Args:
            config: Configuration dictionary with SIEM connection details
        """
        self.config = config
        self.enabled = config.get("enabled", False)
        self.verify_ssl = config.get("verify_ssl", True)
        self.timeout = config.get("timeout", 10)  # seconds
    
    def send_event(self, event: Union[SIEMEvent, Dict[str, Any]]) -> bool:
        """
        Send a single event to the SIEM.
        
        Args:
            event: Event to send (either SIEMEvent or dict)
            
        Returns:
            bool: True if the event was sent successfully, False otherwise
        """
        raise NotImplementedError("Subclasses must implement send_event")
    
    def send_events_batch(self, events: List[Union[SIEMEvent, Dict[str, Any]]]) -> bool:
        """
        Send multiple events to the SIEM in a single batch.
        
        Args:
            events: List of events to send
            
        Returns:
            bool: True if all events were sent successfully, False otherwise
        """
        raise NotImplementedError("Subclasses must implement send_events_batch")
    
    def test_connection(self) -> bool:
        """
        Test the connection to the SIEM.
        
        Returns:
            bool: True if the connection test was successful, False otherwise
        """
        raise NotImplementedError("Subclasses must implement test_connection")

class SplunkIntegration(SIEMIntegration):
    """Integration with Splunk via HTTP Event Collector (HEC)"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.url = config["url"]
        self.token = config["token"]
        self.index = config.get("index", "main")
        self.source_type = config.get("source_type", "edr:security")
        self.host = config.get("host", "edr-system")
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        self.session.headers.update({
            "Authorization": f"Splunk {self.token}",
            "Content-Type": "application/json"
        })
    
    def _prepare_event(self, event: Union[SIEMEvent, Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare an event for sending to Splunk"""
        if isinstance(event, SIEMEvent):
            event_data = event.to_dict()
        else:
            event_data = event
        
        # Format the event for Splunk HEC
        splunk_event = {
            "event": event_data,
            "sourcetype": self.source_type,
            "index": self.index,
            "host": self.host,
            "source": event_data.get("source", "edr_system")
        }
        
        # Add timestamp if not already present
        if "time" not in event_data and "timestamp" in event_data:
            # Convert ISO format timestamp to epoch time
            timestamp = event_data["timestamp"]
            if isinstance(timestamp, str):
                from dateutil import parser
                timestamp = parser.parse(timestamp)
            if hasattr(timestamp, 'timestamp'):
                splunk_event["time"] = timestamp.timestamp()
        
        return splunk_event
    
    def send_event(self, event: Union[SIEMEvent, Dict[str, Any]]) -> bool:
        if not self.enabled:
            return False
        
        try:
            splunk_event = self._prepare_event(event)
            response = self.session.post(
                self.url,
                json=splunk_event,
                timeout=self.timeout
            )
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Failed to send event to Splunk: {str(e)}")
            return False
    
    def send_events_batch(self, events: List[Union[SIEMEvent, Dict[str, Any]]]) -> bool:
        if not self.enabled or not events:
            return False
        
        try:
            # Splunk HEC supports multiple events in a single request
            splunk_events = [self._prepare_event(event) for event in events]
            response = self.session.post(
                self.url,
                json=splunk_events,
                timeout=self.timeout
            )
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Failed to send batch to Splunk: {str(e)}")
            return False
    
    def test_connection(self) -> bool:
        try:
            # Send a test event to verify the connection
            test_event = SIEMEvent(
                event_type="test_connection",
                severity="info",
                details={"message": "Test connection from EDR system"}
            )
            return self.send_event(test_event)
        except Exception as e:
            logger.error(f"Splunk connection test failed: {str(e)}")
            return False

class ElasticIntegration(SIEMIntegration):
    """Integration with Elasticsearch/Elastic SIEM"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.url = config["url"]
        self.api_key = config.get("api_key")
        self.username = config.get("username")
        self.password = config.get("password")
        self.index = config.get("index", "edr-events")
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        
        # Set up authentication
        if self.api_key:
            self.session.headers.update({"Authorization": f"ApiKey {self.api_key}"})
        elif self.username and self.password:
            from requests.auth import HTTPBasicAuth
            self.session.auth = HTTPBasicAuth(self.username, self.password)
    
    def send_event(self, event: Union[SIEMEvent, Dict[str, Any]]) -> bool:
        if not self.enabled:
            return False
        
        try:
            if isinstance(event, SIEMEvent):
                event_data = event.to_dict()
            else:
                event_data = event
            
            # Elasticsearch requires the index in the URL
            url = f"{self.url.rstrip('/')}/{self.index}/_doc"
            
            response = self.session.post(
                url,
                json=event_data,
                timeout=self.timeout
            )
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Failed to send event to Elasticsearch: {str(e)}")
            return False
    
    def send_events_batch(self, events: List[Union[SIEMEvent, Dict[str, Any]]]) -> bool:
        if not self.enabled or not events:
            return False
        
        try:
            # Elasticsearch bulk API requires a specific format
            bulk_data = []
            for event in events:
                if isinstance(event, SIEMEvent):
                    event_data = event.to_dict()
                else:
                    event_data = event
                
                # Add index info
                bulk_data.append({"index": {"_index": self.index}})
                bulk_data.append(event_data)
            
            # Join with newlines and add a final newline
            payload = "\n".join(json.dumps(item) for item in bulk_data) + "\n"
            
            # Send to bulk API
            url = f"{self.url.rstrip('/')}/_bulk"
            response = self.session.post(
                url,
                data=payload,
                headers={"Content-Type": "application/x-ndjson"},
                timeout=self.timeout
            )
            response.raise_for_status()
            
            # Check for individual item errors in the response
            result = response.json()
            if result.get("errors", False):
                for item in result.get("items", []):
                    if "error" in item.get("index", {}):
                        logger.error(f"Error indexing document: {item['index']['error']}")
                return False
                
            return True
        except Exception as e:
            logger.error(f"Failed to send batch to Elasticsearch: {str(e)}")
            return False
    
    def test_connection(self) -> bool:
        try:
            # Check if the cluster is available
            response = self.session.get(
                f"{self.url.rstrip('/')}/_cluster/health",
                timeout=self.timeout
            )
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Elasticsearch connection test failed: {str(e)}")
            return False

class SIEMIntegrationFactory:
    """Factory for creating SIEM integration instances"""
    
    @staticmethod
    def create_siem_integration(siem_type: Union[str, SIEMType], config: Dict[str, Any]) -> Optional[SIEMIntegration]:
        """
        Create a SIEM integration instance based on the specified type.
        
        Args:
            siem_type: Type of SIEM (e.g., 'splunk', 'elastic')
            config: Configuration dictionary for the SIEM integration
            
        Returns:
            SIEMIntegration: An instance of the appropriate SIEM integration class, or None if not found
        """
        if isinstance(siem_type, str):
            siem_type = SIEMType(siem_type.lower())
        
        if not config.get("enabled", False):
            logger.warning(f"SIEM integration {siem_type.value} is disabled in configuration")
            return None
        
        try:
            if siem_type == SIEMType.SPLUNK:
                return SplunkIntegration(config)
            elif siem_type == SIEMType.ELK:
                return ElasticIntegration(config)
            # Add more SIEM integrations here
            else:
                logger.error(f"Unsupported SIEM type: {siem_type}")
                return None
        except Exception as e:
            logger.error(f"Failed to initialize {siem_type.value} integration: {str(e)}")
            return None

# Example usage
if __name__ == "__main__":
    # Example configuration
    config = {
        "enabled": True,
        "type": "splunk",
        "url": "https://splunk.example.com:8088/services/collector/event",
        "token": "your-hec-token-here",
        "index": "edr_events",
        "verify_ssl": True
    }
    
    # Create SIEM integration
    siem = SIEMIntegrationFactory.create_siem_integration(config["type"], config)
    
    if siem and siem.test_connection():
        print("Successfully connected to SIEM")
        
        # Send a test event
        event = SIEMEvent(
            event_type="test_event",
            severity="info",
            details={"message": "Test event from EDR system"}
        )
        
        if siem.send_event(event):
            print("Successfully sent test event to SIEM")
        else:
            print("Failed to send test event to SIEM")
    else:
        print("Failed to connect to SIEM")
