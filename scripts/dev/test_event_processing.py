"""
Integration tests for event processing in the SIEM system.
"""
import pytest
import json
from datetime import datetime, timedelta
from typing import Dict, Any

# Import the actual modules to test
from siem.core.database import Database
from siem.services.event_processor import EventProcessor

class TestEventProcessing:
    """Test suite for event processing functionality."""
    
    @pytest.fixture(autouse=True)
    def setup(self, temp_db):
        """Set up test environment."""
        self.db = temp_db
        self.cursor = self.db.cursor()
        self.event_processor = EventProcessor(database=self.db)
        
    def test_process_single_event(self, sample_event_data: Dict[str, Any]):
        """Test processing a single event through the system."""
        # Process the event
        event_id = self.event_processor.process_event(sample_event_data)
        
        # Verify the event was stored correctly
        self.cursor.execute("SELECT * FROM events WHERE id = ?", (event_id,))
        event = self.cursor.fetchone()
        
        assert event is not None
        assert event["source"] == sample_event_data["source"]
        assert event["event_type"] == sample_event_data["event_type"]
        assert event["severity"] == sample_event_data["severity"]
        
        # Verify no alert was created for normal events
        self.cursor.execute("SELECT COUNT(*) as count FROM alerts WHERE event_id = ?", (event_id,))
        assert self.cursor.fetchone()["count"] == 0
    
    def test_process_high_severity_event(self):
        """Test that high severity events generate alerts."""
        # Create a high severity event
        event_data = {
            "source": "security_scanner",
            "event_type": "intrusion_attempt",
            "severity": 4,  # High severity
            "description": "Possible intrusion attempt detected",
            "raw_data": json.dumps({"ip": "192.168.1.100", "port": 22, "protocol": "ssh"}),
            "status": "new"
        }
        
        # Process the event
        event_id = self.event_processor.process_event(event_data)
        
        # Verify an alert was created
        self.cursor.execute("""
            SELECT a.* FROM alerts a
            WHERE a.event_id = ?
        """, (event_id,))
        
        alert = self.cursor.fetchone()
        assert alert is not None
        assert alert["title"] == "High Severity Event Detected"
        assert alert["severity"] == 4
        assert alert["status"] == "open"
    
    def test_event_correlation(self):
        """Test that related events are properly correlated."""
        # Create multiple related events
        base_data = {
            "source": "firewall",
            "event_type": "blocked_connection",
            "severity": 2,
            "description": "Connection blocked by firewall",
            "status": "new"
        }
        
        # Generate 5 similar events from the same source IP
        for i in range(5):
            event_data = base_data.copy()
            event_data["raw_data"] = json.dumps({
                "src_ip": "192.168.1.100",
                "dst_port": 80,
                "action": "block",
                "timestamp": (datetime.utcnow() - timedelta(minutes=i)).isoformat()
            })
            self.event_processor.process_event(event_data)
        
        # Verify correlation (this would depend on your correlation logic)
        self.cursor.execute("""
            SELECT COUNT(DISTINCT e.id) as event_count
            FROM events e
            WHERE e.source = 'firewall'
            AND e.event_type = 'blocked_connection'
            AND json_extract(e.raw_data, '$.src_ip') = '192.168.1.100'
        """)
        
        result = self.cursor.fetchone()
        assert result["event_count"] == 5
        
        # Verify that a correlation alert was created
        self.cursor.execute("""
            SELECT COUNT(*) as alert_count
            FROM alerts
            WHERE title = 'Multiple Blocked Connections Detected'
        """)
        
        alert_count = self.cursor.fetchone()["alert_count"]
        assert alert_count > 0
