"""
Unit tests for database operations.
"""
import pytest
import sqlite3
from typing import Dict, Any
from datetime import datetime

def test_database_connection(temp_db: sqlite3.Connection):
    """Test database connection is established and basic operations work."""
    # Test basic query
    cursor = temp_db.cursor()
    cursor.execute("SELECT 1")
    result = cursor.fetchone()
    assert result[0] == 1

def test_create_event(temp_db: sqlite3.Connection, sample_event_data: Dict[str, Any]):
    """Test creating a new event in the database."""
    cursor = temp_db.cursor()
    
    # Insert test event
    cursor.execute("""
        INSERT INTO events (
            source, event_type, severity, description, raw_data, status
        ) VALUES (?, ?, ?, ?, ?, ?)
    """, (
        sample_event_data["source"],
        sample_event_data["event_type"],
        sample_event_data["severity"],
        sample_event_data["description"],
        sample_event_data["raw_data"],
        sample_event_data["status"]
    ))
    
    # Verify the event was inserted
    cursor.execute("SELECT * FROM events WHERE source = ?", (sample_event_data["source"],))
    event = cursor.fetchone()
    
    assert event is not None
    assert event["source"] == sample_event_data["source"]
    assert event["event_type"] == sample_event_data["event_type"]
    assert event["severity"] == sample_event_data["severity"]
    assert event["description"] == sample_event_data["description"]
    assert event["raw_data"] == sample_event_data["raw_data"]
    assert event["status"] == sample_event_data["status"]

def test_event_alert_relationship(temp_db: sqlite3.Connection, sample_event_data: Dict[str, Any]):
    """Test the relationship between events and alerts."""
    cursor = temp_db.cursor()
    
    # Insert test event
    cursor.execute("""
        INSERT INTO events (
            source, event_type, severity, description
        ) VALUES (?, ?, ?, ?)
    """, (
        sample_event_data["source"],
        sample_event_data["event_type"],
        sample_event_data["severity"],
        sample_event_data["description"]
    ))
    event_id = cursor.lastrowid
    
    # Create alert for the event
    cursor.execute("""
        INSERT INTO alerts (
            event_id, title, description, status, severity
        ) VALUES (?, ?, ?, ?, ?)
    """, (
        event_id,
        "Test Alert",
        "This is a test alert",
        "open",
        2
    ))
    
    # Verify the relationship
    cursor.execute("""
        SELECT e.id, a.id as alert_id, a.title, a.status
        FROM events e
        JOIN alerts a ON e.id = a.event_id
        WHERE e.id = ?
    """, (event_id,))
    
    result = cursor.fetchone()
    assert result is not None
    assert result["id"] == event_id
    assert result["title"] == "Test Alert"
    assert result["status"] == "open"

@pytest.mark.parametrize("event_count", [0, 1, 5])
def test_event_count(temp_db: sqlite3.Connection, event_count: int, sample_event_data: Dict[str, Any]):
    """Test counting events in the database."""
    cursor = temp_db.cursor()
    
    # Insert test events
    for i in range(event_count):
        cursor.execute("""
            INSERT INTO events (source, event_type, severity, description)
            VALUES (?, ?, ?, ?)
        """, (
            f"{sample_event_data['source']}_{i}",
            sample_event_data["event_type"],
            sample_event_data["severity"],
            f"{sample_event_data['description']} {i}"
        ))
    
    # Verify count
    cursor.execute("SELECT COUNT(*) as count FROM events")
    count = cursor.fetchone()["count"]
    assert count == event_count
