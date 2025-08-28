"""
Event Store for NIPS Forensics

Provides a simple in-memory and persistent event storage for NIPS events.
"""
import json
import os
import time
import sqlite3
from datetime import datetime
from typing import List, Dict, Any, Optional, Iterator
import logging

logger = logging.getLogger(__name__)

class EventStore:
    """Stores and retrieves security events for forensic analysis."""
    
    def __init__(self, db_path: str = 'nips_events.db'):
        """Initialize the event store with a SQLite database.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize the database schema if it doesn't exist."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    event_type TEXT NOT NULL,
                    source_ip TEXT,
                    dest_ip TEXT,
                    source_port INTEGER,
                    dest_port INTEGER,
                    protocol TEXT,
                    severity TEXT,
                    description TEXT,
                    raw_data TEXT,
                    processed BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes for faster queries
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_dest_ip ON events(dest_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)')
            
            conn.commit()
    
    def store_event(self, event: Dict[str, Any]) -> int:
        """Store a security event in the database.
        
        Args:
            event: Dictionary containing event data
            
        Returns:
            int: The ID of the inserted event
        """
        required_fields = ['timestamp', 'event_type']
        for field in required_fields:
            if field not in event:
                raise ValueError(f"Missing required field: {field}")
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Prepare the event data
            event_data = {
                'timestamp': event.get('timestamp', time.time()),
                'event_type': event['event_type'],
                'source_ip': event.get('source_ip'),
                'dest_ip': event.get('dest_ip'),
                'source_port': event.get('source_port'),
                'dest_port': event.get('dest_port'),
                'protocol': event.get('protocol'),
                'severity': event.get('severity', 'medium'),
                'description': event.get('description', ''),
                'raw_data': json.dumps(event.get('raw_data', {})) if isinstance(event.get('raw_data'), dict) else str(event.get('raw_data', '')),
                'processed': 0
            }
            
            # Insert the event
            cursor.execute('''
                INSERT INTO events (
                    timestamp, event_type, source_ip, dest_ip, source_port, 
                    dest_port, protocol, severity, description, raw_data, processed
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event_data['timestamp'],
                event_data['event_type'],
                event_data['source_ip'],
                event_data['dest_ip'],
                event_data['source_port'],
                event_data['dest_port'],
                event_data['protocol'],
                event_data['severity'],
                event_data['description'],
                event_data['raw_data'],
                event_data['processed']
            ))
            
            event_id = cursor.lastrowid
            conn.commit()
            
            logger.debug(f"Stored event {event_id} of type {event['event_type']}")
            return event_id
    
    def get_events(self, limit: int = 100, offset: int = 0, **filters) -> List[Dict[str, Any]]:
        """Retrieve events matching the given filters.
        
        Args:
            limit: Maximum number of events to return
            offset: Number of events to skip
            **filters: Filter criteria (e.g., event_type='intrusion', severity='high')
            
        Returns:
            List of event dictionaries
        """
        query = 'SELECT * FROM events'
        params = []
        
        if filters:
            conditions = []
            for key, value in filters.items():
                if value is not None:
                    conditions.append(f"{key} = ?")
                    params.append(value)
            
            if conditions:
                query += ' WHERE ' + ' AND '.join(conditions)
        
        query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
        params.extend([limit, offset])
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            events = []
            for row in cursor.fetchall():
                event = dict(row)
                # Convert timestamp to datetime
                event['timestamp'] = datetime.fromtimestamp(event['timestamp']).isoformat()
                # Parse raw_data if it exists
                if event['raw_data']:
                    try:
                        event['raw_data'] = json.loads(event['raw_data'])
                    except (json.JSONDecodeError, TypeError):
                        pass
                events.append(event)
            
            return events
    
    def get_event_count(self, **filters) -> int:
        """Get the count of events matching the given filters.
        
        Args:
            **filters: Filter criteria
            
        Returns:
            int: Number of matching events
        """
        query = 'SELECT COUNT(*) FROM events'
        params = []
        
        if filters:
            conditions = []
            for key, value in filters.items():
                if value is not None:
                    conditions.append(f"{key} = ?")
                    params.append(value)
            
            if conditions:
                query += ' WHERE ' + ' AND '.join(conditions)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchone()[0]
    
    def mark_processed(self, event_ids: List[int]):
        """Mark events as processed.
        
        Args:
            event_ids: List of event IDs to mark as processed
        """
        if not event_ids:
            return
            
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            placeholders = ','.join('?' * len(event_ids))
            cursor.execute(
                f'UPDATE events SET processed = 1 WHERE id IN ({placeholders})',
                event_ids
            )
            conn.commit()
    
    def cleanup_old_events(self, days_to_keep: int = 30):
        """Remove events older than the specified number of days.
        
        Args:
            days_to_keep: Number of days of events to keep
        """
        cutoff = time.time() - (days_to_keep * 24 * 60 * 60)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM events WHERE timestamp < ?', (cutoff,))
            deleted = cursor.rowcount
            conn.commit()
            
            if deleted > 0:
                logger.info(f"Cleaned up {deleted} events older than {days_to_keep} days")
    
    def export_events(self, output_file: str, format: str = 'json', **filters):
        """Export events to a file.
        
        Args:
            output_file: Path to the output file
            format: Export format ('json' or 'csv')
            **filters: Filter criteria for events to export
        """
        events = self.get_events(limit=0, **filters)
        
        if format.lower() == 'json':
            with open(output_file, 'w') as f:
                json.dump(events, f, indent=2)
        elif format.lower() == 'csv':
            import csv
            
            if not events:
                return
                
            # Get all unique field names from all events
            fieldnames = set()
            for event in events:
                fieldnames.update(event.keys())
            
            with open(output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=sorted(fieldnames))
                writer.writeheader()
                writer.writerows(events)
        else:
            raise ValueError(f"Unsupported export format: {format}")
