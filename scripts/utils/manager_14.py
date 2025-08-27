"""EDR (Endpoint Detection and Response) Manager."""
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import psutil
import platform
import socket
import json

from ...database.database import Database

class EDRManager:
    """Manages EDR functionality including endpoint monitoring and threat detection."""
    
    def __init__(self, db: Database):
        """Initialize the EDR manager."""
        self.logger = logging.getLogger(__name__)
        self.db = db
        self.endpoints = {}
        self._initialize_database()
        
    def _initialize_database(self):
        """Initialize EDR-specific database tables."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS endpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT NOT NULL,
                    ip_address TEXT,
                    os TEXT,
                    last_seen DATETIME,
                    is_online BOOLEAN DEFAULT 0,
                    threat_level INTEGER DEFAULT 0,
                    metadata TEXT
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS endpoint_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    endpoint_id INTEGER,
                    event_type TEXT,
                    severity INTEGER,
                    description TEXT,
                    process_name TEXT,
                    process_id INTEGER,
                    parent_process TEXT,
                    command_line TEXT,
                    file_path TEXT,
                    hash_value TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    is_malicious BOOLEAN DEFAULT 0,
                    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id)
                )
            """)
            
            # Create indexes
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_endpoint_events_endpoint_id 
                ON endpoint_events(endpoint_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_endpoint_events_timestamp 
                ON endpoint_events(timestamp)
            """)
            conn.commit()
    
    def discover_endpoints(self) -> int:
        """Discover and register endpoints on the network."""
        try:
            # Get local endpoint info
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            os_info = f"{platform.system()} {platform.release()}"
            
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if endpoint exists
                cursor.execute(
                    "SELECT id FROM endpoints WHERE hostname = ?", 
                    (hostname,)
                )
                result = cursor.fetchone()
                
                if result:
                    # Update existing endpoint
                    cursor.execute(
                        """
                        UPDATE endpoints 
                        SET ip_address = ?, os = ?, last_seen = CURRENT_TIMESTAMP, is_online = 1
                        WHERE hostname = ?
                        """,
                        (ip_address, os_info, hostname)
                    )
                    endpoint_id = result[0]
                else:
                    # Insert new endpoint
                    cursor.execute(
                        """
                        INSERT INTO endpoints 
                        (hostname, ip_address, os, last_seen, is_online)
                        VALUES (?, ?, ?, CURRENT_TIMESTAMP, 1)
                        """,
                        (hostname, ip_address, os_info)
                    )
                    endpoint_id = cursor.lastrowid
                
                conn.commit()
                self.endpoints[hostname] = {
                    'id': endpoint_id,
                    'ip_address': ip_address,
                    'os': os_info,
                    'last_seen': datetime.now(),
                    'is_online': True
                }
                
                return endpoint_id
                
        except Exception as e:
            self.logger.error(f"Error discovering endpoints: {e}")
            return -1
    
    def get_endpoint_metrics(self) -> Dict:
        """Get EDR metrics for the dashboard."""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get endpoint counts
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total,
                        SUM(CASE WHEN is_online = 1 THEN 1 ELSE 0 END) as online,
                        SUM(CASE WHEN threat_level > 0 THEN 1 ELSE 0 END) as threatened,
                        COUNT(DISTINCT os) as os_types
                    FROM endpoints
                """)
                counts = cursor.fetchone()
                
                # Get recent threats
                cursor.execute("""
                    SELECT COUNT(*) 
                    FROM endpoint_events 
                    WHERE timestamp > datetime('now', '-24 hours') 
                    AND severity >= 3
                """)
                recent_threats = cursor.fetchone()[0]
                
                return {
                    'total_endpoints': counts[0] or 0,
                    'online_endpoints': counts[1] or 0,
                    'threatened_endpoints': counts[2] or 0,
                    'os_types': counts[3] or 0,
                    'recent_threats': recent_threats
                }
                
        except Exception as e:
            self.logger.error(f"Error getting EDR metrics: {e}")
            return {
                'total_endpoints': 0,
                'online_endpoints': 0,
                'threatened_endpoints': 0,
                'os_types': 0,
                'recent_threats': 0
            }
    
    def get_recent_threats(self, limit: int = 10) -> List[Dict]:
        """Get recent threats across all endpoints."""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT 
                        e.hostname, ee.event_type, ee.severity, 
                        ee.description, ee.timestamp
                    FROM endpoint_events ee
                    JOIN endpoints e ON ee.endpoint_id = e.id
                    WHERE ee.severity >= 3
                    ORDER BY ee.timestamp DESC
                    LIMIT ?
                """, (limit,))
                
                return [{
                    'hostname': row[0],
                    'event_type': row[1],
                    'severity': row[2],
                    'description': row[3],
                    'timestamp': row[4]
                } for row in cursor.fetchall()]
                
        except Exception as e:
            self.logger.error(f"Error getting recent threats: {e}")
            return []
    
    def log_endpoint_event(self, 
                         endpoint_id: int, 
                         event_type: str, 
                         severity: int, 
                         description: str,
                         process_name: str = None,
                         process_id: int = None,
                         parent_process: str = None,
                         command_line: str = None,
                         file_path: str = None,
                         hash_value: str = None) -> bool:
        """Log an endpoint event."""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO endpoint_events 
                    (endpoint_id, event_type, severity, description, 
                     process_name, process_id, parent_process, 
                     command_line, file_path, hash_value)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    endpoint_id, event_type, severity, description,
                    process_name, process_id, parent_process,
                    command_line, file_path, hash_value
                ))
                
                # Update endpoint threat level if this is a high severity event
                if severity >= 4:  # Critical
                    cursor.execute("""
                        UPDATE endpoints 
                        SET threat_level = GREATEST(threat_level, ?)
                        WHERE id = ?
                    """, (severity, endpoint_id))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Error logging endpoint event: {e}")
            return False
