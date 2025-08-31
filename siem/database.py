"""
SIEM Database Module

Handles all database operations for the SIEM system using SQLite.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
import logging

logger = logging.getLogger(__name__)

class SIEMDatabase:
    """Manages all database operations for the SIEM system."""
    
    def __init__(self, db_path: str = "siem.db"):
        """Initialize the database connection and create tables if they don't exist."""
        self.db_path = Path(db_path)
        self.conn = None
        self._initialize_database()
    
    def _initialize_database(self) -> None:
        """Create the database file and tables if they don't exist."""
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row  # Enable dictionary-style access
            self._create_tables()
            logger.info(f"Database initialized at {self.db_path}")
        except sqlite3.Error as e:
            logger.error(f"Error initializing database: {e}")
            raise
    
    def _create_tables(self) -> None:
        """Create the necessary tables in the database."""
        tables = [
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                timestamp DATETIME NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                raw_data TEXT NOT NULL,
                tags TEXT DEFAULT '[]',
                processed BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE NOT NULL,
                timestamp DATETIME NOT NULL,
                source TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                event_ids TEXT NOT NULL,
                assigned_to TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                query TEXT NOT NULL,
                severity TEXT NOT NULL,
                tags TEXT DEFAULT '[]',
                enabled BOOLEAN DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS system_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                value TEXT NOT NULL,
                description TEXT,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        ]
        
        cursor = self.conn.cursor()
        try:
            for table_sql in tables:
                cursor.execute(table_sql)
            self.conn.commit()
        except sqlite3.Error as e:
            self.conn.rollback()
            logger.error(f"Error creating tables: {e}")
            raise
        finally:
            cursor.close()
    
    # Event methods
    def add_event(self, event: Dict[str, Any]) -> bool:
        """Add a new event to the database."""
        sql = """
        INSERT OR IGNORE INTO events 
        (event_id, timestamp, source, event_type, severity, description, raw_data, tags)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(sql, (
                event.get('event_id'),
                event.get('timestamp'),
                event.get('source'),
                event.get('event_type'),
                event.get('severity'),
                event.get('description'),
                json.dumps(event.get('raw_data', {})),
                json.dumps(event.get('tags', []))
            ))
            self.conn.commit()
            return cursor.lastrowid is not None
        except sqlite3.Error as e:
            logger.error(f"Error adding event: {e}")
            self.conn.rollback()
            return False
        finally:
            cursor.close()
    
    def get_events(self, limit: int = 100, **filters) -> List[Dict[str, Any]]:
        """Retrieve events with optional filtering."""
        query = "SELECT * FROM events"
        params = []
        
        if filters:
            conditions = []
            for key, value in filters.items():
                if key == 'start_time':
                    conditions.append("timestamp >= ?")
                    params.append(value)
                elif key == 'end_time':
                    conditions.append("timestamp <= ?")
                    params.append(value)
                elif key == 'severity':
                    if isinstance(value, (list, tuple)):
                        placeholders = ','.join(['?'] * len(value))
                        conditions.append(f"severity IN ({placeholders})")
                        params.extend(value)
                    else:
                        conditions.append("severity = ?")
                        params.append(value)
                else:
                    conditions.append(f"{key} = ?")
                    params.append(value)
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
        
        query += f" ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        try:
            cursor = self.conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error as e:
            logger.error(f"Error retrieving events: {e}")
            return []
        finally:
            cursor.close()
    
    # Alert methods
    def add_alert(self, alert: Dict[str, Any]) -> bool:
        """Add a new alert to the database."""
        sql = """
        INSERT OR IGNORE INTO alerts 
        (alert_id, timestamp, source, title, description, severity, status, event_ids)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(sql, (
                alert.get('alert_id'),
                alert.get('timestamp'),
                alert.get('source'),
                alert.get('title'),
                alert.get('description'),
                alert.get('severity'),
                alert.get('status', 'new'),
                json.dumps(alert.get('event_ids', []))
            ))
            self.conn.commit()
            return cursor.lastrowid is not None
        except sqlite3.Error as e:
            logger.error(f"Error adding alert: {e}")
            self.conn.rollback()
            return False
        finally:
            cursor.close()
    
    def update_alert_status(self, alert_id: str, status: str, notes: str = None) -> bool:
        """Update the status of an alert."""
        if notes:
            sql = """
            UPDATE alerts 
            SET status = ?, notes = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE alert_id = ?
            """
            params = (status, notes, alert_id)
        else:
            sql = """
            UPDATE alerts 
            SET status = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE alert_id = ?
            """
            params = (status, alert_id)
        
        try:
            cursor = self.conn.cursor()
            cursor.execute(sql, params)
            self.conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            logger.error(f"Error updating alert status: {e}")
            self.conn.rollback()
            return False
        finally:
            cursor.close()
    
    def get_alerts(self, limit: int = 100, **filters) -> List[Dict[str, Any]]:
        """Retrieve alerts with optional filtering."""
        query = "SELECT * FROM alerts"
        params = []
        
        if filters:
            conditions = []
            for key, value in filters.items():
                if key == 'start_time':
                    conditions.append("timestamp >= ?")
                    params.append(value)
                elif key == 'end_time':
                    conditions.append("timestamp <= ?")
                    params.append(value)
                elif key == 'status':
                    if isinstance(value, (list, tuple)):
                        placeholders = ','.join(['?'] * len(value))
                        conditions.append(f"status IN ({placeholders})")
                        params.extend(value)
                    else:
                        conditions.append("status = ?")
                        params.append(value)
                else:
                    conditions.append(f"{key} = ?")
                    params.append(value)
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
        
        query += f" ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        try:
            cursor = self.conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error as e:
            logger.error(f"Error retrieving alerts: {e}")
            return []
        finally:
            cursor.close()
    
    # Rule methods
    def add_rule(self, rule: Dict[str, Any]) -> bool:
        """Add a new detection rule to the database."""
        sql = """
        INSERT OR REPLACE INTO rules 
        (rule_id, name, description, query, severity, tags, enabled)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(sql, (
                rule.get('rule_id'),
                rule.get('name'),
                rule.get('description'),
                rule.get('query'),
                rule.get('severity'),
                json.dumps(rule.get('tags', [])),
                int(rule.get('enabled', True))
            ))
            self.conn.commit()
            return cursor.lastrowid is not None
        except sqlite3.Error as e:
            logger.error(f"Error adding rule: {e}")
            self.conn.rollback()
            return False
        finally:
            cursor.close()
    
    def get_rules(self, enabled_only: bool = True) -> List[Dict[str, Any]]:
        """Retrieve all rules, optionally only enabled ones."""
        query = "SELECT * FROM rules"
        params = []
        
        if enabled_only:
            query += " WHERE enabled = 1"
        
        query += " ORDER BY name"
        
        try:
            cursor = self.conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error as e:
            logger.error(f"Error retrieving rules: {e}")
            return []
        finally:
            cursor.close()
    
    # Settings methods
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a system setting value by key."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT value FROM system_settings WHERE key = ?", (key,))
            row = cursor.fetchone()
            return row['value'] if row else default
        except sqlite3.Error as e:
            logger.error(f"Error getting setting {key}: {e}")
            return default
        finally:
            cursor.close()
    
    def set_setting(self, key: str, value: Any, description: str = None) -> bool:
        """Set a system setting value."""
        sql = """
        INSERT OR REPLACE INTO system_settings 
        (key, value, description) 
        VALUES (?, ?, ?)
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(sql, (key, str(value), description))
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error setting {key}: {e}")
            self.conn.rollback()
            return False
        finally:
            cursor.close()
    
    # Database maintenance
    def backup_database(self, backup_path: str = None) -> bool:
        """Create a backup of the database."""
        if not backup_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"siem_backup_{timestamp}.db"
        
        try:
            # Ensure the backup directory exists
            backup_path = Path(backup_path)
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Create a backup using SQLite's backup API
            backup_conn = sqlite3.connect(backup_path)
            with backup_conn:
                self.conn.backup(backup_conn)
            backup_conn.close()
            
            logger.info(f"Database backup created at {backup_path}")
            return True
        except Exception as e:
            logger.error(f"Error creating database backup: {e}")
            return False
        finally:
            if 'backup_conn' in locals():
                backup_conn.close()
    
    def close(self) -> None:
        """Close the database connection."""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")
    
    def __del__(self) -> None:
        """Ensure the database connection is closed when the object is destroyed."""
        self.close()

# Singleton instance
db = SIEMDatabase()

def get_database() -> SIEMDatabase:
    """Get the database instance (singleton pattern)."""
    return db
