#!/usr/bin/env python3
"""
Database Verification and Fix Script

This script verifies the database schema and fixes any issues found.
"""
import os
import sys
import sqlite3
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('db_verify.log')
    ]
)
logger = logging.getLogger('siem.db_verify')

class DatabaseVerifier:
    """Class to verify and fix database schema issues."""
    
    def __init__(self, db_path: str):
        """Initialize with database path."""
        self.db_path = os.path.abspath(db_path)
        self.conn = None
        self.cursor = None
        
        # Required tables and their columns
        self.required_tables = {
            'events': [
                'id', 'timestamp', 'source', 'event_type', 'severity',
                'description', 'raw_data', 'processed', 'created_at', 'updated_at'
            ],
            'alerts': [
                'id', 'title', 'description', 'severity', 'status',
                'source', 'event_id', 'created_at', 'updated_at'
            ],
            'rules': [
                'id', 'name', 'description', 'severity', 'query',
                'is_active', 'created_at', 'updated_at'
            ],
            'users': [
                'id', 'username', 'password_hash', 'email', 'role',
                'is_active', 'last_login', 'created_at', 'updated_at'
            ]
        }
        
    def connect(self) -> bool:
        """Connect to the database."""
        try:
            # Ensure directory exists
            db_dir = os.path.dirname(self.db_path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
                logger.info(f"Created database directory: {db_dir}")
            
            # Connect to database
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
            self.cursor = self.conn.cursor()
            
            # Enable foreign keys and WAL mode
            self.cursor.execute("PRAGMA foreign_keys = ON;")
            self.cursor.execute("PRAGMA journal_mode = WAL;")
            self.conn.commit()
            
            logger.info(f"Connected to database: {self.db_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            return False
    
    def close(self) -> None:
        """Close the database connection."""
        if self.conn:
            try:
                self.conn.close()
                logger.info("Database connection closed")
            except Exception as e:
                logger.error(f"Error closing database: {e}")
            finally:
                self.conn = None
                self.cursor = None
    
    def verify_schema(self) -> bool:
        """Verify the database schema."""
        if not self.conn:
            logger.error("Not connected to database")
            return False
            
        try:
            success = True
            
            # Check if tables exist
            self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            existing_tables = [row[0].lower() for row in self.cursor.fetchall()]
            logger.info(f"Found tables: {', '.join(existing_tables) or 'None'}")
            
            # Check required tables
            for table, columns in self.required_tables.items():
                if table not in existing_tables:
                    logger.error(f"Missing required table: {table}")
                    success = False
                    continue
                    
                # Check columns
                self.cursor.execute(f"PRAGMA table_info({table});")
                existing_columns = [row['name'].lower() for row in self.cursor.fetchall()]
                missing_columns = [col for col in columns if col.lower() not in existing_columns]
                
                if missing_columns:
                    logger.error(f"Table '{table}' is missing columns: {', '.join(missing_columns)}")
                    success = False
                
            return success
            
        except Exception as e:
            logger.error(f"Error verifying schema: {e}")
            return False
    
    def fix_schema(self) -> bool:
        """Fix database schema issues."""
        if not self.conn:
            logger.error("Not connected to database")
            return False
            
        try:
            success = True
            self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            existing_tables = [row[0].lower() for row in self.cursor.fetchall()]
            
            # Create missing tables
            if 'events' not in existing_tables:
                logger.info("Creating 'events' table...")
                self.cursor.execute('''
                    CREATE TABLE events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        source TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        severity TEXT CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
                        description TEXT,
                        raw_data TEXT,
                        processed BOOLEAN DEFAULT 0,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                logger.info("Created 'events' table")
            
            # Add missing columns to existing tables
            for table, columns in self.required_tables.items():
                if table not in existing_tables:
                    continue
                    
                self.cursor.execute(f"PRAGMA table_info({table});")
                existing_columns = [row['name'].lower() for row in self.cursor.fetchall()]
                
                for column in columns:
                    if column.lower() not in existing_columns:
                        logger.info(f"Adding column '{column}' to table '{table}'...")
                        column_type = self._get_column_type(table, column)
                        if column_type:
                            self.cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_type}")
                            logger.info(f"Added column '{column}' to table '{table}'")
                        else:
                            logger.warning(f"Unknown column type for '{table}.{column}'") 
                            success = False
            
            # Create indexes
            self._create_indexes()
            
            self.conn.commit()
            return success
            
        except Exception as e:
            logger.error(f"Error fixing schema: {e}")
            self.conn.rollback()
            return False
    
    def _get_column_type(self, table: str, column: str) -> Optional[str]:
        """Get the SQL type for a column."""
        type_map = {
            'id': 'INTEGER PRIMARY KEY AUTOINCREMENT',
            'timestamp': 'DATETIME',
            'created_at': 'DATETIME DEFAULT CURRENT_TIMESTAMP',
            'updated_at': 'DATETIME DEFAULT CURRENT_TIMESTAMP',
            'severity': 'TEXT CHECK(severity IN (\'LOW\', \'MEDIUM\', \'HIGH\', \'CRITICAL\'))',
            'is_active': 'BOOLEAN DEFAULT 1',
            'processed': 'BOOLEAN DEFAULT 0'
        }
        
        # Default types based on column name patterns
        if column.endswith('_at') or column in ['timestamp', 'last_login']:
            return 'DATETIME'
        elif column.endswith('_id'):
            return 'INTEGER'
        elif column in ['email', 'username', 'name', 'description', 'source', 'event_type']:
            return 'TEXT'
        elif column in ['is_', 'has_', 'processed']:
            return 'BOOLEAN'
        elif column in ['severity', 'status', 'role']:
            return 'TEXT'
        
        return 'TEXT'  # Default fallback
    
    def _create_indexes(self) -> None:
        """Create necessary indexes."""
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)",
            "CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)",
            "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)",
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)"
        ]
        
        for index_sql in indexes:
            try:
                self.cursor.execute(index_sql)
            except Exception as e:
                logger.warning(f"Failed to create index: {e}")

def main():
    """Main function."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Verify and fix database schema')
    parser.add_argument('--db-path', type=str, default='data/siem.db',
                      help='Path to the database file')
    parser.add_argument('--fix', action='store_true',
                      help='Fix any schema issues found')
    
    args = parser.parse_args()
    
    # Initialize verifier
    verifier = DatabaseVerifier(args.db_path)
    
    try:
        # Connect to database
        if not verifier.connect():
            logger.error("Failed to connect to database")
            return 1
        
        # Check if database exists
        if not os.path.exists(args.db_path):
            logger.warning(f"Database file does not exist: {args.db_path}")
            if args.fix:
                logger.info("Creating new database...")
            else:
                logger.error("Use --fix to create a new database")
                return 1
        
        # Verify schema
        logger.info("Verifying database schema...")
        if verifier.verify_schema():
            logger.info("Database schema is valid")
            return 0
        
        # Fix schema if requested
        if args.fix:
            logger.info("Fixing database schema...")
            if verifier.fix_schema():
                logger.info("Database schema fixed successfully")
                
                # Verify after fixing
                if verifier.verify_schema():
                    logger.info("Database verification passed after fixes")
                    return 0
                else:
                    logger.error("Database verification failed after fixes")
                    return 1
            else:
                logger.error("Failed to fix database schema")
                return 1
        else:
            logger.error("Schema issues found. Use --fix to attempt repairs.")
            return 1
            
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return 1
    finally:
        verifier.close()

if __name__ == "__main__":
    sys.exit(main())
