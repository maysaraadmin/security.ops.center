#!/usr/bin/env python3
"""
Database Schema Fixer for SIEM System

This script verifies and fixes the database schema.
"""
import os
import sys
import sqlite3
import logging
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('fix_database_schema.log')
    ]
)
logger = logging.getLogger('siem.db_fix')

class DatabaseFixer:
    def __init__(self, db_path):
        self.db_path = os.path.abspath(db_path)
        self.conn = None
        self.cursor = None
        self.required_tables = {
            'events': [
                'id INTEGER PRIMARY KEY AUTOINCREMENT',
                'timestamp DATETIME NOT NULL',
                'source TEXT NOT NULL',
                'event_type TEXT NOT NULL',
                'severity INTEGER NOT NULL',
                'description TEXT',
                'raw_data TEXT',
                'status TEXT DEFAULT "new"',
                'source_ip TEXT',
                'destination_ip TEXT',
                'created_at DATETIME DEFAULT CURRENT_TIMESTAMP',
                'updated_at DATETIME DEFAULT CURRENT_TIMESTAMP'
            ],
            'alerts': [
                'id INTEGER PRIMARY KEY AUTOINCREMENT',
                'event_id INTEGER',
                'title TEXT NOT NULL',
                'description TEXT',
                'status TEXT DEFAULT "open"',
                'severity INTEGER DEFAULT 1',
                'created_at DATETIME DEFAULT CURRENT_TIMESTAMP',
                'updated_at DATETIME DEFAULT CURRENT_TIMESTAMP',
                'FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE SET NULL'
            ],
            'users': [
                'id INTEGER PRIMARY KEY AUTOINCREMENT',
                'username TEXT UNIQUE NOT NULL',
                'password_hash TEXT NOT NULL',
                'role TEXT DEFAULT "analyst"',
                'is_active BOOLEAN DEFAULT 1',
                'created_at DATETIME DEFAULT CURRENT_TIMESTAMP',
                'updated_at DATETIME DEFAULT CURRENT_TIMESTAMP'
            ],
            'settings': [
                'id INTEGER PRIMARY KEY AUTOINCREMENT',
                'key TEXT UNIQUE NOT NULL',
                'value TEXT',
                'description TEXT',
                'created_at DATETIME DEFAULT CURRENT_TIMESTAMP',
                'updated_at DATETIME DEFAULT CURRENT_TIMESTAMP'
            ]
        }
        self.indexes = [
            'CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)',
            'CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)',
            'CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)',
            'CREATE INDEX IF NOT EXISTS idx_events_status ON events(status)',
            'CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)'
        ]

    def connect(self):
        """Connect to the database."""
        try:
            # Ensure the directory exists
            db_dir = os.path.dirname(self.db_path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
                logger.info(f"Created database directory: {db_dir}")
            
            logger.info(f"Connecting to database: {self.db_path}")
            self.conn = sqlite3.connect(self.db_path)
            self.cursor = self.conn.cursor()
            
            # Enable WAL mode for better concurrency
            self.cursor.execute("PRAGMA journal_mode=WAL;")
            self.cursor.execute("PRAGMA synchronous=NORMAL;")
            self.cursor.execute("PRAGMA foreign_keys=ON;")
            
            return True
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}", exc_info=True)
            return False

    def close(self):
        """Close the database connection."""
        if self.conn:
            try:
                self.conn.commit()
                self.conn.close()
                logger.info("Database connection closed")
            except Exception as e:
                logger.error(f"Error closing database connection: {e}")
            finally:
                self.conn = None
                self.cursor = None

    def get_existing_tables(self):
        """Get a list of existing tables in the database."""
        self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        return [row[0].lower() for row in self.cursor.fetchall()]

    def create_table(self, table_name):
        """Create a table with the specified name and columns."""
        if table_name not in self.required_tables:
            logger.error(f"No schema defined for table: {table_name}")
            return False
            
        columns = ', '.join(self.required_tables[table_name])
        create_sql = f"CREATE TABLE {table_name} ({columns})"
        
        try:
            logger.info(f"Creating table: {table_name}")
            self.cursor.execute(create_sql)
            self.conn.commit()
            logger.info(f"Created table: {table_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to create table {table_name}: {e}")
            return False

    def check_table_columns(self, table_name):
        """Check if a table has all required columns and add any missing ones."""
        if table_name not in self.required_tables:
            return True
            
        self.cursor.execute(f"PRAGMA table_info({table_name})")
        existing_columns = [row[1].lower() for row in self.cursor.fetchall()]
        
        for column_def in self.required_tables[table_name]:
            # Extract column name from definition (first word before space)
            column_name = column_def.split()[0].lower()
            
            if column_name not in existing_columns:
                try:
                    # Handle primary key separately
                    if 'PRIMARY KEY' in column_def.upper():
                        continue
                        
                    alter_sql = f"ALTER TABLE {table_name} ADD COLUMN {column_def}"
                    logger.info(f"Adding column {table_name}.{column_name}")
                    self.cursor.execute(alter_sql)
                    self.conn.commit()
                    logger.info(f"Added column {table_name}.{column_name}")
                except Exception as e:
                    logger.error(f"Failed to add column {table_name}.{column_name}: {e}")
                    return False
        
        return True

    def create_indexes(self):
        """Create required indexes."""
        try:
            for index_sql in self.indexes:
                self.cursor.execute(index_sql)
            self.conn.commit()
            logger.info("Created indexes")
            return True
        except Exception as e:
            logger.error(f"Failed to create indexes: {e}")
            return False

    def fix_database(self):
        """Fix the database schema."""
        if not self.connect():
            return False
            
        try:
            existing_tables = self.get_existing_tables()
            logger.info(f"Existing tables: {', '.join(existing_tables) if existing_tables else 'None'}")
            
            # Create missing tables
            for table_name in self.required_tables:
                if table_name not in existing_tables:
                    if not self.create_table(table_name):
                        return False
                else:
                    logger.info(f"Table exists: {table_name}")
                    # Check and fix table columns
                    if not self.check_table_columns(table_name):
                        return False
            
            # Create indexes
            if not self.create_indexes():
                return False
                
            # Add default admin user if users table is empty
            self.cursor.execute("SELECT COUNT(*) FROM users")
            if self.cursor.fetchone()[0] == 0:
                logger.info("Adding default admin user")
                self.cursor.execute(
                    "INSERT INTO users (username, password_hash, role, is_active) "
                    "VALUES (?, ?, ?, ?)",
                    ('admin', 'admin', 'admin', 1)
                )
                self.conn.commit()
            
            return True
            
        except Exception as e:
            logger.error(f"Error fixing database: {e}", exc_info=True)
            return False
        finally:
            self.close()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Fix SIEM database schema')
    parser.add_argument('--db-path', type=str, default='data/siem.db',
                      help='Path to the database file')
    
    args = parser.parse_args()
    
    fixer = DatabaseFixer(args.db_path)
    success = fixer.fix_database()
    
    if success:
        print(f"Database schema fixed successfully: {os.path.abspath(args.db_path)}")
        sys.exit(0)
    else:
        print(f"Failed to fix database schema: {os.path.abspath(args.db_path)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
