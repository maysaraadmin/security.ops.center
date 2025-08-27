#!/usr/bin/env python3
"""
Database Setup Script for SIEM System

This script ensures the database is properly initialized with the correct schema
before the application starts.
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
        logging.FileHandler('database_setup.log')
    ]
)
logger = logging.getLogger('siem.db_setup')

def ensure_database(db_path: str) -> bool:
    """Ensure the database exists with the correct schema."""
    try:
        # Ensure the directory exists
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            logger.info(f"Created database directory: {db_dir}")
        
        # Connect to the database (creates it if it doesn't exist)
        logger.info(f"Initializing database at: {db_path}")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Enable WAL mode for better concurrency
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute("PRAGMA foreign_keys=ON;")
        
        # Create tables if they don't exist
        create_tables(cursor)
        
        # Commit changes and close
        conn.commit()
        conn.close()
        
        logger.info("Database setup completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}", exc_info=True)
        return False

def create_tables(cursor):
    """Create all necessary tables in the database."""
    # Events table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL,
        source TEXT NOT NULL,
        event_type TEXT NOT NULL,
        severity INTEGER NOT NULL,
        description TEXT,
        raw_data TEXT,
        category TEXT,
        status TEXT DEFAULT 'new',
        source_ip TEXT,
        destination_ip TEXT,
        user_agent TEXT,
        hostname TEXT,
        process_name TEXT,
        process_id INTEGER,
        parent_process_id INTEGER,
        command_line TEXT,
        file_path TEXT,
        file_hash TEXT,
        registry_key TEXT,
        registry_value TEXT,
        registry_data TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Alerts table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT DEFAULT 'open',
        severity INTEGER DEFAULT 1,
        source TEXT,
        category TEXT,
        assigned_to TEXT,
        resolution TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        resolved_at DATETIME,
        FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE SET NULL
    )
    ''')
    
    # Users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT,
        email TEXT UNIQUE,
        role TEXT DEFAULT 'analyst',
        is_active BOOLEAN DEFAULT 1,
        last_login DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Settings table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE NOT NULL,
        value TEXT,
        description TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Create indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_status ON events(status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)')
    
    logger.info("Created database tables and indexes")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Initialize the SIEM database')
    parser.add_argument('--db-path', type=str, default='data/siem.db',
                      help='Path to the database file')
    
    args = parser.parse_args()
    
    # Ensure the database is properly initialized
    success = ensure_database(args.db_path)
    
    if success:
        print(f"Database initialized successfully at: {args.db_path}")
        sys.exit(0)
    else:
        print(f"Failed to initialize database at: {args.db_path}")
        sys.exit(1)
