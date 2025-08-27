#!/usr/bin/env python3
"""
Database Initialization Script

This script initializes the SIEM database with the required tables.
"""
import os
import sqlite3
from pathlib import Path
from datetime import datetime

def init_database():
    """Initialize the SQLite database with required tables."""
    # Get the database path from environment variable or use default
    db_path = os.getenv('DB_PATH', 'data/siem.db')
    
    # Create the data directory if it doesn't exist
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    print(f"Initializing database at: {os.path.abspath(db_path)}")
    
    # Connect to SQLite database (creates it if it doesn't exist)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Enable WAL mode for better concurrency
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA synchronous=NORMAL;")
    cursor.execute("PRAGMA foreign_keys=ON;")
    
    # Create events table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL,
        source TEXT NOT NULL,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL,
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
    
    # Create indexes for better query performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)')
    
    # Create alerts table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        severity TEXT NOT NULL,
        status TEXT DEFAULT 'OPEN',
        timestamp DATETIME NOT NULL,
        source TEXT,
        event_data TEXT,
        assigned_to TEXT,
        resolution TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT,
        is_active BOOLEAN DEFAULT 1,
        is_admin BOOLEAN DEFAULT 0,
        last_login DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Create threat_intel table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS threat_intel (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator_type TEXT NOT NULL,
        indicator_value TEXT NOT NULL,
        threat_type TEXT,
        description TEXT,
        first_seen DATETIME,
        last_seen DATETIME,
        confidence FLOAT,
        source TEXT,
        is_active BOOLEAN DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(indicator_type, indicator_value)
    )
    ''')
    
    # Create indexes for threat_intel
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_intel_indicator ON threat_intel(indicator_type, indicator_value)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_intel_type ON threat_intel(threat_type)')
    
    # Create audit_log table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL,
        user_id INTEGER,
        action TEXT NOT NULL,
        entity_type TEXT,
        entity_id INTEGER,
        details TEXT,
        ip_address TEXT,
        user_agent TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')
    
    # Create indexes for audit_log
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action)')
    
    # Create a default admin user if one doesn't exist
    cursor.execute("SELECT id FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        from passlib.hash import bcrypt
        hashed_password = bcrypt.hash('admin123')  # Default password, should be changed after first login
        cursor.execute('''
        INSERT INTO users (username, email, password_hash, full_name, is_admin)
        VALUES (?, ?, ?, ?, ?)
        ''', ('admin', 'admin@example.com', hashed_password, 'System Administrator', 1))
        print("Created default admin user (username: admin, password: admin123)")
    
    # Commit changes and close connection
    conn.commit()
    conn.close()
    
    print("Database initialization completed successfully!")

if __name__ == "__main__":
    init_database()
