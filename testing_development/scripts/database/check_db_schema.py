#!/usr/bin/env python3
"""
Database Schema Checker for SIEM System

This script verifies the database schema and connection.
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
        logging.FileHandler('db_schema_check.log')
    ]
)
logger = logging.getLogger('siem.db_check')

def check_database(db_path: str) -> bool:
    """Check if the database exists and has the correct schema."""
    try:
        logger.info(f"Checking database at: {db_path}")
        
        if not os.path.exists(db_path):
            logger.error(f"Database file does not exist: {db_path}")
            return False
            
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if tables exist
        required_tables = ['events', 'alerts', 'users', 'settings']
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing_tables = [row[0].lower() for row in cursor.fetchall()]
        
        logger.info(f"Found tables: {', '.join(existing_tables) if existing_tables else 'No tables found'}")
        
        # Check for missing tables
        missing_tables = [t for t in required_tables if t not in existing_tables]
        if missing_tables:
            logger.error(f"Missing required tables: {', '.join(missing_tables)}")
            return False
            
        # Check each table's columns
        table_columns = {
            'events': ['id', 'timestamp', 'source', 'event_type', 'severity', 'description', 'status'],
            'alerts': ['id', 'event_id', 'title', 'status', 'severity', 'created_at'],
            'users': ['id', 'username', 'password_hash', 'role', 'is_active'],
            'settings': ['id', 'key', 'value', 'description']
        }
        
        for table, required_columns in table_columns.items():
            if table not in existing_tables:
                continue
                
            cursor.execute(f"PRAGMA table_info({table})")
            columns = [row[1].lower() for row in cursor.fetchall()]
            logger.info(f"Table '{table}' columns: {', '.join(columns) if columns else 'No columns found'}")
            
            missing_columns = [col for col in required_columns if col.lower() not in columns]
            if missing_columns:
                logger.error(f"Table '{table}' is missing columns: {', '.join(missing_columns)}")
                return False
        
        # Check WAL mode
        cursor.execute("PRAGMA journal_mode")
        journal_mode = cursor.fetchone()[0]
        logger.info(f"Journal mode: {journal_mode}")
        
        conn.close()
        
        logger.info("Database schema check completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error checking database: {e}", exc_info=True)
        return False

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Check SIEM database schema')
    parser.add_argument('--db-path', type=str, default='data/siem.db',
                      help='Path to the database file')
    
    args = parser.parse_args()
    
    success = check_database(args.db_path)
    
    if success:
        print(f"Database check passed: {args.db_path}")
        sys.exit(0)
    else:
        print(f"Database check failed: {args.db_path}")
        sys.exit(1)
