#!/usr/bin/env python3
"""
Database Check and Fix Script

This script checks the SIEM database structure and fixes any issues.
"""
import os
import sqlite3
import logging
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('siem.db_check')

def check_database(db_path: str):
    """Check and fix the database structure."""
    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        logger.info(f"Found tables: {', '.join(tables) if tables else 'No tables found'}")
        
        # Check events table structure
        if 'events' in tables:
            logger.info("Checking events table structure...")
            cursor.execute("PRAGMA table_info(events)")
            columns = [col[1] for col in cursor.fetchall()]
            logger.info(f"Events table columns: {', '.join(columns)}")
            
            # Check for required columns
            required_columns = [
                'id', 'timestamp', 'source', 'event_type', 'severity',
                'description', 'raw_data', 'status', 'created_at', 'updated_at'
            ]
            
            for col in required_columns:
                if col not in columns:
                    logger.warning(f"Missing required column: {col}")
                    try:
                        if col == 'status':
                            cursor.execute(f"ALTER TABLE events ADD COLUMN {col} TEXT DEFAULT 'new'")
                        elif col in ['created_at', 'updated_at']:
                            cursor.execute(f"ALTER TABLE events ADD COLUMN {col} DATETIME DEFAULT CURRENT_TIMESTAMP")
                        else:
                            cursor.execute(f"ALTER TABLE events ADD COLUMN {col} TEXT")
                        logger.info(f"Added missing column: {col}")
                    except sqlite3.OperationalError as e:
                        logger.error(f"Error adding column {col}: {e}")
        
        # Commit changes
        conn.commit()
        conn.close()
        logger.info("Database check completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error checking database: {e}")
        return False

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Check and fix SIEM database structure')
    parser.add_argument('--db-path', type=str, default='data/siem.db',
                      help='Path to the database file')
    
    args = parser.parse_args()
    
    # Ensure the database directory exists
    db_dir = os.path.dirname(args.db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    
    # Check if database exists, create if it doesn't
    if not os.path.exists(args.db_path):
        logger.info(f"Database not found at {args.db_path}, creating new database")
        open(args.db_path, 'a').close()
    
    success = check_database(args.db_path)
    if success:
        print(f"Database check completed successfully: {args.db_path}")
    else:
        print(f"Database check failed for: {args.db_path}")
        sys.exit(1)
