"""
Migration script to add raw_data column to events table if it doesn't exist.
"""
import sqlite3
import logging
import os
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('siem.migration')

def add_raw_data_column(db_path: str = 'siem.db') -> None:
    """
    Add raw_data column to events table if it doesn't exist.
    
    Args:
        db_path: Path to the SQLite database file
    """
    try:
        # Convert to absolute path
        db_path = os.path.abspath(db_path)
        
        # Check if database exists
        if not os.path.exists(db_path):
            logger.warning(f"Database file not found at {db_path}")
            return
            
        logger.info(f"Checking database schema in {db_path}")
        
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if raw_data column exists
        cursor.execute("PRAGMA table_info(events)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'raw_data' not in columns:
            logger.info("Adding raw_data column to events table")
            cursor.execute("""
                ALTER TABLE events 
                ADD COLUMN raw_data TEXT
            """)
            conn.commit()
            logger.info("Successfully added raw_data column")
        else:
            logger.info("raw_data column already exists")
            
        # Clean up
        cursor.close()
        conn.close()
        
    except Exception as e:
        logger.error(f"Error during migration: {e}", exc_info=True)
        if 'conn' in locals():
            conn.rollback()
        raise

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='SIEM Database Migration Tool')
    parser.add_argument('--db', default='siem.db', help='Path to SQLite database file')
    args = parser.parse_args()
    
    add_raw_data_column(args.db)
