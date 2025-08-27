import sqlite3
import os
import logging
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('fix_events_table.log')
    ]
)
logger = logging.getLogger('fix_events')

def add_status_column(db_path):
    """Add status column to events table if it doesn't exist."""
    try:
        logger.info(f"Connecting to database: {db_path}")
        
        # Check if database file exists
        if not os.path.exists(db_path):
            logger.error(f"Database file does not exist: {db_path}")
            return False
            
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if status column exists
        cursor.execute("PRAGMA table_info(events)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'status' in columns:
            logger.info("Status column already exists in events table")
            return True
            
        # Add status column with default value 'new'
        logger.info("Adding status column to events table...")
        cursor.execute("""
        ALTER TABLE events 
        ADD COLUMN status TEXT DEFAULT 'new'
        """)
        
        # Create index on status column
        logger.info("Creating index on status column...")
        cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_status 
        ON events(status)
        """)
        
        conn.commit()
        logger.info("Successfully added status column and index")
        
        # Verify the change
        cursor.execute("PRAGMA table_info(events)")
        columns = [col[1] for col in cursor.fetchall()]
        logger.info(f"Updated events table columns: {', '.join(columns)}")
        
        conn.close()
        return True
        
    except Exception as e:
        logger.error(f"Error adding status column: {e}", exc_info=True)
        if 'conn' in locals():
            conn.rollback()
            try:
                conn.close()
            except:
                pass
        return False

if __name__ == "__main__":
    db_path = os.path.abspath("siem.db")
    print(f"Fixing events table in: {db_path}")
    
    if add_status_column(db_path):
        print("✅ Successfully updated events table")
    else:
        print("❌ Failed to update events table")
