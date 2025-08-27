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
        logging.FileHandler('verify_schema.log')
    ]
)
logger = logging.getLogger('verify_schema')

def check_database_schema(db_path):
    """Check if the database schema is correct."""
    try:
        logger.info(f"Checking database at: {db_path}")
        
        if not os.path.exists(db_path):
            logger.error(f"Database file does not exist: {db_path}")
            return False
            
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if events table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events'")
        if not cursor.fetchone():
            logger.error("Events table does not exist in the database")
            return False
            
        # Check if status column exists in events table
        cursor.execute("PRAGMA table_info(events)")
        columns = [col[1].lower() for col in cursor.fetchall()]
        logger.info(f"Columns in events table: {', '.join(columns)}")
        
        if 'status' not in columns:
            logger.error("Status column is missing from the events table")
            return False
            
        logger.info("Database schema verification passed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error verifying database schema: {e}", exc_info=True)
        return False
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    # Check database in data directory
    data_db = Path('data/siem.db')
    if data_db.exists():
        print(f"\nChecking database at: {data_db.absolute()}")
        if check_database_schema(str(data_db.absolute())):
            print("✅ Database schema is valid")
        else:
            print("❌ Database schema is invalid")
    else:
        print(f"Database not found at: {data_db.absolute()}")
    
    # Check database in root directory
    root_db = Path('siem.db')
    if root_db.exists():
        print(f"\nChecking database at: {root_db.absolute()}")
        if check_database_schema(str(root_db.absolute())):
            print("✅ Database schema is valid")
        else:
            print("❌ Database schema is invalid")
    else:
        print(f"Database not found at: {root_db.absolute()}")
