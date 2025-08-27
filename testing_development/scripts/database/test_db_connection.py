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
        logging.FileHandler('test_db_connection.log')
    ]
)
logger = logging.getLogger('test_db')

def test_database_connection(db_path):
    """Test database connection and verify schema."""
    try:
        logger.info(f"Testing database connection to: {db_path}")
        
        # Check if database file exists
        if not os.path.exists(db_path):
            logger.error(f"Database file does not exist: {db_path}")
            return False
            
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check database integrity
        cursor.execute("PRAGMA integrity_check;")
        integrity_check = cursor.fetchone()
        logger.info(f"Database integrity check: {integrity_check[0] if integrity_check else 'Failed'}")
        
        # List all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        logger.info(f"Found {len(tables)} tables: {', '.join(tables) if tables else 'No tables found'}")
        
        # Check events table structure
        if 'events' in tables:
            cursor.execute("PRAGMA table_info(events)")
            columns = [col[1] for col in cursor.fetchall()]
            logger.info(f"Events table columns: {', '.join(columns) if columns else 'No columns found'}")
            
            # Check for required columns
            required_columns = {'id', 'timestamp', 'source', 'event_type', 'severity', 'status'}
            missing_columns = required_columns - set(columns)
            if missing_columns:
                logger.warning(f"Missing required columns in events table: {', '.join(missing_columns)}")
            else:
                logger.info("All required columns found in events table")
        else:
            logger.warning("Events table not found in the database")
        
        # Check indexes
        cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='index'")
        indexes = cursor.fetchall()
        logger.info(f"Found {len(indexes)} indexes")
        for idx_name, idx_sql in indexes:
            logger.info(f"  - {idx_name}: {idx_sql}")
        
        conn.close()
        return True
        
    except Exception as e:
        logger.error(f"Error testing database connection: {e}", exc_info=True)
        if 'conn' in locals():
            try:
                conn.close()
            except:
                pass
        return False

if __name__ == "__main__":
    # Test both possible database locations
    db_paths = [
        os.path.abspath("data/siem.db"),
        os.path.abspath("siem.db")
    ]
    
    for db_path in db_paths:
        print(f"\n{'='*80}")
        print(f"Testing database at: {db_path}")
        print(f"{'='*80}")
        if test_database_connection(db_path):
            print("✅ Database test completed successfully")
        else:
            print("❌ Database test failed")
