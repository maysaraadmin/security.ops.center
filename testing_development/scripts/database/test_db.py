import os
import sys
from pathlib import Path
from src.models.database import Database

def test_database_connection():
    try:
        # Get database path
        db_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
        os.makedirs(db_dir, exist_ok=True)
        db_path = os.path.join(db_dir, 'siem_test.db')
        
        print(f"Testing database connection to: {db_path}")
        
        # Initialize database
        db = Database(db_name=db_path)
        
        # Test connection
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT sqlite_version()")
            version = cursor.fetchone()[0]
            print(f"SQLite version: {version}")
            
            # Create a test table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL
                )
            """)
            conn.commit()
            print("Test table created successfully")
            
        print("Database test completed successfully!")
        return True
        
    except Exception as e:
        print(f"Error testing database: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_database_connection()
