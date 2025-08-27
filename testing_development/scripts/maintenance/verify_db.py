import sqlite3
import os
from pathlib import Path

def check_database():
    # Get the database path
    db_path = str(Path(__file__).parent.parent / 'siem.db')
    print(f"Checking database at: {db_path}")
    
    if not os.path.exists(db_path):
        print("Error: Database file does not exist!")
        return
    
    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        print("\nTables in database:")
        for table in tables:
            print(f"- {table[0]}")
        
        # Check schema of important tables
        important_tables = ['events', 'alerts', 'rules', 'users']
        for table in important_tables:
            try:
                cursor.execute(f"PRAGMA table_info({table})")
                columns = cursor.fetchall()
                print(f"\nSchema for table '{table}':")
                for col in columns:
                    print(f"  {col[1]} ({col[2]}) {'PRIMARY KEY' if col[5] else ''}")
            except sqlite3.OperationalError:
                print(f"\nTable '{table}' does not exist!")
        
        # Check if any data exists
        for table in important_tables:
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]
                print(f"\nTable '{table}' has {count} rows")
            except sqlite3.OperationalError:
                pass
        
        conn.close()
        
    except Exception as e:
        print(f"Error checking database: {e}")

if __name__ == "__main__":
    check_database()
