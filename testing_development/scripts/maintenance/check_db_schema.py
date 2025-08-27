import sqlite3
import sys
from pathlib import Path

def check_db_schema(db_path):
    """Check the database schema and report any issues."""
    if not Path(db_path).exists():
        print(f"Error: Database file not found: {db_path}")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get list of tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        
        print("\n=== Database Schema Check ===")
        print(f"Found {len(tables)} tables: {', '.join(tables)}\n")
        
        # Check each table's structure
        for table in tables:
            print(f"Table: {table}")
            print("-" * (len(table) + 8))
            
            # Get table info
            cursor.execute(f"PRAGMA table_info({table})")
            columns = cursor.fetchall()
            
            if not columns:
                print(f"  Warning: No columns found in table '{table}'")
                continue
                
            print("Columns:")
            for col in columns:
                print(f"  {col[1]} ({col[2]}) {'PRIMARY KEY' if col[5] else ''} {'NOT NULL' if col[3] else ''}")
            
            # Check for indexes
            cursor.execute(f"PRAGMA index_list({table})")
            indexes = cursor.fetchall()
            
            if indexes:
                print("\n  Indexes:")
                for idx in indexes:
                    idx_name = idx[1]
                    cursor.execute(f"PRAGMA index_info({idx_name})")
                    idx_cols = cursor.fetchall()
                    col_names = [col[2] for col in idx_cols]
                    print(f"    {idx_name}: {', '.join(col_names)}")
            
            print("\n" + "="*50 + "\n")
        
        return True
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    db_path = sys.argv[1] if len(sys.argv) > 1 else 'siem.db'
    check_db_schema(db_path)
