import sqlite3
def check_schema():
    try:
        conn = sqlite3.connect('D:\\siem\\data\\siem.db')
        cursor = conn.cursor()
        
        # List all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        print("\n=== Database Schema Check ===")
        print(f"Found {len(tables)} tables in the database:")
        
        for table in tables:
            table_name = table[0]
            print(f"\nTable: {table_name}")
            print("-" * 50)
            
            # Get table info
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = cursor.fetchall()
            print(f"Columns ({len(columns)}):")
            for col in columns:
                print(f"  - {col[1]} ({col[2]})")
                
            # Get index info
            cursor.execute(f"PRAGMA index_list({table_name})")
            indexes = cursor.fetchall()
            if indexes:
                print("\nIndexes:")
                for idx in indexes:
                    idx_name = idx[1]
                    cursor.execute(f"PRAGMA index_info({idx_name})")
                    idx_cols = cursor.fetchall()
                    cols = [col[2] for col in idx_cols]
                    print(f"  - {idx_name}: {', '.join(cols)}")
        
        conn.close()
        
    except Exception as e:
        print(f"Error checking schema: {e}")
        raise

if __name__ == "__main__":
    check_schema()
