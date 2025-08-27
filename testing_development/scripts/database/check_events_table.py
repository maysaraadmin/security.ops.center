import sqlite3
import sys

def check_events_table():
    try:
        conn = sqlite3.connect('data/siem.db')
        cursor = conn.cursor()
        
        # Get table info
        cursor.execute("PRAGMA table_info('events')")
        print("\nColumns in 'events' table:")
        for col in cursor.fetchall():
            print(f"- {col[1]} ({col[2]})")
            if col[4]:  # If there's a default value
                print(f"  Default: {col[4]}")
        
        # Get table creation SQL
        cursor.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'events'")
        create_sql = cursor.fetchone()
        if create_sql and create_sql[0]:
            print("\nTable creation SQL:")
            print(create_sql[0])
        
        # Check for any CHECK constraints
        cursor.execute("""
            SELECT sql FROM sqlite_master 
            WHERE type = 'table' AND name = 'events' 
            AND sql LIKE '%CHECK%'
        """)
        check_constraints = cursor.fetchall()
        if check_constraints:
            print("\nCHECK constraints:")
            for constraint in check_constraints:
                print(constraint[0])
        
        # Get sample data
        cursor.execute("SELECT severity, COUNT(*) as count FROM events GROUP BY severity")
        print("\nSeverity distribution:")
        for row in cursor.fetchall():
            print(f"- {row[0]}: {row[1]} events")
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    check_events_table()
