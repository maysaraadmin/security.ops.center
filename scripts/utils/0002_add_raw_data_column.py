"""Migration to add raw_data column to events table."""

def migrate(db_conn):
    """Apply the migration.
    
    Args:
        db_conn: Database connection object
    """
    cursor = db_conn.cursor()
    
    try:
        # Check if the column already exists
        cursor.execute("PRAGMA table_info(events)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'raw_data' not in columns:
            # Add the raw_data column
            cursor.execute("""
                ALTER TABLE events 
                ADD COLUMN raw_data TEXT
            """)
            db_conn.commit()
            print("Successfully added raw_data column to events table")
        else:
            print("raw_data column already exists in events table")
            
    except Exception as e:
        db_conn.rollback()
        print(f"Error adding raw_data column: {str(e)}")
        raise
    finally:
        cursor.close()

if __name__ == "__main__":
    import sqlite3
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python 0002_add_raw_data_column.py <database_path>")
        sys.exit(1)
        
    db_path = sys.argv[1]
    try:
        with sqlite3.connect(db_path) as conn:
            migrate(conn)
        print("Migration completed successfully")
    except Exception as e:
        print(f"Migration failed: {str(e)}")
        sys.exit(1)
