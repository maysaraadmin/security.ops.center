#!/usr/bin/env python3
"""
Check Database Structure

This script checks the structure of the SIEM database.
"""
import os
import sys
import sqlite3

def check_database_structure(db_path):
    """Check the structure of the database."""
    if not os.path.exists(db_path):
        print(f"Database file not found: {db_path}")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get list of tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        print(f"\nTables in database: {', '.join(tables) if tables else 'No tables found'}")
        
        # Check each table's structure
        for table in tables:
            print(f"\nTable: {table}")
            print("-" * (len(table) + 7))
            
            # Get table info
            cursor.execute(f"PRAGMA table_info({table})")
            columns = cursor.fetchall()
            
            if not columns:
                print("  No columns found")
                continue
                
            print(f"  {'Column':<20} {'Type':<15} {'Not Null':<8} {'Primary Key':<11} {'Default'}")
            print("  " + "-" * 70)
            
            for col in columns:
                col_id, name, col_type, not_null, default_val, pk = col
                print(f"  {name:<20} {col_type:<15} {'YES' if not_null else 'NO':<8} {'YES' if pk else 'NO':<11} {default_val or 'None'}")
            
            # Get indexes for this table
            cursor.execute(f"PRAGMA index_list({table})")
            indexes = cursor.fetchall()
            
            if indexes:
                print("\n  Indexes:")
                for idx in indexes:
                    idx_id, idx_name, unique = idx[0], idx[1], idx[2]
                    cursor.execute(f"PRAGMA index_info({idx_name})")
                    idx_cols = [row[2] for row in cursor.fetchall()]
                    unique_str = "UNIQUE " if unique else ""
                    print(f"    {unique_str}INDEX {idx_name} ON {table}({', '.join(idx_cols)})")
        
        # Check foreign keys
        cursor.execute("PRAGMA foreign_key_list('alerts')")
        fks = cursor.fetchall()
        
        if fks:
            print("\nForeign Keys:")
            for fk in fks:
                print(f"  {fk[3]}.{fk[4]} -> {fk[2]}({fk[5]})")
        
        conn.close()
        return True
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'siem.db')
    print(f"Checking database structure: {db_path}")
    
    if not os.path.exists(os.path.dirname(db_path)):
        print(f"Database directory does not exist: {os.path.dirname(db_path)}")
        sys.exit(1)
    
    success = check_database_structure(db_path)
    if not success:
        print("\nDatabase check failed.")
        sys.exit(1)
    
    print("\nDatabase check completed successfully.")
