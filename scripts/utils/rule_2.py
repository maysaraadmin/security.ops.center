from typing import List, Dict, Any
from .database import Database

class RuleModel:
    def __init__(self, db: Database):
        self.db = db
        
    def get_all_rules(self) -> List[Dict[str, Any]]:
        """Retrieve all rules from the database"""
        query = "SELECT * FROM rules ORDER BY name"
        results = self.db.execute_query(query)
        
        rules = []
        for row in results:
            rules.append({
                'id': row[0],
                'name': row[1],
                'condition': row[2],
                'action': row[3],
                'severity': row[4],
                'enabled': bool(row[5])
            })
            
        return rules
    
    def create_rule(
        self,
        name: str,
        condition: str,
        action: str,
        severity: int,
        enabled: bool = True
    ) -> int:
        """Create a new rule"""
        query = """
            INSERT INTO rules (name, condition, action, severity, enabled)
            VALUES (?, ?, ?, ?, ?)
        """
        params = (name, condition, action, severity, int(enabled))
        self.db.execute_update(query, params)
        return self.db.cursor.lastrowid
    
    def update_rule(
        self,
        rule_id: int,
        name: str,
        condition: str,
        action: str,
        severity: int,
        enabled: bool
    ) -> bool:
        """Update an existing rule"""
        query = """
            UPDATE rules 
            SET name = ?, condition = ?, action = ?, severity = ?, enabled = ?
            WHERE id = ?
        """
        params = (name, condition, action, severity, int(enabled), rule_id)
        self.db.execute_update(query, params)
        return True
    
    def delete_rule(self, rule_id: int) -> bool:
        """Delete a rule"""
        query = "DELETE FROM rules WHERE id = ?"
        self.db.execute_update(query, (rule_id,))
        return True
    
    def toggle_rule(self, rule_id: int) -> bool:
        """Toggle a rule's enabled status"""
        query = "UPDATE rules SET enabled = NOT enabled WHERE id = ?"
        self.db.execute_update(query, (rule_id,))
        return True
    
    def get_active_rules(self) -> List[Dict[str, Any]]:
        """Get all enabled rules"""
        query = "SELECT * FROM rules WHERE enabled = 1"
        results = self.db.execute_query(query)
        
        rules = []
        for row in results:
            rules.append({
                'id': row[0],
                'name': row[1],
                'condition': row[2],
                'action': row[3],
                'severity': row[4],
                'enabled': bool(row[5])
            })
            
        return rules