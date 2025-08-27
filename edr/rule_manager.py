"""
EDR Rule Management System
Handles loading, validating, and managing detection rules.
"""
import json
import os
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
import yaml

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("EDR_RuleManager")

class RuleManager:
    """Manages EDR detection rules with support for multiple rule formats."""
    
    def __init__(self, rules_dir: str = "rules"):
        """Initialize the rule manager with a directory containing rule files."""
        self.rules_dir = Path(rules_dir)
        self.rules: List[Dict[str, Any]] = []
        self.rule_groups: Dict[str, List[Dict[str, Any]]] = {
            'process': [],
            'network': [],
            'file': [],
            'registry': [],
            'memory': []
        }
        self._load_rules()
    
    def _load_rules(self) -> None:
        """Load all rules from the rules directory."""
        if not self.rules_dir.exists():
            logger.warning(f"Rules directory not found: {self.rules_dir}")
            self.rules_dir.mkdir(parents=True, exist_ok=True)
            self._create_default_rules()
            return
        
        for rule_file in self.rules_dir.glob("*.[yaml|yml|json]"):
            try:
                if rule_file.suffix.lower() in ['.yaml', '.yml']:
                    with open(rule_file, 'r', encoding='utf-8') as f:
                        rules = yaml.safe_load(f)
                else:  # JSON
                    with open(rule_file, 'r', encoding='utf-8') as f:
                        rules = json.load(f)
                
                if isinstance(rules, list):
                    self._process_rules(rules)
                elif isinstance(rules, dict):
                    self._process_rule(rules)
                
                logger.info(f"Loaded {len(self.rules)} rules from {rule_file}")
                
            except (yaml.YAMLError, json.JSONDecodeError) as e:
                logger.error(f"Error parsing rule file {rule_file}: {e}")
            except Exception as e:
                logger.error(f"Error loading rule file {rule_file}: {e}")
    
    def _process_rules(self, rules: List[Dict[str, Any]]) -> None:
        """Process and validate a list of rules."""
        for rule in rules:
            self._process_rule(rule)
    
    def _process_rule(self, rule: Dict[str, Any]) -> None:
        """Process and validate a single rule."""
        try:
            # Validate required fields
            required_fields = ['id', 'name', 'description', 'severity', 'enabled', 'condition']
            if not all(field in rule for field in required_fields):
                logger.warning(f"Skipping invalid rule: missing required fields: {rule.get('id', 'unknown')}")
                return
            
            # Set defaults
            rule.setdefault('tags', [])
            rule.setdefault('author', 'EDR System')
            rule.setdefault('version', '1.0')
            rule.setdefault('created', '')
            rule.setdefault('modified', '')
            
            # Add to rules list
            self.rules.append(rule)
            
            # Add to appropriate group
            rule_type = rule.get('type', 'process').lower()
            if rule_type in self.rule_groups:
                self.rule_groups[rule_type].append(rule)
            else:
                self.rule_groups[rule_type] = [rule]
                
        except Exception as e:
            logger.error(f"Error processing rule {rule.get('id', 'unknown')}: {e}")
    
    def _create_default_rules(self) -> None:
        """Create default rules if no rules are found."""
        default_rules = [
            {
                "id": "PROC-001",
                "name": "Suspicious Process Creation",
                "description": "Detects creation of suspicious processes",
                "severity": "high",
                "enabled": True,
                "type": "process",
                "condition": {
                    "process_name": ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"],
                    "parent_process": ["explorer.exe", "iexplore.exe", "chrome.exe", "firefox.exe"]
                },
                "action": "alert"
            },
            {
                "id": "NET-001",
                "name": "Suspicious Network Connection",
                "description": "Detects suspicious outbound network connections",
                "severity": "medium",
                "enabled": True,
                "type": "network",
                "condition": {
                    "remote_port": ["4444", "8080", "53"],
                    "process_name": ["powershell.exe", "cmd.exe"]
                },
                "action": "alert"
            }
        ]
        
        # Save default rules
        default_file = self.rules_dir / "default_rules.yaml"
        with open(default_file, 'w', encoding='utf-8') as f:
            yaml.dump(default_rules, f, default_flow_style=False)
        
        self._process_rules(default_rules)
        logger.info(f"Created default rules at {default_file}")
    
    def get_rules(self, rule_type: str = None, enabled: bool = None) -> List[Dict[str, Any]]:
        """Get rules, optionally filtered by type and enabled status."""
        if rule_type:
            rules = self.rule_groups.get(rule_type.lower(), [])
        else:
            rules = self.rules
        
        if enabled is not None:
            return [r for r in rules if r['enabled'] == enabled]
        return rules
    
    def get_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Get a rule by its ID."""
        for rule in self.rules:
            if rule.get('id') == rule_id:
                return rule
        return None
    
    def enable_rule(self, rule_id: str, enabled: bool = True) -> bool:
        """Enable or disable a rule."""
        for rule in self.rules:
            if rule.get('id') == rule_id:
                rule['enabled'] = enabled
                return True
        return False
    
    def add_rule(self, rule: Dict[str, Any]) -> bool:
        """Add a new rule."""
        if 'id' not in rule:
            logger.error("Cannot add rule: missing 'id' field")
            return False
        
        # Check if rule already exists
        if self.get_rule(rule['id']):
            logger.warning(f"Rule with ID {rule['id']} already exists")
            return False
        
        self._process_rule(rule)
        return True
    
    def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> bool:
        """Update an existing rule."""
        rule = self.get_rule(rule_id)
        if not rule:
            return False
        
        # Don't allow changing the ID
        updates.pop('id', None)
        rule.update(updates)
        return True
    
    def delete_rule(self, rule_id: str) -> bool:
        """Delete a rule."""
        for i, rule in enumerate(self.rules):
            if rule.get('id') == rule_id:
                # Remove from rules list
                self.rules.pop(i)
                
                # Remove from rule groups
                for group in self.rule_groups.values():
                    group[:] = [r for r in group if r.get('id') != rule_id]
                
                return True
        return False
    
    def export_rules(self, output_file: str, format: str = 'yaml') -> bool:
        """Export all rules to a file."""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                if format.lower() == 'json':
                    json.dump(self.rules, f, indent=2)
                else:  # default to YAML
                    yaml.dump(self.rules, f, default_flow_style=False)
            return True
        except Exception as e:
            logger.error(f"Error exporting rules: {e}")
            return False

# Example usage
if __name__ == "__main__":
    # Initialize rule manager
    rule_manager = RuleManager("rules")
    
    # Get all enabled process rules
    process_rules = rule_manager.get_rules(rule_type="process", enabled=True)
    print(f"Loaded {len(process_rules)} process rules")
    
    # Export rules
    rule_manager.export_rules("exported_rules.yaml")
