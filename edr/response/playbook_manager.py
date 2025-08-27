"""
Playbook Manager for EDR Response System.
Manages the loading, validation, and execution of response playbooks.
"""
import os
import json
import logging
import yaml
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
from enum import Enum
import copy

from .response_engine import ResponseAction, ResponseResult

class PlaybookValidationError(Exception):
    """Raised when a playbook fails validation."""
    pass

class PlaybookManager:
    """Manages response playbooks for automated remediation."""
    
    def __init__(self, playbooks_dir: Optional[str] = None):
        """Initialize the playbook manager."""
        self.logger = logging.getLogger('edr.response.playbook_manager')
        
        # Set up playbooks directory
        if not playbooks_dir:
            self.playbooks_dir = os.path.join(os.path.dirname(__file__), 'playbooks')
        else:
            self.playbooks_dir = playbooks_dir
        
        # Create playbooks directory if it doesn't exist
        os.makedirs(self.playbooks_dir, exist_ok=True)
        
        # Load playbooks
        self.playbooks: Dict[str, Dict[str, Any]] = {}
        self._load_playbooks()
    
    def _load_playbooks(self) -> None:
        """Load all playbooks from the playbooks directory."""
        self.playbooks = {}
        
        # Find all JSON and YAML files in the playbooks directory
        for ext in ('*.json', '*.yaml', '*.yml'):
            for filepath in Path(self.playbooks_dir).glob(ext):
                try:
                    self._load_playbook(filepath)
                except Exception as e:
                    self.logger.error(f"Failed to load playbook {filepath}: {e}")
        
        self.logger.info(f"Loaded {len(self.playbooks)} playbooks from {self.playbooks_dir}")
    
    def _load_playbook(self, filepath: Union[str, Path]) -> None:
        """Load a single playbook from a file."""
        filepath = str(filepath)
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                if filepath.endswith(('.yaml', '.yml')):
                    playbook = yaml.safe_load(f)
                else:  # JSON
                    playbook = json.load(f)
            
            # Validate the playbook
            self._validate_playbook(playbook)
            
            # Add to playbooks dictionary
            playbook_id = playbook.get('id') or os.path.splitext(os.path.basename(filepath))[0]
            self.playbooks[playbook_id] = playbook
            
            self.logger.debug(f"Loaded playbook: {playbook_id}")
            
        except (json.JSONDecodeError, yaml.YAMLError) as e:
            raise PlaybookValidationError(f"Invalid playbook format in {filepath}: {e}")
        except Exception as e:
            raise PlaybookValidationError(f"Failed to load playbook {filepath}: {e}")
    
    def _validate_playbook(self, playbook: Dict[str, Any]) -> None:
        """Validate a playbook structure."""
        if not isinstance(playbook, dict):
            raise PlaybookValidationError("Playbook must be a dictionary")
        
        # Check required fields
        required_fields = ['name', 'description', 'actions']
        for field in required_fields:
            if field not in playbook:
                raise PlaybookValidationError(f"Missing required field: {field}")
        
        # Validate actions
        if not isinstance(playbook['actions'], list):
            raise PlaybookValidationError("'actions' must be a list")
        
        for i, action in enumerate(playbook['actions']):
            if not isinstance(action, dict):
                raise PlaybookValidationError(f"Action {i} must be a dictionary")
            
            if 'action' not in action:
                raise PlaybookValidationError(f"Action {i} is missing 'action' field")
            
            # Validate action type
            try:
                ResponseAction(action['action'])
            except ValueError:
                valid_actions = [a.value for a in ResponseAction]
                raise PlaybookValidationError(
                    f"Invalid action type '{action['action']}' in action {i}. "
                    f"Valid actions are: {', '.join(valid_actions)}"
                )
            
            # Ensure parameters is a dictionary if it exists
            if 'parameters' in action and not isinstance(action['parameters'], dict):
                raise PlaybookValidationError(f"'parameters' in action {i} must be a dictionary")
        
        # Validate conditions if present
        if 'conditions' in playbook:
            if not isinstance(playbook['conditions'], list):
                raise PlaybookValidationError("'conditions' must be a list")
            
            for i, condition in enumerate(playbook['conditions']):
                if not isinstance(condition, dict):
                    raise PlaybookValidationError(f"Condition {i} must be a dictionary")
                
                if 'field' not in condition or 'operator' not in condition:
                    raise PlaybookValidationError(
                        f"Condition {i} is missing required fields ('field' and 'operator' are required)"
                    )
    
    def get_playbook(self, playbook_id: str) -> Dict[str, Any]:
        """Get a playbook by ID."""
        playbook = self.playbooks.get(playbook_id)
        if not playbook:
            raise ValueError(f"Playbook not found: {playbook_id}")
        return copy.deepcopy(playbook)
    
    def list_playbooks(self) -> List[Dict[str, Any]]:
        """List all available playbooks with basic information."""
        return [
            {
                'id': playbook_id,
                'name': playbook.get('name', 'Unnamed Playbook'),
                'description': playbook.get('description', ''),
                'actions': len(playbook.get('actions', [])),
                'conditions': len(playbook.get('conditions', [])),
                'enabled': playbook.get('enabled', True)
            }
            for playbook_id, playbook in self.playbooks.items()
        ]
    
    def create_playbook(self, playbook: Dict[str, Any]) -> str:
        """Create a new playbook."""
        # Validate the playbook
        self._validate_playbook(playbook)
        
        # Generate an ID if not provided
        playbook_id = playbook.get('id')
        if not playbook_id:
            # Create a slug from the name
            from slugify import slugify
            playbook_id = slugify(playbook['name'].lower())
            
            # Make sure the ID is unique
            base_id = playbook_id
            counter = 1
            while playbook_id in self.playbooks:
                playbook_id = f"{base_id}_{counter}"
                counter += 1
            
            playbook['id'] = playbook_id
        
        # Save the playbook to a file
        filepath = os.path.join(self.playbooks_dir, f"{playbook_id}.yaml")
        with open(filepath, 'w', encoding='utf-8') as f:
            yaml.safe_dump(playbook, f, default_flow_style=False, sort_keys=False)
        
        # Add to in-memory store
        self.playbooks[playbook_id] = playbook
        
        self.logger.info(f"Created new playbook: {playbook_id}")
        return playbook_id
    
    def update_playbook(self, playbook_id: str, playbook_data: Dict[str, Any]) -> None:
        """Update an existing playbook."""
        if playbook_id not in self.playbooks:
            raise ValueError(f"Playbook not found: {playbook_id}")
        
        # Make sure the ID in the data matches
        if 'id' in playbook_data and playbook_data['id'] != playbook_id:
            raise ValueError("Cannot change playbook ID")
        
        # Validate the updated playbook
        self._validate_playbook(playbook_data)
        
        # Save the updated playbook
        filepath = os.path.join(self.playbooks_dir, f"{playbook_id}.yaml")
        with open(filepath, 'w', encoding='utf-8') as f:
            yaml.safe_dump(playbook_data, f, default_flow_style=False, sort_keys=False)
        
        # Update in-memory store
        self.playbooks[playbook_id] = playbook_data
        
        self.logger.info(f"Updated playbook: {playbook_id}")
    
    def delete_playbook(self, playbook_id: str) -> None:
        """Delete a playbook."""
        if playbook_id not in self.playbooks:
            raise ValueError(f"Playbook not found: {playbook_id}")
        
        # Delete the playbook file
        file_extensions = ['.yaml', '.yml', '.json']
        deleted = False
        
        for ext in file_extensions:
            filepath = os.path.join(self.playbooks_dir, f"{playbook_id}{ext}")
            if os.path.exists(filepath):
                os.remove(filepath)
                deleted = True
                break
        
        if not deleted:
            self.logger.warning(f"No playbook file found for {playbook_id}")
        
        # Remove from in-memory store
        del self.playbooks[playbook_id]
        
        self.logger.info(f"Deleted playbook: {playbook_id}")
    
    def find_matching_playbooks(self, alert_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find playbooks that match the given alert data."""
        matching_playbooks = []
        
        for playbook_id, playbook in self.playbooks.items():
            # Skip disabled playbooks
            if not playbook.get('enabled', True):
                continue
            
            # If no conditions, match all
            if 'conditions' not in playbook or not playbook['conditions']:
                matching_playbooks.append(playbook)
                continue
            
            # Check conditions
            conditions_met = True
            for condition in playbook['conditions']:
                field = condition['field']
                operator = condition['operator']
                value = condition.get('value')
                
                # Get the field value from alert data using dot notation
                field_value = self._get_nested_value(alert_data, field)
                
                # Apply operator
                if not self._evaluate_condition(field_value, operator, value):
                    conditions_met = False
                    break
            
            if conditions_met:
                matching_playbooks.append(playbook)
        
        return matching_playbooks
    
    def _get_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        """Get a nested value from a dictionary using dot notation."""
        keys = path.split('.')
        value = data
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        
        return value
    
    def _evaluate_condition(self, field_value: Any, operator: str, expected_value: Any) -> bool:
        """Evaluate a condition."""
        try:
            if operator == 'equals':
                return field_value == expected_value
            elif operator == 'not_equals':
                return field_value != expected_value
            elif operator == 'contains':
                if field_value is None:
                    return False
                return expected_value in str(field_value)
            elif operator == 'not_contains':
                if field_value is None:
                    return True
                return expected_value not in str(field_value)
            elif operator == 'starts_with':
                if not isinstance(field_value, str):
                    field_value = str(field_value)
                return field_value.startswith(expected_value)
            elif operator == 'ends_with':
                if not isinstance(field_value, str):
                    field_value = str(field_value)
                return field_value.endswith(expected_value)
            elif operator == 'exists':
                return field_value is not None
            elif operator == 'not_exists':
                return field_value is None
            elif operator == 'greater_than':
                return float(field_value) > float(expected_value)
            elif operator == 'less_than':
                return float(field_value) < float(expected_value)
            elif operator == 'in':
                if not isinstance(expected_value, list):
                    expected_value = [expected_value]
                return field_value in expected_value
            elif operator == 'not_in':
                if not isinstance(expected_value, list):
                    expected_value = [expected_value]
                return field_value not in expected_value
            else:
                self.logger.warning(f"Unsupported operator: {operator}")
                return False
        except (TypeError, ValueError) as e:
            self.logger.warning(f"Error evaluating condition: {e}")
            return False

# Example usage
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    # Initialize the playbook manager
    playbook_manager = PlaybookManager()
    
    # List all playbooks
    playbooks = playbook_manager.list_playbooks()
    print(f"Available playbooks: {[p['name'] for p in playbooks]}")
    
    # Example alert data
    alert_data = {
        'severity': 'high',
        'type': 'ransomware',
        'source': 'edr',
        'details': {
            'process_name': 'malware.exe',
            'file_path': 'C:\\malware.exe',
            'source_ip': '192.168.1.100'
        }
    }
    
    # Find matching playbooks
    matching_playbooks = playbook_manager.find_matching_playbooks(alert_data)
    print(f"Matching playbooks: {[p['name'] for p in matching_playbooks]}")
