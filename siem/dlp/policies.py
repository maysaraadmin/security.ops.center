"""
DLP Policy Management

Handles the creation, management, and evaluation of DLP policies.
"""
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

import yaml

class DLPPolicyManager:
    """Manages DLP policies and their evaluation."""

    def __init__(self, policy_dir: Optional[str] = None):
        """Initialize the DLP policy manager.
        
        Args:
            policy_dir: Directory containing policy files (YAML/JSON)
        """
        self.logger = logging.getLogger(__name__)
        self.policies: List[Dict] = []
        self.policy_dir = Path(policy_dir) if policy_dir else None
        
        if self.policy_dir and self.policy_dir.exists():
            self._load_policies_from_dir()
    
    def _load_policies_from_dir(self) -> None:
        """Load policies from the configured policy directory."""
        if not self.policy_dir or not self.policy_dir.exists():
            self.logger.warning(f"Policy directory not found: {self.policy_dir}")
            return
            
        for policy_file in self.policy_dir.glob('*.yaml'):
            self.load_policy(policy_file)
            
        for policy_file in self.policy_dir.glob('*.json'):
            self.load_policy(policy_file)
    
    def load_policy(self, policy_path: Union[str, Path]) -> bool:
        """
        Load a single policy from a file.
        
        Args:
            policy_path: Path to the policy file (YAML or JSON)
            
        Returns:
            bool: True if the policy was loaded successfully, False otherwise
        """
        try:
            policy_path = Path(policy_path)
            with open(policy_path, 'r', encoding='utf-8') as f:
                if policy_path.suffix.lower() == '.json':
                    policy = json.load(f)
                else:  # Default to YAML
                    policy = yaml.safe_load(f)
                
                if self._validate_policy(policy):
                    self.policies.append(policy)
                    self.logger.info(f"Loaded policy: {policy.get('name', 'Unnamed')} from {policy_path}")
                    return True
                
        except Exception as e:
            self.logger.error(f"Error loading policy from {policy_path}: {str(e)}", exc_info=True)
            
        return False
    
    def _validate_policy(self, policy: Dict) -> bool:
        """
        Validate a policy definition.
        
        Args:
            policy: Policy dictionary to validate
            
        Returns:
            bool: True if the policy is valid, False otherwise
        """
        required_fields = ['id', 'name', 'description', 'rules']
        
        for field in required_fields:
            if field not in policy:
                self.logger.error(f"Policy missing required field: {field}")
                return False
                
        if not isinstance(policy['rules'], list):
            self.logger.error("Policy rules must be a list")
            return False
            
        # Validate each rule in the policy
        for rule in policy['rules']:
            if not self._validate_rule(rule):
                return False
                
        return True
    
    def _validate_rule(self, rule: Dict) -> bool:
        """
        Validate a single rule within a policy.
        
        Args:
            rule: Rule dictionary to validate
            
        Returns:
            bool: True if the rule is valid, False otherwise
        """
        required_fields = ['id', 'name', 'conditions', 'actions']
        
        for field in required_fields:
            if field not in rule:
                self.logger.error(f"Rule missing required field: {field}")
                return False
                
        if not isinstance(rule['conditions'], list) or not rule['conditions']:
            self.logger.error("Rule must have at least one condition")
            return False
            
        if not isinstance(rule['actions'], list) or not rule['actions']:
            self.logger.error("Rule must have at least one action")
            return False
            
        return True
    
    def evaluate_policies(self, analysis_results: Dict, context: Optional[Dict] = None) -> List[Dict]:
        """
        Evaluate all loaded policies against the analysis results.
        
        Args:
            analysis_results: Results from DLP analysis
            context: Additional context for policy evaluation
            
        Returns:
            List of triggered policy actions
        """
        context = context or {}
        triggered_actions = []
        
        for policy in self.policies:
            for rule in policy.get('rules', []):
                if self._evaluate_rule(rule, analysis_results, context):
                    triggered_actions.extend(rule.get('actions', []))
        
        return triggered_actions
    
    def _evaluate_rule(self, rule: Dict, analysis_results: Dict, context: Dict) -> bool:
        """
        Evaluate a single rule against the analysis results.
        
        Args:
            rule: Rule to evaluate
            analysis_results: Results from DLP analysis
            context: Additional context for evaluation
            
        Returns:
            bool: True if the rule conditions are met, False otherwise
        """
        # TODO: Implement more sophisticated condition evaluation
        # For now, we'll just check if any finding matches the rule conditions
        
        for condition in rule.get('conditions', []):
            condition_type = condition.get('type')
            
            if condition_type == 'finding_type':
                finding_type = condition.get('value')
                if not any(f['type'] == finding_type for f in analysis_results.get('findings', [])):
                    return False
                    
            elif condition_type == 'sensitivity':
                sensitivity = condition.get('value')
                if not any(f['sensitivity'] == sensitivity for f in analysis_results.get('findings', [])):
                    return False
                    
            # Add more condition types as needed
            
        return True  # All conditions passed
    
    def get_policy_by_id(self, policy_id: str) -> Optional[Dict]:
        """
        Get a policy by its ID.
        
        Args:
            policy_id: ID of the policy to retrieve
            
        Returns:
            The policy dictionary if found, None otherwise
        """
        return next((p for p in self.policies if p.get('id') == policy_id), None)
    
    def get_all_policies(self) -> List[Dict]:
        """
        Get all loaded policies.
        
        Returns:
            List of all loaded policies
        """
        return self.policies.copy()
    
    def clear_policies(self) -> None:
        """Clear all loaded policies."""
        self.policies = []
        self.logger.info("Cleared all DLP policies")
