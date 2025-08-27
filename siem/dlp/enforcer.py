"""
DLP Policy Enforcer

Handles the execution and enforcement of DLP policies across different scopes.
"""
import logging
from typing import Dict, List, Optional, Any, Set, Union
from dataclasses import dataclass
from enum import Enum
import json
from pathlib import Path

from .actions import ActionFactory, ActionContext, ActionType
from .policies import DLPPolicyManager

class PolicyScope(Enum):
    """Scopes where DLP policies can be applied."""
    ENDPOINT = "endpoint"
    NETWORK = "network"
    CLOUD = "cloud"
    EMAIL = "email"
    ALL = "all"

@dataclass
class PolicyMatch:
    """Represents a match between a policy and content."""
    policy_id: str
    rule_id: str
    conditions_matched: List[Dict]
    actions: List[Dict]
    context: Dict[str, Any]

class PolicyEnforcer:
    """Enforces DLP policies across different scopes."""
    
    def __init__(self, policy_dir: Optional[str] = None):
        """Initialize the policy enforcer.
        
        Args:
            policy_dir: Directory containing policy files
        """
        self.logger = logging.getLogger(__name__)
        self.policy_manager = DLPPolicyManager(policy_dir)
        self.action_factory = ActionFactory()
        self.scope_handlers = {
            PolicyScope.ENDPOINT: self._handle_endpoint,
            PolicyScope.NETWORK: self._handle_network,
            PolicyScope.CLOUD: self._handle_cloud,
            PolicyScope.EMAIL: self._handle_email,
        }
    
    def evaluate_content(self, content: Union[str, bytes], scope: Union[str, PolicyScope], 
                        context: Optional[Dict] = None) -> List[Dict]:
        """Evaluate content against all applicable policies.
        
        Args:
            content: The content to evaluate
            scope: The scope of the content (endpoint, network, cloud, email)
            context: Additional context for evaluation
            
        Returns:
            List of actions that were executed
        """
        if isinstance(scope, str):
            try:
                scope = PolicyScope(scope.lower())
            except ValueError:
                self.logger.error(f"Invalid scope: {scope}")
                return []
        
        context = context or {}
        context['content'] = content
        
        # Get all policies that apply to this scope
        policies = self._get_policies_for_scope(scope)
        
        # Evaluate each policy
        matches = []
        for policy in policies:
            policy_matches = self._evaluate_policy(policy, content, context)
            matches.extend(policy_matches)
        
        # Execute actions for all matches
        results = []
        for match in matches:
            action_results = self._execute_actions(match.actions, match.context)
            results.append({
                'policy_id': match.policy_id,
                'rule_id': match.rule_id,
                'actions_executed': action_results
            })
        
        return results
    
    def _get_policies_for_scope(self, scope: PolicyScope) -> List[Dict]:
        """Get all policies that apply to the given scope."""
        policies = []
        for policy in self.policy_manager.get_all_policies():
            policy_scopes = policy.get('scope', [PolicyScope.ALL.value])
            if scope.value in policy_scopes or PolicyScope.ALL.value in policy_scopes:
                policies.append(policy)
        return policies
    
    def _evaluate_policy(self, policy: Dict, content: Any, context: Dict) -> List[PolicyMatch]:
        """Evaluate a single policy against the content."""
        matches = []
        
        for rule in policy.get('rules', []):
            conditions_met, matched_conditions = self._evaluate_rule(rule, content, context)
            if conditions_met:
                matches.append(PolicyMatch(
                    policy_id=policy['id'],
                    rule_id=rule['id'],
                    conditions_matched=matched_conditions,
                    actions=rule.get('actions', []),
                    context=context.copy()
                ))
        
        return matches
    
    def _evaluate_rule(self, rule: Dict, content: Any, context: Dict) -> tuple[bool, List[Dict]]:
        """Evaluate a single rule's conditions."""
        matched_conditions = []
        
        for condition in rule.get('conditions', []):
            condition_met = self._evaluate_condition(condition, content, context)
            if not condition_met:
                return False, []
            matched_conditions.append(condition)
        
        return len(matched_conditions) > 0, matched_conditions
    
    def _evaluate_condition(self, condition: Dict, content: Any, context: Dict) -> bool:
        """Evaluate a single condition."""
        condition_type = condition.get('type')
        
        if condition_type == 'pattern_match':
            field = condition.get('field')
            pattern = condition.get('pattern')
            
            if field == 'content':
                if isinstance(content, bytes):
                    # For binary content, we can only do simple pattern matching
                    try:
                        content_str = content.decode('utf-8', errors='ignore')
                    except Exception as e:
                        self.logger.warning(f"Failed to decode content: {str(e)}")
                        return False
                else:
                    content_str = str(content)
                
                import re
                return bool(re.search(pattern, content_str))
            
            # Handle other fields in the context
            if field in context:
                field_value = str(context[field])
                import re
                return bool(re.search(pattern, field_value))
            
            return False
            
        elif condition_type == 'file_extension':
            if 'file_path' in context:
                file_path = Path(context['file_path'])
                return file_path.suffix.lower() in condition.get('extensions', [])
            return False
            
        # Add more condition types as needed
        
        return False
    
    def _execute_actions(self, actions: List[Dict], context: Dict) -> List[Dict]:
        """Execute a list of actions."""
        results = []
        
        for action_def in actions:
            try:
                action = self.action_factory.create_action(action_def)
                action_context = ActionContext(
                    source=context.get('source', 'unknown'),
                    content=context.get('content'),
                    metadata=context,
                    user=context.get('user'),
                    destination=context.get('destination')
                )
                
                result = action.execute(action_context)
                results.append({
                    'type': action.action_type.name.lower(),
                    'success': True,
                    'result': result
                })
                
            except Exception as e:
                self.logger.error(f"Failed to execute action: {str(e)}", exc_info=True)
                results.append({
                    'type': action_def.get('type', 'unknown'),
                    'success': False,
                    'error': str(e)
                })
        
        return results
    
    # Scope-specific handlers
    def _handle_endpoint(self, content: Any, context: Dict) -> List[Dict]:
        """Handle content at the endpoint level."""
        return self.evaluate_content(content, PolicyScope.ENDPOINT, context)
    
    def _handle_network(self, content: Any, context: Dict) -> List[Dict]:
        """Handle network traffic."""
        return self.evaluate_content(content, PolicyScope.NETWORK, context)
    
    def _handle_cloud(self, content: Any, context: Dict) -> List[Dict]:
        """Handle cloud storage and services."""
        return self.evaluate_content(content, PolicyScope.CLOUD, context)
    
    def _handle_email(self, content: Any, context: Dict) -> List[Dict]:
        """Handle email content."""
        return self.evaluate_content(content, PolicyScope.EMAIL, context)
    
    def handle_content(self, content: Any, scope: Union[str, PolicyScope], 
                      context: Optional[Dict] = None) -> List[Dict]:
        """Handle content based on its scope.
        
        This is the main entry point for the enforcer.
        """
        if isinstance(scope, str):
            try:
                scope = PolicyScope(scope.lower())
            except ValueError:
                self.logger.error(f"Invalid scope: {scope}")
                return []
        
        handler = self.scope_handlers.get(scope)
        if not handler:
            self.logger.error(f"No handler for scope: {scope}")
            return []
        
        context = context or {}
        context['scope'] = scope.value
        
        return handler(content, context)
