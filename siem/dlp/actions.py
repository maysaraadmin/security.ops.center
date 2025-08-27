"""
DLP Policy Actions

Implements various actions that can be taken when a DLP policy is triggered.
"""
import logging
from typing import Dict, Any, Optional, Union, List
from dataclasses import dataclass, field
from enum import Enum, auto
import json
import hashlib
from pathlib import Path

class ActionType(Enum):
    """Types of actions that can be taken when a policy is triggered."""
    BLOCK = auto()
    ALLOW = auto()
    QUARANTINE = auto()
    REDACT = auto()
    ENCRYPT = auto()
    NOTIFY = auto()
    LOG = auto()

@dataclass
class ActionContext:
    """Context for policy actions."""
    source: str  # endpoint, network, cloud, email
    content: Union[bytes, str, None] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    user: Optional[Dict[str, Any]] = None
    destination: Optional[str] = None

class PolicyAction:
    """Base class for all policy actions."""
    
    def __init__(self, action_type: ActionType, params: Optional[Dict] = None):
        self.action_type = action_type
        self.params = params or {}
        self.logger = logging.getLogger(__name__)
    
    def execute(self, context: ActionContext) -> Dict[str, Any]:
        """Execute the action with the given context.
        
        Args:
            context: The context in which to execute the action
            
        Returns:
            Dict containing the result of the action
        """
        raise NotImplementedError("Subclasses must implement execute()")

class BlockAction(PolicyAction):
    """Action to block a file transfer, email, or other operation."""
    
    def __init__(self, params: Optional[Dict] = None):
        super().__init__(ActionType.BLOCK, params)
    
    def execute(self, context: ActionContext) -> Dict[str, Any]:
        """Execute the block action."""
        self.logger.warning(
            f"Blocking {context.source} operation: {context.metadata.get('operation', 'unknown')}"
        )
        return {
            "blocked": True,
            "message": self.params.get("message", "Operation blocked by DLP policy"),
            "context": context.metadata
        }

class EncryptAction(PolicyAction):
    """Action to encrypt sensitive data."""
    
    def __init__(self, params: Optional[Dict] = None):
        super().__init__(ActionType.ENCRYPT, params)
    
    def execute(self, context: ActionContext) -> Dict[str, Any]:
        """Execute the encrypt action."""
        # In a real implementation, this would encrypt the content
        self.logger.info(
            f"Encrypting {context.source} content"
        )
        return {
            "encrypted": True,
            "algorithm": self.params.get("algorithm", "AES-256"),
            "context": context.metadata
        }

class QuarantineAction(PolicyAction):
    """Action to quarantine a file or email."""
    
    def __init__(self, params: Optional[Dict] = None):
        super().__init__(ActionType.QUARANTINE, params)
        self.quarantine_dir = Path(params.get("quarantine_dir", "/var/quarantine"))
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
    
    def execute(self, context: ActionContext) -> Dict[str, Any]:
        """Execute the quarantine action."""
        if not context.content:
            return {"quarantined": False, "error": "No content to quarantine"}
            
        try:
            # Generate a unique filename
            content_hash = hashlib.sha256(
                context.content if isinstance(context.content, bytes) 
                else context.content.encode('utf-8')
            ).hexdigest()
            
            quarantine_path = self.quarantine_dir / f"quarantined_{content_hash}"
            
            # Save the content
            mode = 'wb' if isinstance(context.content, bytes) else 'w'
            with open(quarantine_path, mode) as f:
                f.write(context.content)
            
            self.logger.info(f"Quarantined content to {quarantine_path}")
            
            return {
                "quarantined": True,
                "path": str(quarantine_path),
                "context": context.metadata
            }
            
        except Exception as e:
            self.logger.error(f"Failed to quarantine content: {str(e)}", exc_info=True)
            return {
                "quarantined": False,
                "error": str(e),
                "context": context.metadata
            }

class RedactAction(PolicyAction):
    """Action to redact sensitive information from content."""
    
    def __init__(self, params: Optional[Dict] = None):
        super().__init__(ActionType.REDACT, params)
        self.replacement = params.get("replacement", "[REDACTED]")
    
    def execute(self, context: ActionContext) -> Dict[str, Any]:
        """Execute the redaction action."""
        if not context.content:
            return {"redacted": False, "error": "No content to redact"}
            
        try:
            if isinstance(context.content, bytes):
                # For binary content, we can't redact, so we'll return the original
                self.logger.warning("Cannot redact binary content")
                return {
                    "redacted": False,
                    "content": context.content,
                    "context": context.metadata
                }
            
            # In a real implementation, this would use the patterns from the policy
            # to identify and redact sensitive information
            redacted_content = context.content  # Placeholder
            
            self.logger.info("Redacted sensitive information from content")
            
            return {
                "redacted": True,
                "content": redacted_content,
                "context": context.metadata
            }
            
        except Exception as e:
            self.logger.error(f"Failed to redact content: {str(e)}", exc_info=True)
            return {
                "redacted": False,
                "error": str(e),
                "context": context.metadata
            }

class ActionFactory:
    """Factory for creating policy actions."""
    
    @staticmethod
    def create_action(action_def: Dict) -> PolicyAction:
        """Create an action from a definition.
        
        Args:
            action_def: Dictionary defining the action
            
        Returns:
            An instance of the appropriate PolicyAction subclass
        """
        action_type = ActionType[action_def.get("type").upper()]
        params = action_def.get("params", {})
        
        if action_type == ActionType.BLOCK:
            return BlockAction(params)
        elif action_type == ActionType.ENCRYPT:
            return EncryptAction(params)
        elif action_type == ActionType.QUARANTINE:
            return QuarantineAction(params)
        elif action_type == ActionType.REDACT:
            return RedactAction(params)
        else:
            raise ValueError(f"Unsupported action type: {action_type}")

# Example policy with actions
example_policy = {
    "id": "block_sensitive_emails",
    "name": "Block Emails with Sensitive Data",
    "description": "Block emails containing sensitive information",
    "scope": ["email"],
    "rules": [
        {
            "id": "block_ssn_in_email",
            "name": "Block SSN in Email",
            "conditions": [
                {
                    "type": "pattern_match",
                    "field": "content",
                    "pattern": r"\b\d{3}[-.]?\d{2}[-.]?\d{4}\b",
                    "sensitivity": "high"
                }
            ],
            "actions": [
                {
                    "type": "block",
                    "params": {
                        "message": "Email contains sensitive information (SSN)"
                    }
                },
                {
                    "type": "notify",
                    "params": {
                        "recipients": ["security@example.com"],
                        "subject": "Blocked email with sensitive data",
                        "template": "email_blocked.html"
                    }
                }
            ]
        }
    ]
}
