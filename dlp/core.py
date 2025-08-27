"""
DLP Core Module

Core functionality for data discovery and classification.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Any, Callable, Coroutine, TYPE_CHECKING
import asyncio
import logging

logger = logging.getLogger('dlp.core')

class DLPUserInteraction:
    """Handles user interactions for DLP actions."""
    
    async def prompt_for_decision(
        self,
        message: str,
        options: List[str],
        default: Optional[str] = None
    ) -> str:
        """Prompt the user for a decision.
        
        Args:
            message: The message to display to the user
            options: List of available options
            default: Default option if user doesn't respond
            
        Returns:
            The user's selected option
        """
        # In a real implementation, this would show a dialog to the user
        print(f"\nDLP Action Required:")
        print(f"{message}")
        print("Options:", ", ".join(f"[{i+1}] {opt}" for i, opt in enumerate(options)))
        
        if default:
            print(f"Press Enter for default: {default}")
            
        while True:
            choice = input("Your choice: ").strip()
            if not choice and default:
                return default
                
            if choice.isdigit() and 1 <= int(choice) <= len(options):
                return options[int(choice)-1]
                
            print(f"Please enter a number between 1 and {len(options)}")
    
    def log_action(self, action: str, details: Dict[str, Any]) -> None:
        """Log a DLP action.
        
        Args:
            action: The action being taken
            details: Additional details about the action
        """
        logger.info(f"DLP Action: {action} - {details}")

# Forward declarations for type hints
if TYPE_CHECKING:
    from typing import Optional as Opt
    DLPScanner = 'DLPScanner'
    PolicyEngine = 'PolicyEngine'

class DataType(Enum):
    """Types of sensitive data."""
    PII = "pii"  # Personally Identifiable Information
    PHI = "phi"  # Protected Health Information
    PCI = "pci"  # Payment Card Information
    CREDENTIALS = "credentials"
    INTELLECTUAL_PROPERTY = "ip"
    CUSTOM = "custom"

class MatchConfidence(Enum):
    """Confidence level of a classification match."""
    LOW = 0.3
    MEDIUM = 0.6
    HIGH = 0.9
    CERTAIN = 1.0

@dataclass
class ClassificationResult:
    """Result of a data classification operation."""
    data_type: DataType
    confidence: MatchConfidence
    match: str
    context: str = ""
    location: str = ""
    line_number: Optional[int] = None
    rule_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

class DLPScanner:
    """Main DLP scanner class that coordinates scanning and classification."""
    
    def __init__(self, user_interaction: Optional[DLPUserInteraction] = None):
        self.scanners = []
        self.classifiers = []
        self.policy_engine = PolicyEngine()
        self.scan_results = []
        self.user_interaction = user_interaction or DLPUserInteraction()
    
    async def scan(
        self, 
        targets: List[str], 
        scan_types: Optional[List[str]] = None,
        callback: Optional[Callable[[ClassificationResult], Coroutine]] = None,
        user_info: Optional[Dict[str, Any]] = None,
        interactive: bool = True
    ) -> List[ClassificationResult]:
        """
        Scan targets for sensitive data with optional user interaction.
        
        Args:
            targets: List of targets to scan (file paths, directories, etc.)
            scan_types: Optional list of scan types to perform
            callback: Optional async callback for progress updates
            user_info: Information about the current user for policy decisions
            interactive: Whether to show interactive prompts to the user
            
        Returns:
            List of classification results
        """
        results = []
        user_info = user_info or {}
        
        # Notify user that scanning is starting
        if interactive:
            await self.user_interaction.notify_user(
                title="DLP Scan Started",
                message=f"Scanning {len(targets)} target(s) for sensitive data...",
                notification_type=NotificationType.TOAST,
                severity="info"
            )
        
        for i, target in enumerate(targets, 1):
            # If no specific scan types are specified, try to determine them
            target_scan_types = scan_types or self._detect_scan_types(target)
            
            for scan_type in target_scan_types:
                scanner = self._get_scanner(scan_type)
                if not scanner:
                    logger.warning(f"No scanner found for type: {scan_type}")
                    continue
                
                try:
                    # Notify user about current scan
                    if interactive:
                        await self.user_interaction.notify_user(
                            title="Scanning...",
                            message=f"Scanning {target} ({i}/{len(targets)})",
                            notification_type=NotificationType.TOAST,
                            severity="info",
                            metadata={
                                'progress': f"{i}/{len(targets)}",
                                'current_target': target,
                                'scan_type': scan_type
                            }
                        )
                    
                    # Scan the target with the appropriate scanner
                    async for content, metadata in scanner.scan(target):
                        # Classify the content
                        classified = await self._classify_content(content, metadata)
                        
                        # Process results with policies and user interaction if interactive
                        if interactive:
                            processed_list = await self.policy_engine.process_results(
                                [classified] if not isinstance(classified, list) else classified,
                                metadata,
                                user_info
                            )
                        else:
                            # Just apply policies without user interaction
                            processed_list = self.policy_engine.process_results(
                                [classified] if not isinstance(classified, list) else classified,
                                metadata
                            )
                        
                        # Add to results
                        if isinstance(processed_list, list):
                            results.extend(processed_list)
                            
                            # Call the callback if provided
                            if callback:
                                for result in processed_list:
                                    await callback(result)
                        else:
                            results.append(processed_list)
                            if callback:
                                await callback(processed_list)
                                
                except Exception as e:
                    error_msg = f"Error scanning {target} with {scan_type}: {e}"
                    logger.error(error_msg, exc_info=True)
                    
                    if interactive:
                        await self.user_interaction.notify_user(
                            title="Scan Error",
                            message=error_msg,
                            notification_type=NotificationType.TOAST,
                            severity="error"
                        )
                    continue
        
        # Notify user that scanning is complete
        if interactive:
            await self.user_interaction.notify_user(
                title="DLP Scan Complete",
                message=f"Scan complete. Found {len(results)} potential issues.",
                notification_type=NotificationType.TOAST,
                severity="success" if not results else "warning"
            )
        
        self.scan_results.extend(results)
        return results
    
    def add_scanner(self, scanner):
        """Add a scanner to the DLP system."""
        self.scanners.append(scanner)
    
    def add_classifier(self, classifier):
        """Add a classifier to the DLP system."""
        self.classifiers.append(classifier)
    
    async def _run_scan(self, scanner, target, callback):
        """Run a scan with the given scanner and target."""
        try:
            async for content, metadata in scanner.scan(target):
                results = await self._classify_content(content, metadata)
                for result in results:
                    self.scan_results.append(result)
                    if callback:
                        await callback(result)
        except Exception as e:
            logger.error(f"Error scanning {target} with {scanner.__class__.__name__}: {e}")
    
    async def _classify_content(
        self, 
        content: str, 
        metadata: Dict[str, Any]
    ) -> List[ClassificationResult]:
        """Classify content using all available classifiers."""
        results = []
        
        for classifier in self.classifiers:
            try:
                result = await classifier.classify(content, metadata)
                if result:
                    if isinstance(result, list):
                        results.extend(result)
                    else:
                        results.append(result)
            except Exception as e:
                logger.error(f"Error in classifier {classifier.__class__.__name__}: {e}")
        
        # Apply policies to filter and process results
        return self.policy_engine.process_results(results, metadata)
    
    def _get_scanner(self, scan_type: str):
        """Get a scanner for the given scan type."""
        for scanner in self.scanners:
            if scanner.scan_type == scan_type:
                return scanner
        return None

class DLPUserInteraction:
    """Handles user interactions for DLP actions."""
    
    async def prompt_for_decision(
        self,
        message: str,
        options: List[str],
        default: Optional[str] = None
    ) -> str:
        """Prompt the user for a decision.
        
        Args:
            message: The message to display to the user
            options: List of available options
            default: Default option if user doesn't respond
            
        Returns:
            The user's selected option
        """
        # In a real implementation, this would show a dialog to the user
        print(f"\nDLP Action Required:")
        print(f"{message}")
        print("Options:", ", ".join(f"[{i+1}] {opt}" for i, opt in enumerate(options)))
        
        if default:
            print(f"Press Enter for default: {default}")
            
        while True:
            choice = input("Your choice: ").strip()
            if not choice and default:
                return default
                
            if choice.isdigit() and 1 <= int(choice) <= len(options):
                return options[int(choice)-1]
                
            print(f"Please enter a number between 1 and {len(options)}")
    
    def log_action(self, action: str, details: Dict[str, Any]) -> None:
        """Log a DLP action.
        
        Args:
            action: The action being taken
            details: Additional details about the action
        """
        logger.info(f"DLP Action: {action} - {details}")


class PolicyEngine:
    """Engine for managing and applying DLP policies."""
    
    def __init__(self, user_interaction: Optional[DLPUserInteraction] = None):
        self.policies = []
        self.exclusions = []
        self.user_interaction = user_interaction or DLPUserInteraction()
    
    def add_policy(self, policy):
        """Add a DLP policy."""
        self.policies.append(policy)
    
    def add_exclusion(self, pattern: str, data_type: Optional[DataType] = None):
        """Add a pattern to exclude from scanning."""
        self.exclusions.append((pattern, data_type))
    
    async def process_results(
        self, 
        results: List[ClassificationResult],
        metadata: Dict[str, Any],
        user_info: Optional[Dict[str, Any]] = None
    ) -> List[ClassificationResult]:
        """
        Process classification results by applying policies and user interactions.
        
        Args:
            results: List of classification results
            metadata: Additional metadata about the scan
            user_info: Information about the current user
            
        Returns:
            List of filtered and processed classification results
        """
        filtered = []
        user_info = user_info or {}
        
        for result in results:
            # Check if this result should be excluded
            if self._is_excluded(result, metadata):
                continue
                
            # Apply policies
            policy_actions = []
            for policy in self.policies:
                if policy.matches(result.match, metadata):
                    # Collect policy actions
                    policy_actions.extend(policy.actions)
                    
                    # Apply policy transformations
                    result = policy.apply(result, metadata)
                    if result is None:  # Policy might filter out the result
                        break
            else:  # No policy filtered out the result
                # If we have policy actions, handle user interaction
                if policy_actions and self.user_interaction:
                    await self._handle_policy_actions(policy_actions, result, metadata, user_info)
                filtered.append(result)
        
        return filtered
    
    async def _handle_policy_actions(
        self,
        actions: List[Any],
        result: ClassificationResult,
        metadata: Dict[str, Any],
        user_info: Dict[str, Any]
    ) -> None:
        """Handle policy actions that require user interaction."""
        context = {
            'result': result,
            'metadata': metadata,
            'user': user_info,
            'timestamp': datetime.utcnow().isoformat(),
            'policy_actions': [
                action.value if hasattr(action, 'value') else str(action)
                for action in actions
            ]
        }
        
        # Determine what type of user interaction is needed
        if RemediationAction.BLOCK in actions:
            await self.user_interaction.apply_remediation(
                RemediationAction.BLOCK,
                context,
                user_info
            )
        elif RemediationAction.FORCE_ENCRYPTION in actions:
            await self.user_interaction.apply_remediation(
                RemediationAction.FORCE_ENCRYPTION,
                context,
                user_info
            )
        elif RemediationAction.WARN in actions:
            await self.user_interaction.notify_user(
                title="Security Warning",
                message=f"Potential data leak detected: {result.data_type.value}",
                notification_type=NotificationType.POPUP,
                severity="warning",
                actions=[
                    {"label": "Continue Anyway", "action": "bypass"},
                    {"label": "Cancel", "action": "cancel"}
                ],
                metadata={
                    'data_type': result.data_type.value,
                    'confidence': result.confidence.value,
                    'location': result.location,
                    'rule_id': result.rule_id
                }
            )
    
    def _is_excluded(
        self, 
        result: ClassificationResult, 
        metadata: Dict[str, Any]
    ) -> bool:
        """Check if a result matches any exclusion rule."""
        for pattern, data_type in self.exclusions:
            # Check if data type matches (if specified)
            if data_type is not None and result.data_type != data_type:
                continue
                
            # Check if the match contains the exclusion pattern
            if pattern.lower() in result.match.lower():
                return True
                
        return False
