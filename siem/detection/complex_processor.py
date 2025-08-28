"""
Complex Event Processing (CEP) for SIEM.

This module implements a complex event processor that can detect patterns
across multiple events over time.
"""
import time
import logging
from typing import Dict, List, Any, Optional, Callable, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
import re

logger = logging.getLogger(__name__)

class EventWindow:
    """Sliding time window for event processing."""
    
    def __init__(self, window_size: int, time_unit: str = 'seconds'):
        """Initialize the event window.
        
        Args:
            window_size: Size of the time window
            time_unit: One of 'seconds', 'minutes', 'hours', 'days'
        """
        self.window_size = window_size
        self.time_unit = time_unit
        self.events = deque()
        self.time_multipliers = {
            'seconds': 1,
            'minutes': 60,
            'hours': 3600,
            'days': 86400
        }
        
    def add_event(self, event: Dict[str, Any]) -> None:
        """Add an event to the window."""
        self.events.append((time.time(), event))
        self._prune_old_events()
    
    def get_events(self) -> List[Dict[str, Any]]:
        """Get all events in the window."""
        self._prune_old_events()
        return [event for _, event in self.events]
    
    def _prune_old_events(self) -> None:
        """Remove events that are outside the time window."""
        current_time = time.time()
        window_seconds = self.window_size * self.time_multipliers.get(self.time_unit, 1)
        
        # Remove events older than the window
        while self.events:
            timestamp, _ = self.events[0]
            if current_time - timestamp > window_seconds:
                self.events.popleft()
            else:
                break


class ComplexPattern:
    """Represents a complex event pattern to match against a sequence of events."""
    
    def __init__(self, pattern_id: str, name: str, description: str, 
                pattern: Dict[str, Any], actions: List[Dict[str, Any]],
                priority: int = 0, enabled: bool = True):
        """Initialize a complex pattern.
        
        Args:
            pattern_id: Unique identifier for the pattern
            name: Human-readable name of the pattern
            description: Description of what the pattern detects
            pattern: Dictionary defining the pattern structure
            actions: List of actions to take when the pattern matches
            priority: Pattern priority (higher numbers are evaluated first)
            enabled: Whether the pattern is enabled
        """
        self.id = pattern_id
        self.name = name
        self.description = description
        self.pattern = pattern
        self.actions = actions
        self.priority = priority
        self.enabled = enabled
        self.windows = {}  # Track event windows for different event types
        self.pattern_graph = self._build_pattern_graph(pattern)
        self.active_sequences = {}  # Track in-progress pattern matches
    
    def _build_pattern_graph(self, pattern: Dict[str, Any]) -> Dict[str, Any]:
        """Build a graph representation of the pattern for efficient matching."""
        # This is a simplified implementation - a real implementation would
        # create a proper state machine or similar structure
        return {
            'initial_state': 'start',
            'states': {
                'start': {
                    'transitions': self._parse_transitions(pattern)
                }
            },
            'time_window': pattern.get('time_window', {'seconds': 60}),
            'match_conditions': pattern.get('conditions', {})
        }
    
    def _parse_transitions(self, pattern: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse pattern transitions into a graph structure."""
        # This is a placeholder - implement actual transition parsing
        return []
    
    def process_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process an event against this pattern.
        
        Returns:
            List of actions to take if the pattern matches
        """
        if not self.enabled:
            return []
        
        # Get or create a window for this event type
        event_type = event.get('event.type', 'default')
        if event_type not in self.windows:
            time_window = self.pattern_graph.get('time_window', {'seconds': 60})
            self.windows[event_type] = EventWindow(
                window_size=time_window.get('value', 60),
                time_unit=time_window.get('unit', 'seconds')
            )
        
        # Add event to the appropriate window
        self.windows[event_type].add_event(event)
        
        # Check for pattern matches
        return self._check_pattern_matches(event)
    
    def _check_pattern_matches(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check if the current event completes any active patterns."""
        # This is a simplified implementation - a real implementation would
        # use the pattern graph to match sequences of events
        
        # For now, just check for simple threshold-based patterns
        for event_type, window in self.windows.items():
            events = window.get_events()
            if len(events) >= self.pattern.get('threshold', 10):
                return self.actions
        
        return []


class ComplexEventProcessor:
    """Processes events to detect complex patterns across multiple events."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the complex event processor."""
        self.config = config or {}
        self.patterns: Dict[str, ComplexPattern] = {}
        self.pattern_files = self.config.get('pattern_files', [])
        self.pattern_dir = self.config.get('pattern_dir', 'patterns')
        self.pattern_ext = self.config.get('pattern_ext', '.json')
        self.action_handlers = {
            'alert': self._handle_alert,
            'log': self._handle_log,
            'enrich': self._handle_enrich,
            'correlate': self._handle_correlate
        }
    
    def load_patterns(self) -> None:
        """Load patterns from configuration files."""
        # Implementation would load patterns from files
        pass
    
    def add_pattern(self, pattern: ComplexPattern) -> None:
        """Add a pattern to the processor."""
        self.patterns[pattern.id] = pattern
    
    def process_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process an event through all active patterns.
        
        Returns:
            List of actions to take based on pattern matches
        """
        actions = []
        
        # Process event against all patterns
        for pattern in sorted(self.patterns.values(), 
                            key=lambda p: p.priority, 
                            reverse=True):
            try:
                pattern_actions = pattern.process_event(event)
                if pattern_actions:
                    actions.extend(pattern_actions)
            except Exception as e:
                logger.error(f"Error processing event with pattern {pattern.id}: {e}", 
                            exc_info=True)
        
        # Execute actions
        results = []
        for action in actions:
            handler = self.action_handlers.get(action.get('type'))
            if handler:
                try:
                    result = handler(event, action)
                    results.append({
                        'action': action,
                        'result': result
                    })
                except Exception as e:
                    logger.error(f"Error executing action {action}: {e}", 
                                exc_info=True)
        
        return results
    
    def _handle_alert(self, event: Dict[str, Any], action: Dict[str, Any]) -> Dict[str, Any]:
        """Handle an alert action."""
        # Implementation would send an alert
        return {'status': 'success', 'message': 'Alert triggered'}
    
    def _handle_log(self, event: Dict[str, Any], action: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a log action."""
        # Implementation would log the event
        return {'status': 'success', 'message': 'Event logged'}
    
    def _handle_enrich(self, event: Dict[str, Any], action: Dict[str, Any]) -> Dict[str, Any]:
        """Handle an enrich action."""
        # Implementation would enrich the event with additional data
        return {'status': 'success', 'message': 'Event enriched'}
    
    def _handle_correlate(self, event: Dict[str, Any], action: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a correlate action."""
        # Implementation would correlate this event with others
        return {'status': 'success', 'message': 'Event correlated'}
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the processor."""
        return {
            'status': 'running',
            'patterns_loaded': len(self.patterns),
            'active_windows': sum(len(p.windows) for p in self.patterns.values())
        }
