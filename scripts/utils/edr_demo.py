"""
EDR System Demo

This script demonstrates the basic usage of the EDR system components.
"""

import time
import json
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('edr.demo')

def demo_detection_engine():
    """Demonstrate the detection engine with sample rules and events."""
    from src.edr.detection import DetectionEngine, DetectionRule
    
    print("\n=== Detection Engine Demo ===\n")
    
    # Create a detection engine
    engine = DetectionEngine()
    
    # Create a sample rule
    rule = DetectionRule(
        id="suspicious_process_001",
        name="Suspicious Process Execution",
        description="Detects execution of suspicious processes",
        severity="high",
        event_types=["process_start"],
        regex_patterns=[
            {
                "pattern": r"(powershell|cmd|wscript|cscript)\\.exe.*\\-enc(odedcommand)?",
                "field": "command_line",
                "description": "Suspicious command line with encoded command"
            }
        ]
    )
    
    # Add the rule to the engine
    engine.rules[rule.id] = rule
    
    # Create a test event
    test_event = {
        "event_id": "12345",
        "event_type": "process_start",
        "timestamp": datetime.utcnow().isoformat(),
        "endpoint_id": "test-endpoint-001",
        "process_name": "powershell.exe",
        "command_line": "powershell -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAG4AbwB0AGUAcABhAGQA",
        "user": "DOMAIN\\attacker"
    }
    
    print("Testing event:")
    print(json.dumps(test_event, indent=2))
    
    # Process the event
    matches = engine.process_event(test_event)
    
    print("\nDetection results:")
    print(json.dumps(matches, indent=2))

def demo_response_engine():
    """Demonstrate the response engine with sample detections."""
    from src.edr.response import ResponseEngine
    
    print("\n=== Response Engine Demo ===\n")
    
    # Create a response engine
    engine = ResponseEngine()
    
    # Create a test detection
    test_detection = {
        "rule_id": "suspicious_process_001",
        "rule_name": "Suspicious Process Execution",
        "severity": "high",
        "timestamp": datetime.utcnow().isoformat(),
        "event": {
            "event_type": "process_start",
            "pid": 1234,
            "process_name": "malware.exe",
            "command_line": "malware.exe --steal-data",
            "user": "SYSTEM"
        }
    }
    
    print("Processing detection:")
    print(json.dumps(test_detection, indent=2))
    
    # Process the detection
    results = engine.process_detection(test_detection)
    
    print("\nResponse results:")
    print(json.dumps(results, indent=2))

def main():
    """Run all demos."""
    print("=== EDR System Demo ===\n")
    
    # Run detection engine demo
    demo_detection_engine()
    
    # Run response engine demo
    demo_response_engine()
    
    print("\n=== Demo Complete ===")

if __name__ == "__main__":
    main()
