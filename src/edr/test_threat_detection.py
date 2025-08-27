"""
Test script for Threat Detection module.
"""

import time
import json
from threat_detection import ThreatDetector

def alert_callback(alert):
    """Handle alert callbacks from the threat detector."""
    print("\n=== THREAT DETECTED ===")
    print(f"Type: {alert['type']}")
    print(f"Severity: {alert['severity']}")
    print(f"Message: {alert['message']}")
    if 'process' in alert:
        print("Process Info:")
        print(f"  PID: {alert['process'].get('pid')}")
        print(f"  Name: {alert['process'].get('name')}")
        cmdline = alert['process'].get('cmdline', [])
        print(f"  Cmdline: {' '.join(cmdline) if isinstance(cmdline, list) else cmdline}")
    if 'connection' in alert:
        print("Connection Info:")
        print(f"  Local: {alert['connection'].get('local')}")
        print(f"  Remote: {alert['connection'].get('remote')}")
    print("====================\n")

def create_test_files():
    """Create test files for detection."""
    # Create a test threat intel file
    threat_intel = {
        "hashes": [
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # Empty file hash
        ],
        "ips": ["1.2.3.4", "5.6.7.8"],
        "domains": ["malicious.com", "evil.org"]
    }
    
    with open('threat_intel.json', 'w') as f:
        json.dump(threat_intel, f)
    
    # Create a test detection rules file
    detection_rules = {
        "suspicious_processes": [
            "test_malware.exe",
            "suspicious_script.py",
            "powershell -nop -exec bypass"
        ],
        "suspicious_paths": [
            "C:\\temp\\",
            "%APPDATA%\\malware"
        ]
    }
    
    with open('detection_rules.json', 'w') as f:
        json.dump(detection_rules, f)

def main():
    print("Setting up test environment...")
    create_test_files()
    
    print("\nStarting threat detector...")
    try:
        detector = ThreatDetector(alert_callback)
        detector.start()
        
        print("\nThreat detector running. Press Ctrl+C to stop.")
        print("Monitoring for threats...\n")
        
        # Simulate some suspicious activity
        print("Simulating suspicious activity in 5 seconds...")
        time.sleep(5)
        
        # Test with a known malicious IP
        print("\nSimulating connection to known malicious IP...")
        alert_callback({
            'timestamp': time.time(),
            'type': 'malicious_connection',
            'severity': 'high',
            'message': 'Connection to known malicious IP',
            'connection': {
                'local': '192.168.1.100:54321',
                'remote': '1.2.3.4:80',
                'status': 'ESTABLISHED'
            }
        })
        
        print("\nMonitoring for real threats...")
        print("Press Ctrl+C to stop the detector.\n")
        
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping threat detector...")
        if 'detector' in locals():
            detector.stop()
        print("Done.")
    except Exception as e:
        print(f"Error: {e}")
        if 'detector' in locals():
            detector.stop()

if __name__ == "__main__":
    main()
