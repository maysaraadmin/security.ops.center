"""
Simple script to check if Sysmon events can be read.
"""
import sys
import os
import win32evtlog
import win32con

def check_sysmon_events():
    """Check if we can read Sysmon events."""
    print("Attempting to read Sysmon events...")
    
    try:
        # Try to open the Sysmon event log
        print("Opening Sysmon event log...")
        h = win32evtlog.OpenEventLog(None, "Microsoft-Windows-Sysmon/Operational")
        
        try:
            print("Reading events...")
            total = win32evtlog.GetNumberOfEventLogRecords(h)
            print(f"Total events in log: {total}")
            
            # Try to read the most recent 5 events
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(h, flags, 0)
            
            if not events:
                print("No events found in the log")
                return False
                
            print("\nFound events. Here are the most recent ones:")
            print("-" * 80)
            
            for i, event in enumerate(events[:5]):
                print(f"\nEvent {i+1}:")
                print(f"  Event ID: {event.EventID}")
                print(f"  Time: {event.TimeGenerated}")
                print(f"  Source: {event.SourceName}")
                print(f"  Computer: {event.ComputerName}")
                
                # Print string inserts if available
                if hasattr(event, 'StringInserts') and event.StringInserts:
                    print("  Details:")
                    for j, item in enumerate(event.StringInserts):
                        print(f"    {j}: {item}")
                
                print("-" * 80)
                
            return True
            
        finally:
            win32evtlog.CloseEventLog(h)
            
    except Exception as e:
        print(f"Error reading Sysmon events: {e}", file=sys.stderr)
        return False

if __name__ == "__main__":
    print("Sysmon Event Log Checker")
    print("=" * 40)
    
    if not check_sysmon_events():
        print("\nTroubleshooting steps:")
        print("1. Make sure Sysmon is installed")
        print("2. Run this script as Administrator")
        print("3. Check if the Sysmon service is running")
        print("4. Verify the event log exists: 'Microsoft-Windows-Sysmon/Operational'")
        sys.exit(1)
