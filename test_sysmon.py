"""
Test script to check Sysmon event log access.
Run this script as Administrator.
"""
import win32evtlog
import win32con
import winerror
import sys

def check_sysmon_log():
    """Check if the Sysmon log is accessible."""
    log_name = "Microsoft-Windows-Sysmon/Operational"
    print(f"Attempting to access Sysmon log: {log_name}")
    
    try:
        # Try to open the Sysmon log
        handle = win32evtlog.OpenEventLog(None, log_name)
        print("✓ Successfully opened Sysmon log")
        
        # Get number of records
        num_records = win32evtlog.GetNumberOfEventLogRecords(handle)
        print(f"✓ Found {num_records} records in Sysmon log")
        
        # Try to read some events
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(handle, flags, 0, 5)
        print(f"✓ Successfully read {len(events)} events")
        
        # Show event IDs of the first few events
        if events:
            print("\nFirst few event IDs:")
            for i, event in enumerate(events[:5], 1):
                print(f"  {i}. Event ID: {event.EventID} - {event.TimeGenerated}")
        
        win32evtlog.CloseEventLog(handle)
        return True
        
    except Exception as e:
        print(f"✗ Error accessing Sysmon log: {str(e)}")
        
        # Try to list available logs
        try:
            print("\nAvailable event logs:")
            logs = win32evtlog.EvtChannelEnum()
            sysmon_logs = [log for log in logs if 'sysmon' in log.lower()]
            
            if sysmon_logs:
                print("\nFound these Sysmon-related logs:")
                for log in sysmon_logs:
                    print(f"  - {log}")
                print("\nTry using one of these log names in the configuration.")
            else:
                print("\nNo Sysmon logs found. Is Sysmon installed?")
                
        except Exception as e2:
            print(f"Error listing available logs: {str(e2)}")
            
        return False

if __name__ == "__main__":
    print("=== Sysmon Log Checker ===")
    print("Note: This script must be run as Administrator")
    print("-" * 30)
    
    if not check_sysmon_log():
        print("\nTroubleshooting tips:")
        print("1. Run this script as Administrator")
        print("2. Ensure Sysmon is installed (https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)")
        print("3. Check if the Sysmon service is running (run 'services.msc' and look for 'Sysmon')")
        print("4. Verify the log name in the script matches your Sysmon configuration")
        
    input("\nPress Enter to exit...")
