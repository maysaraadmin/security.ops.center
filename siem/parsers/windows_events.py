"""
Windows Event Log Parser and Normalizer

This module provides functions to parse and normalize Windows Event Log entries
into a common schema for the SIEM.
"""
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger('siem.parser.windows')

# Mapping of Windows Event IDs to normalized event types
EVENT_TYPE_MAPPING = {
    # Security Events
    '4624': 'authentication_success',
    '4625': 'authentication_failure',
    '4634': 'logoff',
    '4648': 'logon_attempt',
    '4663': 'file_access',
    '4688': 'process_creation',
    '4698': 'scheduled_task_created',
    '4702': 'scheduled_task_updated',
    '4720': 'user_account_created',
    '4722': 'user_account_enabled',
    '4724': 'password_reset_attempt',
    '4726': 'user_account_deleted',
    '4738': 'user_account_changed',
    '4740': 'user_account_locked_out',
    '4768': 'kerberos_auth_ticket_requested',
    '4769': 'kerberos_service_ticket_requested',
    '4776': 'ntlm_authentication',
    '5140': 'network_share_accessed',
    '5145': 'network_share_object_checked',
}

def parse_windows_event(event_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Parse a Windows Event Log entry into a normalized format.
    
    Args:
        event_data: Raw Windows Event Log entry as a dictionary
        
    Returns:
        Normalized event dictionary or None if parsing fails
    """
    try:
        system = event_data.get('System', {})
        event_id = str(system.get('EventID', {}).get('#text', '0'))
        
        # Basic event information
        normalized = {
            'timestamp': _parse_timestamp(system.get('TimeCreated', {}).get('@SystemTime')),
            'event_id': event_id,
            'source_name': 'windows',
            'event_type': EVENT_TYPE_MAPPING.get(event_id, 'unknown'),
            'severity': _map_severity(system.get('Level', '0')),
            'computer': system.get('Computer', '').split('.')[0],  # Remove domain if present
            'source': system.get('Provider', {}).get('@Name', ''),
            'log_name': system.get('Channel', ''),
            'raw_event': event_data  # Keep original event for reference
        }
        
        # Extract user information
        user_data = _extract_user_info(event_data)
        if user_data:
            normalized.update(user_data)
            
        # Extract network information if available
        network_data = _extract_network_info(event_data)
        if network_data:
            normalized.update(network_data)
            
        # Extract process information if available
        process_data = _extract_process_info(event_data)
        if process_data:
            normalized.update(process_data)
            
        # Extract additional event-specific data
        event_data = _extract_event_data(event_data)
        if event_data:
            normalized['event_data'] = event_data
            
        return normalized
        
    except Exception as e:
        logger.error(f"Error parsing Windows event: {e}", exc_info=True)
        return None

def _parse_timestamp(timestamp_str: str) -> str:
    """Convert Windows Event timestamp to ISO format."""
    if not timestamp_str:
        return datetime.utcnow().isoformat() + 'Z'
    try:
        # Handle different timestamp formats
        if timestamp_str.endswith('Z'):
            dt = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S.%fZ')
        else:
            dt = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S.%f')
        return dt.isoformat() + 'Z'
    except ValueError:
        return datetime.utcnow().isoformat() + 'Z'

def _map_severity(level: str) -> str:
    """Map Windows Event Level to standard severity."""
    level_map = {
        '1': 'critical',
        '2': 'error',
        '3': 'warning',
        '4': 'information',
        '5': 'verbose'
    }
    return level_map.get(level, 'information')

def _extract_user_info(event_data: Dict[str, Any]) -> Dict[str, str]:
    """Extract user-related information from event data."""
    result = {}
    
    # Check for user information in EventData
    event_data_section = event_data.get('EventData', {})
    if isinstance(event_data_section, dict):
        data = event_data_section.get('Data', [])
        if isinstance(data, list):
            for item in data:
                name = item.get('@Name', '').lower()
                value = str(item.get('#text', '')).strip()
                
                if name in ['targetusername', 'username'] and value and value != '-':
                    result['user'] = value
                elif name in ['targetdomain', 'domainname'] and value and value != '-':
                    result['domain'] = value
                elif name == 'logontype' and value:
                    result['logon_type'] = _map_logon_type(value)
                    
    # Fall back to Security section if available
    if 'user' not in result and 'Security' in event_data:
        security = event_data['Security']
        if '@UserID' in security:
            result['user'] = security['@UserID']
            
    return result

def _extract_network_info(event_data: Dict[str, Any]) -> Dict[str, str]:
    """Extract network-related information from event data."""
    result = {}
    
    event_data_section = event_data.get('EventData', {})
    if isinstance(event_data_section, dict):
        data = event_data_section.get('Data', [])
        if isinstance(data, list):
            for item in data:
                name = item.get('@Name', '').lower()
                value = str(item.get('#text', '')).strip()
                
                if name in ['sourceipaddress', 'ipaddress'] and value and value != '-':
                    result['source_ip'] = value
                elif name == 'sourceport' and value and value != '-':
                    result['source_port'] = value
                elif name in ['destinationipaddress', 'ipaddress'] and value and value != '-':
                    result['destination_ip'] = value
                elif name == 'destinationport' and value and value != '-':
                    result['destination_port'] = value
                
    return result

def _extract_process_info(event_data: Dict[str, Any]) -> Dict[str, str]:
    """Extract process-related information from event data."""
    result = {}
    
    event_data_section = event_data.get('EventData', {})
    if isinstance(event_data_section, dict):
        data = event_data_section.get('Data', [])
        if isinstance(data, list):
            for item in data:
                name = item.get('@Name', '').lower()
                value = str(item.get('#text', '')).strip()
                
                if name == 'processname' and value and value != '-':
                    result['process_path'] = value
                    result['process_name'] = value.split('\\')[-1]  # Extract just the executable name
                elif name == 'processid' and value and value != '-':
                    result['process_id'] = value
                elif name == 'parentprocessname' and value and value != '-':
                    result['parent_process'] = value
                    
    return result

def _extract_event_data(event_data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract additional event-specific data."""
    result = {}
    
    event_data_section = event_data.get('EventData', {})
    if isinstance(event_data_section, dict):
        data = event_data_section.get('Data', [])
        if isinstance(data, list):
            for item in data:
                name = item.get('@Name', '').lower()
                value = str(item.get('#text', '')).strip()
                
                if value and value != '-':
                    result[name] = value
                    
    return result

def _map_logon_type(logon_type: str) -> str:
    """Map Windows logon type to human-readable format."""
    logon_types = {
        '0': 'System',
        '2': 'Interactive',
        '3': 'Network',
        '4': 'Batch',
        '5': 'Service',
        '7': 'Unlock',
        '8': 'NetworkCleartext',
        '9': 'NewCredentials',
        '10': 'RemoteInteractive',
        '11': 'CachedInteractive'
    }
    return logon_types.get(logon_type, f'Unknown({logon_type})')

# Example usage
if __name__ == "__main__":
    # Sample Windows Event in JSON format
    sample_event = {
        "System": {
            "Provider": {"@Name": "Microsoft-Windows-Security-Auditing", "@Guid": "{54849625-5478-4994-A5BA-3E3B0328C30D}"},
            "EventID": 4624,
            "Version": 2,
            "Level": 0,
            "Task": 12544,
            "Opcode": 0,
            "Keywords": "0x8020000000000000",
            "TimeCreated": {"@SystemTime": "2023-01-01T12:00:00.0000000Z"},
            "EventRecordID": 12345,
            "Correlation": None,
            "Execution": {"@ProcessID": 1234, "@ThreadID": 5678},
            "Channel": "Security",
            "Computer": "WORKSTATION01",
            "Security": {"@UserID": "S-1-5-18"}
        },
        "EventData": {
            "Data": [
                {"@Name": "TargetUserSid", "#text": "S-1-5-21-1234567890-1234567890-1234567890-1001"},
                {"@Name": "TargetUserName", "#text": "johndoe"},
                {"@Name": "TargetDomainName", "#text": "CONTOSO"},
                {"@Name": "TargetLogonId", "#text": "0x12345678"},
                {"@Name": "LogonType", "#text": "2"},
                {"@Name": "LogonProcessName", "#text": "User32"},
                {"@Name": "AuthenticationPackageName", "#text": "Negotiate"},
                {"@Name": "WorkstationName", "#text": "WORKSTATION01"},
                {"@Name": "LogonGuid", "#text": "{12345678-1234-5678-9012-345678901234}"},
                {"@Name": "ProcessId", "#text": "0x123"},
                {"@Name": "ProcessName", "#text": "C:\\Windows\\System32\\winlogon.exe"},
                {"@Name": "IpAddress", "#text": "192.168.1.100"},
                {"@Name": "IpPort", "#text": "12345"}
            ]
        }
    }
    
    parsed = parse_windows_event(sample_event)
    print(json.dumps(parsed, indent=2))
