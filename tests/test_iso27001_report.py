"""
Tests for ISO 27001 compliance reporting.
"""
import os
import sys
import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from siem.compliance.reports import ISO27001Report

def test_iso27001_report_initialization():
    """Test initialization of ISO27001Report."""
    config = {
        'id': 'test_iso27001',
        'name': 'Test ISO 27001 Report',
        'output_dir': '/tmp/iso27001_reports',
        'audit_config': {
            'log_dir': '/tmp/audit_logs'
        }
    }
    
    report = ISO27001Report(config)
    
    assert report.report_id == 'test_iso27001'
    assert report.name == 'Test ISO 27001 Report'
    assert str(report.output_dir) == '/tmp/iso27001_reports'

@patch('siem.compliance.reports.ISO27001Report._query_security_events')
@patch('siem.compliance.reports.ISO27001Report._query_access_events')
@patch('siem.compliance.reports.ISO27001Report._query_risk_assessment_events')
@patch('siem.compliance.reports.ISO27001Report.save_report')
def test_generate_report(mock_save, mock_risk_events, mock_access_events, mock_security_events):
    """Test report generation with mock data."""
    # Setup test data
    mock_security_events.return_value = [
        {'id': 1, 'type': 'firewall', 'severity': 'high'},
        {'id': 2, 'type': 'ids', 'severity': 'medium'}
    ]
    
    mock_access_events.return_value = [
        {'user': 'user1', 'status': 'success'},
        {'user': 'user2', 'status': 'failure'},
        {'user': 'user1', 'status': 'success'}
    ]
    
    mock_risk_events.return_value = [
        {'id': 'R1', 'severity': 'high', 'status': 'open'},
        {'id': 'R2', 'severity': 'medium', 'status': 'mitigated'},
        {'id': 'R3', 'severity': 'low', 'status': 'accepted'}
    ]
    
    # Initialize and generate report
    report = ISO27001Report()
    start_time = datetime(2023, 1, 1)
    end_time = datetime(2023, 1, 31)
    result = report.generate(start_time, end_time)
    
    # Verify the report structure
    assert result['report_id'] == report.report_id
    assert result['standard'] == 'ISO/IEC 27001:2022'
    assert len(result['sections']) == 4  # Should have 4 sections
    
    # Verify save was called
    assert mock_save.called
    
    # Verify access control summary
    access_section = next(s for s in result['sections'] if s['section'] == 'Access Control')
    assert access_section['total_events'] == 3
    assert access_section['unique_users'] == 2
    assert access_section['failed_attempts'] == 1
    
    # Verify risk assessment summary
    risk_section = next(s for s in result['sections'] if s['section'] == 'Risk Assessment')
    assert risk_section['total_risks_identified'] == 3
    assert risk_section['risks_by_severity'] == {
        'high': 1,
        'medium': 1,
        'low': 1
    }

def test_generate_with_empty_data():
    """Test report generation with no data."""
    report = ISO27001Report()
    start_time = datetime(2023, 1, 1)
    end_time = datetime(2023, 1, 31)
    
    with patch.object(report, '_query_security_events', return_value=[]), \
         patch.object(report, '_query_access_events', return_value=[]), \
         patch.object(report, '_query_risk_assessment_events', return_value=[]):
        
        result = report.generate(start_time, end_time)
        
        # Verify the report structure is still valid with no data
        assert result['report_id'] == report.report_id
        assert len(result['sections']) == 4
        
        # Access control section should show zero counts
        access_section = next(s for s in result['sections'] if s['section'] == 'Access Control')
        assert access_section['total_events'] == 0
        assert access_section['unique_users'] == 0
        assert access_section['failed_attempts'] == 0

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
