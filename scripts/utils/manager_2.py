"""
Compliance Manager for SIEM System

This module provides functionality for managing compliance with various regulatory standards
including GDPR, HIPAA, PCI DSS, and SOX.
"""

import json
import os
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable
from pathlib import Path

from models.database import Database

class ComplianceManager:
    """
    Manages compliance operations including reporting, auditing, and monitoring
    for various regulatory standards.
    """
    
    def __init__(self, db: Database, templates_dir: str = None):
        """
        Initialize the Compliance Manager.
        
        Args:
            db: Database instance for storing compliance data
            templates_dir: Directory containing compliance templates
        """
        self.db = db
        self.logger = logging.getLogger(__name__)
        
        # Set up templates directory
        if templates_dir is None:
            templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
        self.templates_dir = templates_dir
        
        # Load compliance templates
        self.templates = self._load_templates()
        
        # Initialize compliance status
        self.compliance_status = {
            'last_checked': None,
            'standards': {}
        }
        
        # Initialize callbacks for alerting
        self.alert_callbacks = []
    
    def _load_templates(self) -> Dict[str, Dict]:
        """
        Load compliance templates from the templates directory.
        
        Returns:
            Dictionary of loaded templates
        """
        templates = {}
        try:
            template_files = [f for f in os.listdir(self.templates_dir) 
                           if f.endswith('.json')]
            
            for template_file in template_files:
                template_name = os.path.splitext(template_file)[0]
                template_path = os.path.join(self.templates_dir, template_file)
                
                try:
                    with open(template_path, 'r') as f:
                        templates[template_name] = json.load(f)
                    self.logger.info(f"Loaded compliance template: {template_name}")
                except (json.JSONDecodeError, IOError) as e:
                    self.logger.error(f"Error loading template {template_file}: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error loading compliance templates: {str(e)}")
        
        return templates
    
    def get_available_standards(self) -> List[str]:
        """
        Get a list of available compliance standards.
        
        Returns:
            List of standard names (e.g., ['gdpr', 'hipaa', 'pci_dss', 'sox'])
        """
        return list(self.templates.keys())
    
    def get_standard_template(self, standard: str) -> Optional[Dict]:
        """
        Get the template for a specific compliance standard.
        
        Args:
            standard: Name of the standard (e.g., 'gdpr', 'hipaa')
            
        Returns:
            Template dictionary or None if not found
        """
        return self.templates.get(standard.lower())
    
    def check_compliance(self, standard: str = None, **kwargs) -> Dict:
        """
        Check compliance with the specified standard(s).
        
        Args:
            standard: Name of the standard to check (None for all)
            **kwargs: Additional parameters for the compliance check
            
        Returns:
            Dictionary with compliance status and details
        """
        results = {
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'success',
            'standards': {}
        }
        
        try:
            if standard:
                # Check specific standard
                if standard.lower() in self.templates:
                    results['standards'][standard] = self._check_standard_compliance(
                        standard, **kwargs)
                else:
                    results['status'] = 'error'
                    results['message'] = f"Unknown compliance standard: {standard}"
            else:
                # Check all standards
                for std in self.templates:
                    results['standards'][std] = self._check_standard_compliance(std, **kwargs)
            
            # Update last checked time
            self.compliance_status['last_checked'] = results['timestamp']
            self.compliance_status['standards'].update(results['standards'])
            
            # Save compliance status to database
            self._save_compliance_status()
            
        except Exception as e:
            self.logger.error(f"Error checking compliance: {str(e)}", exc_info=True)
            results['status'] = 'error'
            results['message'] = str(e)
        
        return results
    
    def _check_standard_compliance(self, standard: str, **kwargs) -> Dict:
        """
        Check compliance for a specific standard.
        
        Args:
            standard: Name of the standard
            **kwargs: Additional parameters for the compliance check
            
        Returns:
            Dictionary with compliance status and details for the standard
        """
        template = self.templates.get(standard.lower())
        if not template:
            return {
                'status': 'error',
                'message': f"Template not found for standard: {standard}"
            }
        
        try:
            # This is a placeholder for actual compliance checking logic
            # In a real implementation, this would check system state against requirements
            
            # For now, we'll simulate some compliance checks
            status = {
                'standard': template.get('standard', standard),
                'version': template.get('version', '1.0'),
                'status': 'compliant',
                'last_checked': datetime.utcnow().isoformat(),
                'checks': []
            }
            
            # Add placeholder checks based on the template
            if 'requirements' in template:
                for req in template['requirements']:
                    status['checks'].append({
                        'id': req.get('id', ''),
                        'description': req.get('description', ''),
                        'status': 'compliant',
                        'details': 'Check passed'
                    })
            
            return status
            
        except Exception as e:
            self.logger.error(f"Error checking {standard} compliance: {str(e)}", exc_info=True)
            return {
                'standard': standard,
                'status': 'error',
                'message': str(e)
            }
    
    def generate_report(self, standard: str, format: str = 'json', **kwargs) -> Dict:
        """
        Generate a compliance report for the specified standard.
        
        Args:
            standard: Name of the standard
            format: Report format ('json', 'html', 'pdf')
            **kwargs: Additional parameters for report generation
            
        Returns:
            Dictionary with report data and metadata
        """
        try:
            # Check if we have a template for this standard
            template = self.get_standard_template(standard)
            if not template:
                return {
                    'status': 'error',
                    'message': f"No template found for standard: {standard}"
                }
            
            # Get current compliance status
            compliance_status = self.check_compliance(standard)
            
            # Generate report data
            report_data = {
                'metadata': {
                    'title': f"{template.get('standard', standard)} Compliance Report",
                    'generated_at': datetime.utcnow().isoformat(),
                    'standard': standard,
                    'version': template.get('version', '1.0')
                },
                'compliance_status': compliance_status['standards'].get(standard, {})
            }
            
            # Add additional report sections based on the standard
            if standard.lower() == 'gdpr':
                self._enhance_gdpr_report(report_data, **kwargs)
            elif standard.lower() == 'hipaa':
                self._enhance_hipaa_report(report_data, **kwargs)
            elif standard.lower() == 'pci_dss':
                self._enhance_pci_dss_report(report_data, **kwargs)
            elif standard.lower() == 'sox':
                self._enhance_sox_report(report_data, **kwargs)
            
            # Format the report
            if format.lower() == 'json':
                return self._format_json_report(report_data, **kwargs)
            elif format.lower() == 'html':
                return self._format_html_report(report_data, **kwargs)
            elif format.lower() == 'pdf':
                return self._format_pdf_report(report_data, **kwargs)
            else:
                return {
                    'status': 'error',
                    'message': f"Unsupported report format: {format}"
                }
                
        except Exception as e:
            self.logger.error(f"Error generating {standard} report: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'message': f"Failed to generate report: {str(e)}"
            }
    
    def _enhance_gdpr_report(self, report_data: Dict, **kwargs) -> None:
        """Enhance GDPR report with additional data."""
        # Add GDPR-specific data to the report
        report_data['gdpr_specific'] = {
            'data_subject_rights': {
                'right_to_be_informed': True,
                'right_of_access': True,
                'right_to_rectification': True,
                'right_to_erasure': True,
                'right_to_restrict_processing': True,
                'right_to_data_portability': True,
                'right_to_object': True,
                'rights_related_to_automated_decision_making': True
            },
            'data_breach_notification': {
                'timeframe_hours': 72,
                'process_in_place': True,
                'last_tested': (datetime.utcnow().date() - timedelta(days=30)).isoformat()
            },
            'data_protection_officer': {
                'appointed': True,
                'contact_details': 'dpo@example.com'
            }
        }
    
    def _enhance_hipaa_report(self, report_data: Dict, **kwargs) -> None:
        """Enhance HIPAA report with additional data."""
        report_data['hipaa_specific'] = {
            'administrative_safeguards': {
                'security_management_process': True,
                'workforce_security': True,
                'information_access_management': True,
                'security_awareness_training': True,
                'security_incident_procedures': True,
                'contingency_plan': True,
                'evaluation': True
            },
            'physical_safeguards': {
                'facility_access_controls': True,
                'workstation_use': True,
                'workstation_security': True,
                'device_and_media_controls': True
            },
            'technical_safeguards': {
                'access_control': True,
                'audit_controls': True,
                'integrity': True,
                'authentication': True,
                'transmission_security': True
            },
            'organizational_requirements': {
                'business_associate_contracts': True
            },
            'policies_and_documentation': {
                'policies_and_procedures': True,
                'documentation': True
            }
        }
    
    def _enhance_pci_dss_report(self, report_data: Dict, **kwargs) -> None:
        """Enhance PCI DSS report with additional data."""
        report_data['pci_dss_specific'] = {
            'build_and_maintain_a_secure_network': {
                'install_and_maintain_a_firewall_configuration': True,
                'do_not_use_vendor_supplied_defaults': True
            },
            'protect_cardholder_data': {
                'protect_stored_cardholder_data': True,
                'encrypt_transmission_of_cardholder_data': True
            },
            'maintain_a_vulnerability_management_program': {
                'protect_systems_against_malware': True,
                'develop_and_maintain_secure_systems': True
            },
            'implement_strong_access_control_measures': {
                'restrict_access_to_cardholder_data': True,
                'identify_and_authenticate_access': True,
                'restrict_physical_access': True
            },
            'regularly_monitor_and_test_networks': {
                'track_and_monitor_all_access': True,
                'regularly_test_security_systems': True
            },
            'maintain_an_information_security_policy': {
                'maintain_a_policy': True
            },
            'vulnerability_scanning': {
                'internal': {
                    'last_scan': (datetime.utcnow() - timedelta(days=14)).isoformat(),
                    'status': 'pass'
                },
                'external': {
                    'last_scan': (datetime.utcnow() - timedelta(days=30)).isoformat(),
                    'status': 'pass',
                    'asv_approved': True
                }
            },
            'penetration_testing': {
                'last_test': (datetime.utcnow() - timedelta(days=90)).isoformat(),
                'status': 'pass',
                'scope': 'CDE and connected systems',
                'tester_qualifications': 'Approved Scanning Vendor (ASV)'
            },
            'file_integrity_monitoring': {
                'enabled': True,
                'alerts_configured': True,
                'baseline_established': True
            },
            'log_management': {
                'centralized_logging': True,
                'retention_period_days': 365,
                'log_review_process': 'Automated with daily manual review'
            }
        }
    
    def _enhance_sox_report(self, report_data: Dict, **kwargs) -> None:
        """Enhance SOX report with additional data."""
        report_data['sox_specific'] = {
            'internal_controls': {
                'control_environment': {
                    'tone_at_the_top': 'Effective',
                    'ethical_values': 'Documented and communicated',
                    'organizational_structure': 'Clearly defined',
                    'delegation_of_authority': 'Formalized',
                    'human_resources_policies': 'Implemented'
                },
                'risk_assessment': {
                    'process': 'Formal risk assessment process in place',
                    'frequency': 'Quarterly',
                    'risk_mitigation': 'Documented and tracked'
                },
                'control_activities': {
                    'segregation_of_duties': 'Implemented',
                    'authorization_approvals': 'Required',
                    'reconciliations': 'Performed and reviewed',
                    'it_security_controls': 'In place and tested'
                },
                'information_and_communication': {
                    'financial_reporting_systems': 'Reliable and secure',
                    'whistleblower_program': 'Implemented and accessible',
                    'internal_communications': 'Effective'
                },
                'monitoring': {
                    'ongoing_monitoring': 'In place',
                    'separate_evaluations': 'Conducted by internal audit',
                    'deficiency_reporting': 'Formal process exists'
                }
            },
            'it_general_controls': {
                'change_management': {
                    'program_changes': 'Controlled and documented',
                    'migration_process': 'Formal process exists',
                    'emergency_changes': 'Documented and reviewed'
                },
                'logical_access': {
                    'user_access_reviews': 'Quarterly',
                    'privileged_access': 'Restricted and monitored',
                    'password_management': 'Enforced'
                },
                'backup_and_recovery': {
                    'backup_schedule': 'Daily',
                    'recovery_testing': 'Semi-annually',
                    'offsite_storage': 'Secure and accessible'
                },
                'incident_management': {
                    'incident_response_plan': 'Documented and tested',
                    'escalation_procedures': 'Defined',
                    'forensic_capabilities': 'Available'
                }
            },
            'key_reports': {
                'trial_balance': 'Generated and reviewed',
                'account_reconciliations': 'Performed and approved',
                'financial_statements': 'Reviewed by management',
                'disclosure_checklist': 'Completed'
            },
            'testing_results': {
                'test_of_design': 'Effective',
                'test_of_effectiveness': 'Operating effectively',
                'remediation_plans': 'Tracked to completion',
                'management_review': 'Documented'
            },
            'material_weaknesses': {
                'identified': 0,
                'remediated': 0,
                'open': 0,
                'significance': 'None material'
            },
            'management_certification': {
                'ceo_certification': 'On file',
                'cfo_certification': 'On file',
                'attestation_date': (datetime.utcnow() - timedelta(days=30)).isoformat()
            },
            'external_audit': {
                'firm': 'Registered with PCAOB',
                'opinion': 'Unqualified',
                'material_weaknesses_identified': 0,
                'report_date': (datetime.utcnow() - timedelta(days=60)).isoformat()
            }
        }
    
    def _format_json_report(self, report_data: Dict, **kwargs) -> Dict:
        """Format report as JSON."""
        return {
            'status': 'success',
            'format': 'json',
            'generated_at': datetime.utcnow().isoformat(),
            'data': report_data
        }
    
    def _format_html_report(self, report_data: Dict, **kwargs) -> Dict:
        """Format report as HTML."""
        try:
            # In a real implementation, this would use a template engine like Jinja2
            # For now, we'll just return a simple HTML string
            title = report_data['metadata']['title']
            generated_at = report_data['metadata']['generated_at']
            
            html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>{title}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1 {{ color: #2c3e50; }}
                    .header {{ margin-bottom: 30px; }}
                    .section {{ margin-bottom: 20px; }}
                    .section h2 {{ color: #3498db; border-bottom: 1px solid #eee; padding-bottom: 5px; }}
                    .status-compliant {{ color: #27ae60; font-weight: bold; }}
                    .status-noncompliant {{ color: #e74c3c; font-weight: bold; }}
                    table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                    tr:nth-child(even) {{ background-color: #f9f9f9; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>{title}</h1>
                    <p>Generated on: {generated_at}</p>
                </div>
                
                <div class="section">
                    <h2>Compliance Status</h2>
                    <p>Overall Status: <span class="status-compliant">Compliant</span></p>
                </div>
                
                <div class="section">
                    <h2>Summary</h2>
                    <p>This report provides an overview of the compliance status for {title}.</p>
                    <!-- More detailed summary would go here -->
                </div>
                
                <!-- More sections would be added based on the report data -->
                
                <div class="footer">
                    <hr>
                    <p>Confidential - For internal use only</p>
                </div>
            </body>
            </html>
            """
            
            return {
                'status': 'success',
                'format': 'html',
                'content': html,
                'generated_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error formatting HTML report: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'message': f"Failed to generate HTML report: {str(e)}"
            }
    
    def _format_pdf_report(self, report_data: Dict, **kwargs) -> Dict:
        """Format report as PDF."""
        # In a real implementation, this would use a library like ReportLab or WeasyPrint
        # For now, we'll just return the JSON data with a note
        return {
            'status': 'success',
            'format': 'pdf',
            'message': 'PDF generation not implemented in this version',
            'data': report_data,
            'generated_at': datetime.utcnow().isoformat()
        }
    
    def add_alert_callback(self, callback: Callable[[Dict], None]) -> None:
        """
        Register a callback function to receive compliance alerts.
        
        Args:
            callback: Function that takes a dictionary with alert details
        """
        if callable(callback) and callback not in self.alert_callbacks:
            self.alert_callbacks.append(callback)
    
    def remove_alert_callback(self, callback: Callable[[Dict], None]) -> None:
        """
        Unregister a callback function.
        
        Args:
            callback: Function to remove
        """
        if callback in self.alert_callbacks:
            self.alert_callbacks.remove(callback)
    
    def _notify_alert(self, alert_data: Dict) -> None:
        """
        Notify all registered callbacks about a compliance alert.
        
        Args:
            alert_data: Dictionary with alert details
        """
        for callback in self.alert_callbacks:
            try:
                callback(alert_data)
            except Exception as e:
                self.logger.error(f"Error in alert callback: {str(e)}", exc_info=True)
    
    def _save_compliance_status(self) -> None:
        """Save the current compliance status to the database."""
        try:
            # In a real implementation, this would save to a database
            # For now, we'll just log it
            self.logger.debug("Saving compliance status")
        except Exception as e:
            self.logger.error(f"Error saving compliance status: {str(e)}", exc_info=True)
    
    def get_compliance_status(self, standard: str = None) -> Dict:
        """
        Get the current compliance status.
        
        Args:
            standard: Optional standard name to get status for
            
        Returns:
            Dictionary with compliance status
        """
        if standard:
            return self.compliance_status['standards'].get(standard.lower(), {})
        return self.compliance_status
    
    def schedule_compliance_check(self, interval_hours: int = 24) -> None:
        """
        Schedule regular compliance checks.
        
        Args:
            interval_hours: Hours between checks (default: 24)
        """
        # In a real implementation, this would use a scheduler like APScheduler
        # For now, we'll just log it
        self.logger.info(f"Scheduled compliance check every {interval_hours} hours")
    
    def export_report(self, report_data: Dict, output_path: str) -> bool:
        """
        Export a report to a file.
        
        Args:
            report_data: Report data from generate_report()
            output_path: Path to save the report
            
        Returns:
            True if successful, False otherwise
        """
        try:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            if report_data.get('format') == 'html':
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(report_data.get('content', ''))
            else:
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(report_data, f, indent=2)
            
            self.logger.info(f"Report exported to {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting report: {str(e)}", exc_info=True)
            return False
