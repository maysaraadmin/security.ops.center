"""
Compliance Templates Module for SIEM.

This module provides pre-defined templates for common compliance standards
including PCI DSS, HIPAA, GDPR, NIST, and ISO 27001.
"""
import os
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class ComplianceStandard(Enum):
    """Supported compliance standards."""
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    NIST_800_53 = "nist_800_53"
    ISO_27001 = "iso_27001"
    SOC2 = "soc2"
    CIS = "cis"
    FEDRAMP = "fedramp"

@dataclass
class ControlRequirement:
    """Represents a control requirement in a compliance standard."""
    id: str
    name: str
    description: str
    category: str
    severity: str = "medium"
    implementation_guidance: Optional[str] = None
    references: List[Dict[str, str]] = field(default_factory=list)
    related_controls: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

@dataclass
class ComplianceTemplate:
    """Represents a compliance template."""
    id: str
    name: str
    description: str
    standard: ComplianceStandard
    version: str
    controls: Dict[str, ControlRequirement]
    last_updated: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the template to a dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'standard': self.standard.value,
            'version': self.version,
            'last_updated': self.last_updated,
            'controls': {
                ctrl_id: {
                    'id': ctrl.id,
                    'name': ctrl.name,
                    'description': ctrl.description,
                    'category': ctrl.category,
                    'severity': ctrl.severity,
                    'implementation_guidance': ctrl.implementation_guidance,
                    'references': ctrl.references,
                    'related_controls': ctrl.related_controls,
                    'tags': ctrl.tags
                }
                for ctrl_id, ctrl in self.controls.items()
            }
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert the template to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)
    
    def save_to_file(self, directory: Union[str, Path]) -> Path:
        """Save the template to a file."""
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        
        filename = f"{self.standard.value}_{self.id}.json"
        filepath = directory / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(self.to_json())
        
        return filepath
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ComplianceTemplate':
        """Create a ComplianceTemplate from a dictionary."""
        controls = {
            ctrl_id: ControlRequirement(
                id=ctrl_data['id'],
                name=ctrl_data['name'],
                description=ctrl_data['description'],
                category=ctrl_data['category'],
                severity=ctrl_data.get('severity', 'medium'),
                implementation_guidance=ctrl_data.get('implementation_guidance'),
                references=ctrl_data.get('references', []),
                related_controls=ctrl_data.get('related_controls', []),
                tags=ctrl_data.get('tags', [])
            )
            for ctrl_id, ctrl_data in data['controls'].items()
        }
        
        return cls(
            id=data['id'],
            name=data['name'],
            description=data['description'],
            standard=ComplianceStandard(data['standard']),
            version=data['version'],
            controls=controls,
            last_updated=data.get('last_updated', datetime.utcnow().isoformat())
        )
    
    @classmethod
    def from_file(cls, filepath: Union[str, Path]) -> 'ComplianceTemplate':
        """Load a ComplianceTemplate from a JSON file."""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        return cls.from_dict(data)

class ComplianceTemplateManager:
    """Manages compliance templates and provides methods to work with them."""
    
    def __init__(self, templates_dir: Optional[Union[str, Path]] = None):
        """Initialize the template manager.
        
        Args:
            templates_dir: Directory containing template files. If None, uses default location.
        """
        if templates_dir is None:
            # Use default location in the same directory as this file
            self.templates_dir = Path(__file__).parent / "templates"
        else:
            self.templates_dir = Path(templates_dir)
        
        # Create the templates directory if it doesn't exist
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        
        # Cache for loaded templates
        self._templates: Dict[str, ComplianceTemplate] = {}
        
        # Load built-in templates
        self._load_builtin_templates()
    
    def _load_builtin_templates(self) -> None:
        """Load built-in compliance templates."""
        # PCI DSS Template
        pci_dss = self._create_pci_dss_template()
        self._templates[pci_dss.id] = pci_dss
        
        # HIPAA Template
        hipaa = self._create_hipaa_template()
        self._templates[hipaa.id] = hipaa
        
        # GDPR Template
        gdpr = self._create_gdpr_template()
        self._templates[gdpr.id] = gdpr
        
        # NIST 800-53 Template
        nist = self._create_nist_template()
        self._templates[nist.id] = nist
        
        # ISO 27001 Template
        iso27001 = self._create_iso27001_template()
        self._templates[iso27001.id] = iso27001
        
        # Save templates to disk
        self._save_templates()
    
    def _save_templates(self) -> None:
        """Save all templates to disk."""
        for template in self._templates.values():
            template.save_to_file(self.templates_dir)
    
    def _create_pci_dss_template(self) -> ComplianceTemplate:
        """Create a PCI DSS compliance template."""
        return ComplianceTemplate(
            id="pci_dss_v3_2_1",
            name="Payment Card Industry Data Security Standard (PCI DSS) v3.2.1",
            description="Security standard for organizations that handle credit card information.",
            standard=ComplianceStandard.PCI_DSS,
            version="3.2.1",
            controls={
                "pci_1": ControlRequirement(
                    id="pci_1",
                    name="Install and maintain a firewall configuration to protect cardholder data",
                    description="Firewall and router standards to protect cardholder data.",
                    category="Network Security",
                    severity="high",
                    implementation_guidance=(
                        "Establish firewall and router configuration standards that include:\n"
                        "- A formal process for approving and testing all network connections\n"
                        "- Configuration of firewalls to restrict connections between untrusted networks\n"
                        "- Restriction of inbound and outbound traffic to that necessary for the business"
                    ),
                    references=[
                        {"title": "PCI DSS v3.2.1 Requirements and Security Assessment Procedures", "url": "https://www.pcisecuritystandards.org/document_library"}
                    ],
                    related_controls=["pci_1.1", "pci_1.2", "pci_1.3"],
                    tags=["firewall", "network_security", "pci"]
                ),
                "pci_2": ControlRequirement(
                    id="pci_2",
                    name="Do not use vendor-supplied defaults for system passwords and other security parameters",
                    description="Secure system configuration management.",
                    category="System Hardening",
                    severity="high",
                    implementation_guidance=(
                        "- Change all vendor-supplied defaults before installing a system on the network\n"
                        "- Develop configuration standards for all system components\n"
                        "- Implement only one primary function per server"
                    ),
                    related_controls=["pci_2.1", "pci_2.2", "pci_2.3"],
                    tags=["hardening", "pci", "passwords"]
                ),
                # Additional controls would be added here
            }
        )
    
    def _create_hipaa_template(self) -> ComplianceTemplate:
        """Create a HIPAA compliance template."""
        return ComplianceTemplate(
            id="hipaa_security_rule",
            name="Health Insurance Portability and Accountability Act (HIPAA) Security Rule",
            description="Security standards for protecting electronic protected health information (ePHI).",
            standard=ComplianceStandard.HIPAA,
            version="1.0",
            controls={
                "hipaa_164_308": ControlRequirement(
                    id="hipaa_164_308",
                    name="Security Management Process",
                    description="Implement policies and procedures to prevent, detect, contain, and correct security violations.",
                    category="Administrative Safeguards",
                    severity="high",
                    implementation_guidance=(
                        "- Implement security management processes to reduce risks and vulnerabilities\n"
                        "- Conduct accurate and thorough risk assessments\n"
                        "- Implement security measures to reduce risks and vulnerabilities"
                    ),
                    related_controls=["hipaa_164_308_a1", "hipaa_164_308_a2", "hipaa_164_308_a3"],
                    tags=["hipaa", "security_management", "risk_assessment"]
                ),
                "hipaa_164_312": ControlRequirement(
                    id="hipaa_164_312",
                    name="Technical Safeguards",
                    description="Implement technical policies and procedures for electronic information systems that maintain ePHI.",
                    category="Technical Safeguards",
                    severity="high",
                    implementation_guidance=(
                        "- Implement access controls to allow access only to authorized persons or software programs\n"
                        "- Implement audit controls to record and examine activity in systems containing ePHI\n"
                        "- Implement integrity controls to ensure ePHI is not improperly altered or destroyed"
                    ),
                    related_controls=["hipaa_164_312_a1", "hipaa_164_312_b", "hipaa_164_312_c1"],
                    tags=["hipaa", "access_control", "audit"]
                )
                # Additional controls would be added here
            }
        )
    
    def _create_gdpr_template(self) -> ComplianceTemplate:
        """Create a GDPR compliance template."""
        return ComplianceTemplate(
            id="gdpr_2016_679",
            name="General Data Protection Regulation (GDPR) 2016/679",
            description="Regulation on data protection and privacy in the European Union and EEA.",
            standard=ComplianceStandard.GDPR,
            version="1.0",
            controls={
                "gdpr_art5": ControlRequirement(
                    id="gdpr_art5",
                    name="Principles relating to processing of personal data",
                    description="Personal data must be processed lawfully, fairly, and transparently.",
                    category="Data Protection Principles",
                    severity="high",
                    implementation_guidance=(
                        "- Process personal data lawfully, fairly, and in a transparent manner\n"
                        "- Collect data for specified, explicit, and legitimate purposes\n"
                        "- Ensure data is accurate and kept up to date"
                    ),
                    related_controls=["gdpr_art6", "gdpr_art7", "gdpr_art8"],
                    tags=["gdpr", "data_protection", "privacy"]
                ),
                "gdpr_art32": ControlRequirement(
                    id="gdpr_art32",
                    name="Security of processing",
                    description="Implement appropriate technical and organizational measures to ensure a level of security appropriate to the risk.",
                    category="Security of Processing",
                    severity="high",
                    implementation_guidance=(
                        "- Implement pseudonymization and encryption of personal data\n"
                        "- Ensure ongoing confidentiality, integrity, availability, and resilience of systems\n"
                        "- Implement processes for regular testing and evaluation of security measures"
                    ),
                    related_controls=["gdpr_art33", "gdpr_art34", "gdpr_art35"],
                    tags=["gdpr", "security", "data_protection"]
                )
                # Additional controls would be added here
            }
        )
    
    def _create_nist_template(self) -> ComplianceTemplate:
        """Create a NIST 800-53 compliance template."""
        return ComplianceTemplate(
            id="nist_800_53_rev5",
            name="NIST Special Publication 800-53 Revision 5",
            description="Security and privacy controls for federal information systems and organizations.",
            standard=ComplianceStandard.NIST_800_53,
            version="5.0",
            controls={
                "ac_1": ControlRequirement(
                    id="ac_1",
                    name="Access Control Policy and Procedures",
                    description="Develop, document, and disseminate an access control policy.",
                    category="Access Control",
                    severity="high",
                    implementation_guidance=(
                        "- Develop and document access control policy\n"
                        "- Define roles and responsibilities for policy implementation\n"
                        "- Review and update the policy at least annually"
                    ),
                    related_controls=["ac_2", "ac_3", "ac_4"],
                    tags=["nist", "access_control", "policy"]
                ),
                "ra_1": ControlRequirement(
                    id="ra_1",
                    name="Risk Assessment Policy and Procedures",
                    description="Develop, document, and disseminate a risk assessment policy.",
                    category="Risk Assessment",
                    severity="high",
                    implementation_guidance=(
                        "- Develop and document risk assessment policy\n"
                        "- Define roles and responsibilities for risk assessment\n"
                        "- Conduct risk assessments at least annually"
                    ),
                    related_controls=["ra_2", "ra_3", "ra_5"],
                    tags=["nist", "risk_assessment", "policy"]
                )
                # Additional controls would be added here
            }
        )
    
    def _create_iso27001_template(self) -> ComplianceTemplate:
        """Create an ISO 27001 compliance template."""
        return ComplianceTemplate(
            id="iso_iec_27001_2013",
            name="ISO/IEC 27001:2013 Information Security Management",
            description="International standard for information security management systems (ISMS).",
            standard=ComplianceStandard.ISO_27001,
            version="2013",
            controls={
                "a_6_1_1": ControlRequirement(
                    id="a_6_1.1",
                    name="Information security roles and responsibilities",
                    description="All information security responsibilities shall be defined and allocated.",
                    category="Organization of Information Security",
                    severity="medium",
                    implementation_guidance=(
                        "- Define and document information security roles and responsibilities\n"
                        "- Allocate responsibilities to appropriate individuals\n"
                        "- Ensure segregation of duties where appropriate"
                    ),
                    related_controls=["a_6.1.2", "a_6.1.3", "a_6.1.4"],
                    tags=["iso27001", "roles", "responsibilities"]
                ),
                "a_12_4_1": ControlRequirement(
                    id="a_12.4.1",
                    name="Event logging",
                    description="Event logs recording user activities, exceptions, faults and information security events shall be produced, kept, and regularly reviewed.",
                    category="Logging and Monitoring",
                    severity="high",
                    implementation_guidance=(
                        "- Implement logging for user activities and security events\n"
                        "- Protect log information from unauthorized access and modification\n"
                        "- Regularly review logs and take appropriate action"
                    ),
                    related_controls=["a_12.4.2", "a_12.4.3", "a_12.4.4"],
                    tags=["iso27001", "logging", "monitoring"]
                )
                # Additional controls would be added here
            }
        )
    
    def get_template(self, template_id: str) -> Optional[ComplianceTemplate]:
        """Get a compliance template by ID."""
        # Check if template is in cache
        if template_id in self._templates:
            return self._templates[template_id]
        
        # Try to load from file
        template_file = self.templates_dir / f"{template_id}.json"
        if template_file.exists():
            try:
                template = ComplianceTemplate.from_file(template_file)
                self._templates[template_id] = template
                return template
            except Exception as e:
                logger.error(f"Error loading template {template_id}: {e}")
                return None
        
        return None
    
    def list_templates(self, standard: Optional[Union[str, ComplianceStandard]] = None) -> List[Dict[str, Any]]:
        """List all available compliance templates.
        
        Args:
            standard: Optional standard to filter by
            
        Returns:
            List of template metadata dictionaries
        """
        # Convert standard to string if it's an enum
        if isinstance(standard, ComplianceStandard):
            standard = standard.value
        
        # Load all templates from disk if not already loaded
        for template_file in self.templates_dir.glob("*.json"):
            template_id = template_file.stem
            if template_id not in self._templates:
                try:
                    template = ComplianceTemplate.from_file(template_file)
                    self._templates[template_id] = template
                except Exception as e:
                    logger.error(f"Error loading template {template_id}: {e}")
        
        # Filter by standard if specified
        templates = self._templates.values()
        if standard:
            templates = [t for t in templates if t.standard.value == standard]
        
        # Return basic template information
        return [
            {
                'id': t.id,
                'name': t.name,
                'description': t.description,
                'standard': t.standard.value,
                'version': t.version,
                'last_updated': t.last_updated,
                'control_count': len(t.controls)
            }
            for t in templates
        ]
    
    def create_custom_template(self, template: ComplianceTemplate) -> bool:
        """Create or update a custom template.
        
        Args:
            template: The template to create or update
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Save the template to disk
            template.save_to_file(self.templates_dir)
            
            # Update the cache
            self._templates[template.id] = template
            
            return True
        except Exception as e:
            logger.error(f"Error saving template {template.id}: {e}")
            return False
    
    def delete_template(self, template_id: str) -> bool:
        """Delete a custom template.
        
        Args:
            template_id: ID of the template to delete
            
        Returns:
            True if successful, False otherwise
        """
        # Don't allow deletion of built-in templates
        if template_id in [t.id for t in [
            self._create_pci_dss_template(),
            self._create_hipaa_template(),
            self._create_gdpr_template(),
            self._create_nist_template(),
            self._create_iso27001_template()
        ]]:
            logger.warning(f"Cannot delete built-in template: {template_id}")
            return False
        
        # Remove from cache
        if template_id in self._templates:
            del self._templates[template_id]
        
        # Delete the file
        template_file = self.templates_dir / f"{template_id}.json"
        if template_file.exists():
            try:
                template_file.unlink()
                return True
            except Exception as e:
                logger.error(f"Error deleting template {template_id}: {e}")
                return False
        
        return True

# Global template manager instance
_template_manager = None

def get_template_manager() -> ComplianceTemplateManager:
    """Get the global template manager instance."""
    global _template_manager
    if _template_manager is None:
        _template_manager = ComplianceTemplateManager()
    return _template_manager

# Example usage
if __name__ == "__main__":
    import logging
    
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Get the template manager
    template_manager = get_template_manager()
    
    # List all available templates
    print("Available compliance templates:")
    for template in template_manager.list_templates():
        print(f"- {template['name']} ({template['id']}): {template['description']}")
    
    # Get a specific template
    pci_template = template_manager.get_template("pci_dss_v3_2_1")
    if pci_template:
        print(f"\nPCI DSS Template Controls (first 2 of {len(pci_template.controls)}):")
        for i, (ctrl_id, ctrl) in enumerate(pci_template.controls.items()):
            if i >= 2:
                break
            print(f"\n{ctrl_id}: {ctrl.name}")
            print(f"  {ctrl.description}")
            print(f"  Category: {ctrl.category}, Severity: {ctrl.severity}")
    
    # Create a custom template
    custom_template = ComplianceTemplate(
        id="custom_standard_v1",
        name="Custom Security Standard",
        description="A custom security standard for internal use.",
        standard=ComplianceStandard.CIS,
        version="1.0",
        controls={
            "custom_1": ControlRequirement(
                id="custom_1",
                name="Custom Control 1",
                description="This is a custom control.",
                category="Custom Category",
                severity="medium",
                tags=["custom", "example"]
            )
        }
    )
    
    if template_manager.create_custom_template(custom_template):
        print("\nCreated custom template successfully!")
    
    # List custom templates
    print("\nCustom templates:")
    for template in template_manager.list_templates(standard=ComplianceStandard.CIS):
        print(f"- {template['name']} ({template['id']})")
    
    # Clean up - delete the custom template
    template_manager.delete_template("custom_standard_v1")
