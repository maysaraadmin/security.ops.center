"""
Compliance Reporting Module for SIEM.

This module handles the generation of compliance reports and audit logs.
"""
import os
import json
import csv
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import hashlib
import time
from pathlib import Path

# Third-party imports (would be added to requirements.txt)
# import pandas as pd
# from jinja2 import Environment, FileSystemLoader
# from weasyprint import HTML

logger = logging.getLogger(__name__)

class ReportFormat(Enum):
    """Supported report formats."""
    JSON = "json"
    CSV = "csv"
    HTML = "html"
    PDF = "pdf"

class ReportStatus(Enum):
    """Report generation status."""
    PENDING = "pending"
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"

@dataclass
class ReportTemplate:
    """Represents a report template."""
    id: str
    name: str
    description: str
    template_file: str
    format: ReportFormat
    parameters: Dict[str, Any] = field(default_factory=dict)
    schedule: Optional[str] = None  # cron format
    retention_days: int = 90
    columns: List[Dict[str, str]] = field(default_factory=list)
    filters: Dict[str, Any] = field(default_factory=dict)

@dataclass
class GeneratedReport:
    """Represents a generated report."""
    id: str
    template_id: str
    name: str
    format: ReportFormat
    status: ReportStatus
    generated_at: datetime
    generated_by: str
    parameters: Dict[str, Any]
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    error: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = asdict(self)
        result['format'] = self.format.value
        result['status'] = self.status.value
        result['generated_at'] = self.generated_at.isoformat()
        
        if self.start_time:
            result['start_time'] = self.start_time.isoformat()
        if self.end_time:
            result['end_time'] = self.end_time.isoformat()
            
        return result

class ReportGenerator:
    """Handles report generation and management."""
    
    def __init__(self, reports_dir: str, templates_dir: str):
        """Initialize the report generator.
        
        Args:
            reports_dir: Directory to store generated reports
            templates_dir: Directory containing report templates
        """
        self.reports_dir = Path(reports_dir)
        self.templates_dir = Path(templates_dir)
        self.templates: Dict[str, ReportTemplate] = {}
        
        # Create directories if they don't exist
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        
        # Load templates
        self._load_templates()
    
    def _load_templates(self) -> None:
        """Load report templates from the templates directory."""
        self.templates = {}
        
        for template_file in self.templates_dir.glob('*.json'):
            try:
                with open(template_file, 'r') as f:
                    template_data = json.load(f)
                    
                template = ReportTemplate(
                    id=template_data['id'],
                    name=template_data['name'],
                    description=template_data.get('description', ''),
                    template_file=template_data.get('template_file', ''),
                    format=ReportFormat(template_data.get('format', 'json')),
                    parameters=template_data.get('parameters', {}),
                    schedule=template_data.get('schedule'),
                    retention_days=template_data.get('retention_days', 90),
                    columns=template_data.get('columns', []),
                    filters=template_data.get('filters', {})
                )
                
                self.templates[template.id] = template
                logger.info(f"Loaded template: {template.name} ({template.id})")
                
            except Exception as e:
                logger.error(f"Error loading template {template_file}: {e}")
    
    def list_templates(self) -> List[Dict[str, Any]]:
        """List all available report templates."""
        return [
            {
                'id': t.id,
                'name': t.name,
                'description': t.description,
                'format': t.format.value,
                'parameters': t.parameters
            }
            for t in self.templates.values()
        ]
    
    def generate_report(
        self,
        template_id: str,
        output_format: Optional[Union[str, ReportFormat]] = None,
        parameters: Optional[Dict[str, Any]] = None,
        generated_by: str = "system",
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> GeneratedReport:
        """Generate a report using the specified template.
        
        Args:
            template_id: ID of the template to use
            output_format: Output format (defaults to template format)
            parameters: Template parameters
            generated_by: Username or system that generated the report
            start_time: Start time for report data
            end_time: End time for report data
            
        Returns:
            GeneratedReport object with report details
        """
        if template_id not in self.templates:
            raise ValueError(f"Template not found: {template_id}")
            
        template = self.templates[template_id]
        output_format = ReportFormat(output_format) if output_format else template.format
        
        # Set default time range if not specified
        now = datetime.utcnow()
        if not end_time:
            end_time = now
        if not start_time:
            start_time = end_time - timedelta(days=30)  # Default to 30 days
        
        # Create report metadata
        report_id = f"report_{int(time.time())}_{hashlib.md5(template_id.encode()).hexdigest()[:6]}"
        report_name = f"{template.name}_{end_time.strftime('%Y%m%d')}"
        
        report = GeneratedReport(
            id=report_id,
            template_id=template_id,
            name=report_name,
            format=output_format,
            status=ReportStatus.GENERATING,
            generated_at=now,
            generated_by=generated_by,
            parameters=parameters or {},
            start_time=start_time,
            end_time=end_time
        )
        
        try:
            # Generate the report in the background
            self._generate_report_async(report, template, parameters or {})
            return report
            
        except Exception as e:
            logger.error(f"Error generating report {report_id}: {e}", exc_info=True)
            report.status = ReportStatus.FAILED
            report.error = str(e)
            return report
    
    def _generate_report_async(
        self,
        report: GeneratedReport,
        template: ReportTemplate,
        parameters: Dict[str, Any]
    ) -> None:
        """Generate a report asynchronously."""
        try:
            # In a real implementation, this would run in a background task
            report_data = self._collect_report_data(template, parameters, report.start_time, report.end_time)
            
            # Generate the report file
            output_file = self.reports_dir / f"{report.id}.{report.format.value}"
            
            if report.format == ReportFormat.JSON:
                self._generate_json_report(report_data, output_file)
            elif report.format == ReportFormat.CSV:
                self._generate_csv_report(report_data, output_file, template)
            elif report.format == ReportFormat.HTML:
                self._generate_html_report(report_data, output_file, template)
            elif report.format == ReportFormat.PDF:
                self._generate_pdf_report(report_data, output_file, template)
            else:
                raise ValueError(f"Unsupported report format: {report.format}")
            
            # Update report metadata
            report.status = ReportStatus.COMPLETED
            report.file_path = str(output_file)
            report.file_size = output_file.stat().st_size
            
            # Save report metadata
            self._save_report_metadata(report)
            
        except Exception as e:
            logger.error(f"Error generating report {report.id}: {e}", exc_info=True)
            report.status = ReportStatus.FAILED
            report.error = str(e)
            self._save_report_metadata(report)
    
    def _collect_report_data(
        self,
        template: ReportTemplate,
        parameters: Dict[str, Any],
        start_time: datetime,
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """Collect data for the report.
        
        In a real implementation, this would query the appropriate data sources
        based on the template and parameters.
        """
        # This is a placeholder - would be replaced with actual data collection
        # For example, querying a database or SIEM for events
        return [
            {
                'timestamp': (end_time - timedelta(minutes=i)).isoformat(),
                'event_type': 'security_alert',
                'severity': ['low', 'medium', 'high', 'critical'][i % 4],
                'source_ip': f"192.168.1.{i % 255}",
                'description': f"Sample security event {i}"
            }
            for i in range(100)
        ]
    
    def _generate_json_report(
        self,
        data: List[Dict[str, Any]],
        output_file: Path
    ) -> None:
        """Generate a JSON report."""
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _generate_csv_report(
        self,
        data: List[Dict[str, Any]],
        output_file: Path,
        template: ReportTemplate
    ) -> None:
        """Generate a CSV report."""
        if not data:
            with open(output_file, 'w') as f:
                f.write("No data available\n")
            return
        
        # Use specified columns or all available fields
        columns = [col['field'] for col in template.columns] if template.columns else data[0].keys()
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=columns)
            writer.writeheader()
            
            for row in data:
                # Only include specified columns
                filtered_row = {k: row.get(k, '') for k in columns}
                writer.writerow(filtered_row)
    
    def _generate_html_report(
        self,
        data: List[Dict[str, Any]],
        output_file: Path,
        template: ReportTemplate
    ) -> None:
        """Generate an HTML report."""
        # In a real implementation, this would use a template engine like Jinja2
        # This is a simplified version
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{title}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
            </style>
        </head>
        <body>
            <h1>{title}</h1>
            <p>Generated on: {now}</p>
            <p>Time range: {start_time} to {end_time}</p>
            {table}
        </body>
        </html>
        """
        
        # Generate table rows
        if not data:
            table = "<p>No data available</p>"
        else:
            columns = [col['field'] for col in template.columns] if template.columns else data[0].keys()
            
            # Generate table header
            table = "<table>\n<thead>\n<tr>"
            for col in columns:
                table += f"<th>{col}</th>"
            table += "</tr>\n</thead>\n<tbody>\n"
            
            # Generate table rows
            for row in data:
                table += "<tr>"
                for col in columns:
                    table += f"<td>{row.get(col, '')}</td>"
                table += "</tr>\n"
            
            table += "</tbody>\n</table>"
        
        # Format the HTML
        html = html.format(
            title=template.name,
            now=datetime.utcnow().isoformat(),
            start_time=report.start_time.isoformat() if hasattr(report, 'start_time') else 'N/A',
            end_time=report.end_time.isoformat() if hasattr(report, 'end_time') else 'N/A',
            table=table
        )
        
        with open(output_file, 'w') as f:
            f.write(html)
    
    def _generate_pdf_report(
        self,
        data: List[Dict[str, Any]],
        output_file: Path,
        template: ReportTemplate
    ) -> None:
        """Generate a PDF report."""
        # In a real implementation, this would use WeasyPrint or similar
        # For now, just generate HTML and convert it to PDF if WeasyPrint is available
        html_file = output_file.with_suffix('.html')
        self._generate_html_report(data, html_file, template)
        
        try:
            from weasyprint import HTML
            HTML(str(html_file)).write_pdf(str(output_file))
            html_file.unlink()  # Remove temporary HTML file
        except ImportError:
            # Fall back to HTML if PDF generation is not available
            logger.warning("WeasyPrint not available, falling back to HTML")
            output_file.rename(html_file)
    
    def _save_report_metadata(self, report: GeneratedReport) -> None:
        """Save report metadata to a JSON file."""
        metadata_file = self.reports_dir / f"{report.id}.json"
        with open(metadata_file, 'w') as f:
            json.dump(report.to_dict(), f, indent=2, default=str)
    
    def list_reports(
        self,
        template_id: Optional[str] = None,
        status: Optional[ReportStatus] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """List generated reports with optional filtering."""
        reports = []
        
        for metadata_file in self.reports_dir.glob('*.json'):
            try:
                with open(metadata_file, 'r') as f:
                    report_data = json.load(f)
                
                # Apply filters
                if template_id and report_data.get('template_id') != template_id:
                    continue
                    
                if status and report_data.get('status') != status.value:
                    continue
                    
                report_time = datetime.fromisoformat(report_data['generated_at'])
                if start_date and report_time < start_date:
                    continue
                    
                if end_date and report_time > end_date:
                    continue
                
                reports.append(report_data)
                
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"Error loading report metadata {metadata_file}: {e}")
        
        # Sort by generation time (newest first)
        return sorted(reports, key=lambda x: x['generated_at'], reverse=True)
    
    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific report by ID."""
        metadata_file = self.reports_dir / f"{report_id}.json"
        
        if not metadata_file.exists():
            return None
        
        try:
            with open(metadata_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading report {report_id}: {e}")
            return None
    
    def cleanup_old_reports(self) -> int:
        """Clean up old reports based on retention policy.
        
        Returns:
            Number of reports deleted
        """
        deleted = 0
        now = datetime.utcnow()
        
        for metadata_file in self.reports_dir.glob('*.json'):
            try:
                with open(metadata_file, 'r') as f:
                    report_data = json.load(f)
                
                # Get template retention period
                template_id = report_data.get('template_id')
                retention_days = 90  # Default retention
                
                if template_id in self.templates:
                    retention_days = self.templates[template_id].retention_days
                
                # Check if report is older than retention period
                report_time = datetime.fromisoformat(report_data['generated_at'])
                if (now - report_time).days > retention_days:
                    # Delete report file if it exists
                    report_file = self.reports_dir / f"{report_data['id']}.{report_data.get('format', 'pdf')}"
                    if report_file.exists():
                        report_file.unlink()
                    
                    # Delete metadata file
                    metadata_file.unlink()
                    deleted += 1
                    
            except (json.JSONDecodeError, KeyError, IOError) as e:
                logger.warning(f"Error processing report {metadata_file}: {e}")
        
        return deleted

# Example usage
if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Create a report generator
    reports_dir = "./reports"
    templates_dir = "./templates"
    
    # Create directories if they don't exist
    os.makedirs(reports_dir, exist_ok=True)
    os.makedirs(templates_dir, exist_ok=True)
    
    # Create a sample template if it doesn't exist
    sample_template = {
        "id": "security_events",
        "name": "Security Events Report",
        "description": "Report of security events and alerts",
        "format": "pdf",
        "retention_days": 90,
        "columns": [
            {"field": "timestamp", "title": "Timestamp"},
            {"field": "event_type", "title": "Event Type"},
            {"field": "severity", "title": "Severity"},
            {"field": "source_ip", "title": "Source IP"},
            {"field": "description", "title": "Description"}
        ],
        "filters": {
            "severity": ["high", "critical"]
        }
    }
    
    template_file = os.path.join(templates_dir, "security_events.json")
    if not os.path.exists(template_file):
        with open(template_file, 'w') as f:
            json.dump(sample_template, f, indent=2)
    
    # Initialize the report generator
    generator = ReportGenerator(reports_dir, templates_dir)
    
    # List available templates
    print("Available templates:")
    for template in generator.list_templates():
        print(f"- {template['name']} ({template['id']})")
    
    # Generate a report
    print("\nGenerating report...")
    report = generator.generate_report(
        template_id="security_events",
        generated_by="example_user",
        start_time=datetime.utcnow() - timedelta(days=7),
        end_time=datetime.utcnow()
    )
    
    print(f"Report generated with ID: {report.id}")
    print(f"Status: {report.status.value}")
    
    if report.status == ReportStatus.COMPLETED:
        print(f"Report saved to: {report.file_path}")
    elif report.error:
        print(f"Error: {report.error}")
