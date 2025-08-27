"""
Compliance Manager for scheduling and executing compliance reports.
"""
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Type, Optional, TypeVar
from pathlib import Path
import json

from .base import ComplianceReport, AuditLogger
from .reports import GDPRReport, HIPAAResponse, PCIDSSReport, SOXReport

# Type variable for ComplianceReport subclasses
ReportClass = TypeVar('ReportClass', bound=ComplianceReport)

class ComplianceManager:
    """Manages the scheduling and execution of compliance reports."""
    
    # Map of report types to their corresponding classes
    REPORT_TYPES = {
        'gdpr': GDPRReport,
        'hipaa': HIPAAResponse,
        'pcidss': PCIDSSReport,
        'sox': SOXReport
    }
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the compliance manager."""
        self.config = config or {}
        self.logger = logging.getLogger("siem.compliance.manager")
        
        # Store reports and their schedules
        self.reports: Dict[str, ComplianceReport] = {}
        self.schedules: Dict[str, Dict[str, Any]] = {}
        
        # Audit logger for tracking report generation
        self.audit_logger = AuditLogger(self.config.get('audit_config', {}))
        
        # Thread control
        self.stop_event = threading.Event()
        self.scheduler_thread: Optional[threading.Thread] = None
        
        # Load configured reports
        self._load_reports()
    
    def _load_reports(self) -> None:
        """Load reports from configuration."""
        reports_config = self.config.get('reports', [])
        
        for report_config in reports_config:
            try:
                report_type = report_config.get('type')
                report_id = report_config.get('id')
                
                if not report_type or not report_id:
                    self.logger.error("Report config missing required fields (type or id)")
                    continue
                
                # Get the report class
                report_class = self.REPORT_TYPES.get(report_type.lower())
                if not report_class:
                    self.logger.error(f"Unknown report type: {report_type}")
                    continue
                
                # Create the report instance
                report = report_class(report_config)
                self.reports[report_id] = report
                
                # Store the schedule if specified
                if 'schedule' in report_config:
                    self.schedules[report_id] = report_config['schedule']
                
                self.logger.info(f"Loaded report: {report_id} ({report_type})")
                
            except Exception as e:
                self.logger.error(f"Failed to load report {report_config.get('id')}: {e}")
    
    def start(self) -> None:
        """Start the compliance manager scheduler."""
        if self.scheduler_thread and self.scheduler_thread.is_alive():
            self.logger.warning("Compliance manager already running")
            return
        
        self.stop_event.clear()
        self.scheduler_thread = threading.Thread(
            target=self._scheduler_loop,
            daemon=True
        )
        self.scheduler_thread.start()
        self.logger.info("Compliance manager started")
    
    def stop(self) -> None:
        """Stop the compliance manager scheduler."""
        self.stop_event.set()
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        self.logger.info("Compliance manager stopped")
    
    def _scheduler_loop(self) -> None:
        """Main scheduler loop that runs in a background thread."""
        while not self.stop_event.is_set():
            try:
                now = datetime.utcnow()
                
                # Check each scheduled report
                for report_id, schedule in self.schedules.items():
                    if report_id not in self.reports:
                        continue
                    
                    # Check if it's time to run the report
                    if self._should_run_report(report_id, schedule, now):
                        self.logger.info(f"Scheduled run for report: {report_id}")
                        
                        # Calculate time range based on schedule
                        time_range = self._get_report_time_range(schedule, now)
                        
                        # Run the report in a separate thread
                        threading.Thread(
                            target=self._run_report_async,
                            args=(report_id, time_range['start'], time_range['end']),
                            daemon=True
                        ).start()
                
                # Sleep for a minute before checking again
                time.sleep(60)
                
            except Exception as e:
                self.logger.error(f"Error in scheduler loop: {e}", exc_info=True)
                time.sleep(60)  # Prevent tight loop on error
    
    def _should_run_report(
        self, 
        report_id: str, 
        schedule: Dict[str, Any], 
        now: datetime
    ) -> bool:
        """Check if a report should be run based on its schedule."""
        # Check if the report is enabled
        if not schedule.get('enabled', True):
            return False
        
        # Get the last run time from state
        last_run = self._get_report_state(report_id, 'last_run')
        
        # If never run, and schedule allows first run
        if not last_run and schedule.get('run_on_startup', False):
            return True
        
        # Check schedule based on frequency
        frequency = schedule.get('frequency', 'daily')
        
        if frequency == 'hourly':
            # Run at the top of every hour
            if not last_run or (now - last_run) >= timedelta(hours=1):
                return now.minute == 0  # Only run at the top of the hour
        
        elif frequency == 'daily':
            # Run once per day at the specified time
            if not last_run or (now.date() > last_run.date()):
                run_time = schedule.get('time', '00:00')
                run_hour, run_minute = map(int, run_time.split(':'))
                return now.hour == run_hour and now.minute == run_minute
        
        elif frequency == 'weekly':
            # Run once per week on the specified day and time
            if not last_run or (now.date() - last_run.date()) >= timedelta(days=7):
                run_day = schedule.get('day', 'monday')
                run_time = schedule.get('time', '00:00')
                run_hour, run_minute = map(int, run_time.split(':'))
                
                # Convert day name to number (0=Monday, 6=Sunday)
                day_map = {
                    'monday': 0, 'tuesday': 1, 'wednesday': 2, 'thursday': 3,
                    'friday': 4, 'saturday': 5, 'sunday': 6
                }
                target_weekday = day_map.get(run_day.lower(), 0)
                
                return (
                    now.weekday() == target_weekday and
                    now.hour == run_hour and
                    now.minute == run_minute
                )
        
        elif frequency == 'monthly':
            # Run once per month on the specified day and time
            if not last_run or (now.year > last_run.year) or (now.month > last_run.month):
                run_day = schedule.get('day', 1)  # Default to 1st of the month
                run_time = schedule.get('time', '00:00')
                run_hour, run_minute = map(int, run_time.split(':'))
                
                return (
                    now.day == run_day and
                    now.hour == run_hour and
                    now.minute == run_minute
                )
        
        return False
    
    def _get_report_time_range(
        self, 
        schedule: Dict[str, Any], 
        now: datetime
    ) -> Dict[str, datetime]:
        """Calculate the time range for a report based on its schedule."""
        frequency = schedule.get('frequency', 'daily')
        
        if frequency == 'hourly':
            end_time = now.replace(minute=0, second=0, microsecond=0)
            start_time = end_time - timedelta(hours=1)
        
        elif frequency == 'daily':
            end_time = now.replace(hour=0, minute=0, second=0, microsecond=0)
            start_time = end_time - timedelta(days=1)
        
        elif frequency == 'weekly':
            end_time = now.replace(hour=0, minute=0, second=0, microsecond=0)
            start_time = end_time - timedelta(weeks=1)
        
        elif frequency == 'monthly':
            # First day of current month at 00:00:00
            end_time = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            # First day of previous month
            if end_time.month == 1:
                start_time = end_time.replace(year=end_time.year-1, month=12)
            else:
                start_time = end_time.replace(month=end_time.month-1)
        
        else:
            # Default to last 24 hours
            end_time = now
            start_time = now - timedelta(days=1)
        
        return {
            'start': start_time,
            'end': end_time
        }
    
    def _run_report_async(
        self, 
        report_id: str, 
        start_time: datetime, 
        end_time: datetime
    ) -> None:
        """Run a report asynchronously and update its state."""
        try:
            if report_id not in self.reports:
                self.logger.error(f"Report not found: {report_id}")
                return
            
            # Log the report start
            self.audit_logger.log_event(
                event_type='report_start',
                actor='system',
                action='generate_report',
                target=report_id,
                details={
                    'start_time': start_time.isoformat(),
                    'end_time': end_time.isoformat()
                }
            )
            
            # Generate the report
            report = self.reports[report_id]
            report_path = report.generate(start_time, end_time)
            
            # Update the report state
            self._update_report_state(report_id, {
                'last_run': datetime.utcnow().isoformat(),
                'last_status': 'success',
                'last_output': report_path
            })
            
            # Log the successful completion
            self.audit_logger.log_event(
                event_type='report_complete',
                actor='system',
                action='generate_report',
                target=report_id,
                status='success',
                details={
                    'output_path': report_path,
                    'start_time': start_time.isoformat(),
                    'end_time': end_time.isoformat()
                }
            )
            
            self.logger.info(f"Generated report: {report_id} -> {report_path}")
            
        except Exception as e:
            self.logger.error(f"Error generating report {report_id}: {e}", exc_info=True)
            
            # Update the report state with error
            self._update_report_state(report_id, {
                'last_run': datetime.utcnow().isoformat(),
                'last_status': 'error',
                'last_error': str(e)
            })
            
            # Log the failure
            self.audit_logger.log_event(
                event_type='report_error',
                actor='system',
                action='generate_report',
                target=report_id,
                status='failure',
                details={
                    'error': str(e),
                    'start_time': start_time.isoformat() if 'start_time' in locals() else None,
                    'end_time': end_time.isoformat() if 'end_time' in locals() else None
                }
            )
    
    def _get_report_state(self, report_id: str, key: str = None) -> Any:
        """Get the state for a report."""
        state_file = Path(f"compliance_state_{report_id}.json")
        
        if not state_file.exists():
            return None
        
        try:
            with open(state_file, 'r') as f:
                state = json.load(f)
            
            if key:
                return state.get(key)
            return state
            
        except (IOError, json.JSONDecodeError) as e:
            self.logger.error(f"Error reading report state for {report_id}: {e}")
            return None
    
    def _update_report_state(self, report_id: str, updates: Dict[str, Any]) -> None:
        """Update the state for a report."""
        state_file = Path(f"compliance_state_{report_id}.json")
        state = self._get_report_state(report_id) or {}
        
        # Apply updates
        state.update(updates)
        
        # Save the updated state
        try:
            with open(state_file, 'w') as f:
                json.dump(state, f, indent=2)
        except IOError as e:
            self.logger.error(f"Error saving report state for {report_id}: {e}")
    
    def get_report_status(self, report_id: str = None) -> Dict[str, Any]:
        """Get status information for reports."""
        if report_id:
            if report_id not in self.reports:
                return {'error': f'Report not found: {report_id}'}
            
            state = self._get_report_state(report_id) or {}
            
            return {
                'report_id': report_id,
                'enabled': report_id in self.schedules,
                'last_run': state.get('last_run'),
                'last_status': state.get('last_status'),
                'last_output': state.get('last_output'),
                'next_run': self._get_next_run_time(report_id)
            }
        
        # Return status for all reports
        return {
            report_id: self.get_report_status(report_id)
            for report_id in self.reports
        }
    
    def _get_next_run_time(self, report_id: str) -> Optional[str]:
        """Calculate the next scheduled run time for a report."""
        if report_id not in self.schedules:
            return None
        
        schedule = self.schedules[report_id]
        if not schedule.get('enabled', True):
            return None
        
        now = datetime.utcnow()
        last_run = self._get_report_state(report_id, 'last_run')
        
        if not last_run:
            if schedule.get('run_on_startup', False):
                return now.isoformat()
            last_run = now
        
        frequency = schedule.get('frequency', 'daily')
        
        if frequency == 'hourly':
            next_run = last_run + timedelta(hours=1)
            next_run = next_run.replace(minute=0, second=0, microsecond=0)
        
        elif frequency == 'daily':
            run_time = schedule.get('time', '00:00')
            run_hour, run_minute = map(int, run_time.split(':'))
            
            next_run = last_run + timedelta(days=1)
            next_run = next_run.replace(
                hour=run_hour,
                minute=run_minute,
                second=0,
                microsecond=0
            )
        
        elif frequency == 'weekly':
            run_day = schedule.get('day', 'monday')
            run_time = schedule.get('time', '00:00')
            run_hour, run_minute = map(int, run_time.split(':'))
            
            # Convert day name to number (0=Monday, 6=Sunday)
            day_map = {
                'monday': 0, 'tuesday': 1, 'wednesday': 2, 'thursday': 3,
                'friday': 4, 'saturday': 5, 'sunday': 6
            }
            target_weekday = day_map.get(run_day.lower(), 0)
            
            next_run = last_run + timedelta(days=1)
            while next_run.weekday() != target_weekday:
                next_run += timedelta(days=1)
            
            next_run = next_run.replace(
                hour=run_hour,
                minute=run_minute,
                second=0,
                microsecond=0
            )
        
        elif frequency == 'monthly':
            run_day = schedule.get('day', 1)
            run_time = schedule.get('time', '00:00')
            run_hour, run_minute = map(int, run_time.split(':'))
            
            # Calculate next month
            if last_run.month == 12:
                next_month = last_run.replace(year=last_run.year+1, month=1)
            else:
                next_month = last_run.replace(month=last_run.month+1)
            
            # Set the day, handling months with fewer days
            try:
                next_run = next_month.replace(day=run_day)
            except ValueError:
                # If the day is invalid for the month (e.g., Feb 30), use the last day
                next_run = next_month.replace(day=1) + timedelta(days=32)
                next_run = next_run.replace(day=1) - timedelta(days=1)
            
            next_run = next_run.replace(
                hour=run_hour,
                minute=run_minute,
                second=0,
                microsecond=0
            )
        
        else:
            return None
        
        return next_run.isoformat() if next_run > now else None
    
    def run_report_now(
        self, 
        report_id: str,
        start_time: datetime = None,
        end_time: datetime = None
    ) -> Dict[str, Any]:
        """Run a report immediately with the specified time range."""
        if report_id not in self.reports:
            return {
                'success': False,
                'error': f'Report not found: {report_id}'
            }
        
        # Default to last 24 hours if no time range specified
        if not end_time:
            end_time = datetime.utcnow()
        if not start_time:
            start_time = end_time - timedelta(days=1)
        
        # Run the report in a separate thread
        threading.Thread(
            target=self._run_report_async,
            args=(report_id, start_time, end_time),
            daemon=True
        ).start()
        
        return {
            'success': True,
            'message': f'Scheduled report {report_id} to run',
            'report_id': report_id,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat()
        }
    
    def cleanup_old_reports(self) -> Dict[str, int]:
        """Clean up old reports and logs based on retention policies."""
        cleaned = {}
        
        # Clean up old reports
        for report_id, report in self.reports.items():
            try:
                count = report.cleanup_old_reports()
                if count > 0:
                    cleaned[report_id] = count
            except Exception as e:
                self.logger.error(f"Error cleaning up reports for {report_id}: {e}")
        
        # Clean up old audit logs
        try:
            log_cleaned = self.audit_logger.cleanup_old_logs()
            if log_cleaned > 0:
                cleaned['audit_logs'] = log_cleaned
        except Exception as e:
            self.logger.error(f"Error cleaning up audit logs: {e}")
        
        return cleaned
