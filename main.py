#!/usr/bin/env python3
"""
AutoVulnScanner - Automated Vulnerability Scanning and Reporting Tool
"""

import os
import sys
import argparse
import json
import datetime
import logging
import time
import subprocess
import requests
from enum import Enum
import socket
import configparser
import csv
import threading
import schedule
import platform

# For ZAP integration
from zapv2 import ZAPv2

# For reporting
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# For the web dashboard
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("vulnscanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("AutoVulnScanner")

class VulnerabilitySeverity(Enum):
    """Enumeration of vulnerability severity levels."""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1
    
    @staticmethod
    def from_cvss(score):
        """Convert CVSS score to severity."""
        if score >= 9.0:
            return VulnerabilitySeverity.CRITICAL
        elif score >= 7.0:
            return VulnerabilitySeverity.HIGH
        elif score >= 4.0:
            return VulnerabilitySeverity.MEDIUM
        elif score >= 0.1:
            return VulnerabilitySeverity.LOW
        else:
            return VulnerabilitySeverity.INFO

class Vulnerability:
    """Class representing a vulnerability finding."""
    def __init__(self, name, description, severity, affected_component, remediation=None, cvss_score=None):
        self.name = name
        self.description = description
        self.severity = severity if isinstance(severity, VulnerabilitySeverity) else VulnerabilitySeverity.from_cvss(cvss_score or 0)
        self.affected_component = affected_component
        self.remediation = remediation
        self.cvss_score = cvss_score
        self.timestamp = datetime.datetime.now()
        
    def to_dict(self):
        """Convert vulnerability to dictionary for serialization."""
        return {
            'name': self.name,
            'description': self.description,
            'severity': self.severity.name,
            'severity_value': self.severity.value,
            'affected_component': self.affected_component,
            'remediation': self.remediation,
            'cvss_score': self.cvss_score,
            'timestamp': self.timestamp.isoformat()
        }
        
    @staticmethod
    def from_dict(data):
        """Create a vulnerability from dictionary data."""
        vuln = Vulnerability(
            name=data['name'],
            description=data['description'],
            severity=VulnerabilitySeverity[data['severity']],
            affected_component=data['affected_component'],
            remediation=data.get('remediation'),
            cvss_score=data.get('cvss_score')
        )
        vuln.timestamp = datetime.datetime.fromisoformat(data['timestamp'])
        return vuln

class ScanResult:
    """Class representing the results of a security scan."""
    def __init__(self, target, scan_type, start_time=None):
        self.target = target
        self.scan_type = scan_type
        self.start_time = start_time or datetime.datetime.now()
        self.end_time = None
        self.vulnerabilities = []
        self.scan_id = f"{scan_type}-{int(time.time())}"
        
    def add_vulnerability(self, vulnerability):
        """Add a vulnerability to the scan results."""
        self.vulnerabilities.append(vulnerability)
        
    def complete_scan(self):
        """Mark the scan as complete."""
        self.end_time = datetime.datetime.now()
        
    def to_dict(self):
        """Convert scan result to dictionary for serialization."""
        return {
            'scan_id': self.scan_id,
            'target': self.target,
            'scan_type': self.scan_type,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
        }
        
    @staticmethod
    def from_dict(data):
        """Create a scan result from dictionary data."""
        result = ScanResult(
            target=data['target'],
            scan_type=data['scan_type'],
            start_time=datetime.datetime.fromisoformat(data['start_time'])
        )
        if data.get('end_time'):
            result.end_time = datetime.datetime.fromisoformat(data['end_time'])
        
        result.scan_id = data['scan_id']
        result.vulnerabilities = [Vulnerability.from_dict(v) for v in data['vulnerabilities']]
        return result
        
    def get_summary(self):
        """Get a summary of the scan results."""
        severity_counts = {s: 0 for s in VulnerabilitySeverity}
        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
            
        duration = (self.end_time - self.start_time).total_seconds() if self.end_time else None
        
        return {
            'target': self.target,
            'scan_type': self.scan_type,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration': duration,
            'total_vulnerabilities': len(self.vulnerabilities),
            'severity_counts': severity_counts
        }

class WebScanner:
    """Class for scanning web applications using OWASP ZAP."""
    def __init__(self, target_url, api_key=None, proxy_host='localhost', proxy_port=8080):
        self.target_url = target_url
        self.zap = None
        self.api_key = api_key
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        
    def setup_zap(self):
        """Initialize and set up ZAP."""
        try:
            # Connect to ZAP
            self.zap = ZAPv2(proxies={'http': f'http://{self.proxy_host}:{self.proxy_port}', 
                                     'https': f'http://{self.proxy_host}:{self.proxy_port}'}, 
                           apikey=self.api_key)
            
            # Check if ZAP is running
            version = self.zap.core.version
            logger.info(f"Connected to ZAP {version}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to ZAP: {e}")
            return False
            
    def spider_scan(self):
        """Run a spider scan to crawl the target website."""
        try:
            logger.info(f"Starting spider scan on {self.target_url}")
            scan_id = self.zap.spider.scan(self.target_url)
            
            # Wait for the spider to complete
            while int(self.zap.spider.status(scan_id)) < 100:
                logger.info(f"Spider progress: {self.zap.spider.status(scan_id)}%")
                time.sleep(2)
                
            logger.info("Spider scan completed")
            return True
        except Exception as e:
            logger.error(f"Spider scan failed: {e}")
            return False
            
    def active_scan(self):
        """Run an active scan to find vulnerabilities."""
        try:
            logger.info(f"Starting active scan on {self.target_url}")
            scan_id = self.zap.ascan.scan(self.target_url)
            
            # Wait for the active scan to complete
            while int(self.zap.ascan.status(scan_id)) < 100:
                logger.info(f"Active scan progress: {self.zap.ascan.status(scan_id)}%")
                time.sleep(5)
                
            logger.info("Active scan completed")
            return True
        except Exception as e:
            logger.error(f"Active scan failed: {e}")
            return False
            
    def get_alerts(self):
        """Get the alerts (vulnerabilities) found by ZAP."""
        vulnerabilities = []
        try:
            alerts = self.zap.core.alerts()
            
            for alert in alerts:
                name = alert.get('name')
                desc = alert.get('description')
                risk = alert.get('risk')
                url = alert.get('url')
                param = alert.get('param', '')
                solution = alert.get('solution')
                
                # Convert ZAP risk to severity
                severity_map = {
                    '3': VulnerabilitySeverity.HIGH,
                    '2': VulnerabilitySeverity.MEDIUM,
                    '1': VulnerabilitySeverity.LOW,
                    '0': VulnerabilitySeverity.INFO
                }
                severity = severity_map.get(risk, VulnerabilitySeverity.INFO)
                
                affected = f"{url} {f'(parameter: {param})' if param else ''}"
                
                vuln = Vulnerability(
                    name=name,
                    description=desc,
                    severity=severity,
                    affected_component=affected,
                    remediation=solution
                )
                vulnerabilities.append(vuln)
                
            return vulnerabilities
        except Exception as e:
            logger.error(f"Failed to get alerts: {e}")
            return []
            
    def perform_scan(self):
        """Perform a complete web scan."""
        scan_result = ScanResult(self.target_url, "web_scan")
        
        if not self.setup_zap():
            logger.error("Failed to set up ZAP. Is ZAP running?")
            return scan_result
            
        self.spider_scan()
        self.active_scan()
        
        vulnerabilities = self.get_alerts()
        for vuln in vulnerabilities:
            scan_result.add_vulnerability(vuln)
            
        scan_result.complete_scan()
        return scan_result

class NetworkScanner:
    """Class for network vulnerability scanning using nmap."""
    def __init__(self, target):
        self.target = target
    
    def is_nmap_installed(self):
        """Check if nmap is installed."""
        try:
            subprocess.run(["nmap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except FileNotFoundError:
            return False
    
    def perform_scan(self):
        """Perform a network scan using nmap."""
        scan_result = ScanResult(self.target, "network_scan")
        
        if not self.is_nmap_installed():
            logger.error("nmap is not installed. Please install nmap to use network scanning features.")
            vuln = Vulnerability(
                name="Scanner Configuration Error",
                description="nmap is not installed on the system",
                severity=VulnerabilitySeverity.INFO,
                affected_component="Scanner",
                remediation="Install nmap to enable network scanning features"
            )
            scan_result.add_vulnerability(vuln)
            scan_result.complete_scan()
            return scan_result
        
        # Basic port scan
        try:
            logger.info(f"Starting nmap scan on {self.target}")
            nmap_output = subprocess.run(
                ["nmap", "-sV", "-Pn", "--script=vuln", self.target],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Process the output
            output_lines = nmap_output.stdout.splitlines()
            current_port = None
            current_service = None
            
            for line in output_lines:
                # Look for port and service info
                if "open" in line and "/tcp" in line:
                    parts = line.split()
                    port_info = parts[0]
                    service_info = ' '.join(parts[2:])
                    current_port = port_info.split('/')[0]
                    current_service = service_info
                    
                    # Add vulnerability for open port
                    vuln = Vulnerability(
                        name=f"Open Port {current_port}",
                        description=f"Port {current_port} is open running {current_service}",
                        severity=VulnerabilitySeverity.INFO,
                        affected_component=f"{self.target}:{current_port}"
                    )
                    scan_result.add_vulnerability(vuln)
                
                # Look for vulnerabilities
                if "|" in line and "VULNERABLE" in line:
                    vuln_name = line.split("|")[0].strip()
                    
                    # Get additional info from the next few lines
                    vuln_index = output_lines.index(line)
                    description = ""
                    for i in range(1, 5):
                        if vuln_index + i < len(output_lines):
                            if "|" in output_lines[vuln_index + i]:
                                description += output_lines[vuln_index + i].split("|")[1].strip() + " "
                    
                    vuln = Vulnerability(
                        name=vuln_name,
                        description=description,
                        severity=VulnerabilitySeverity.HIGH,  # Most nmap vuln scripts detect significant issues
                        affected_component=f"{self.target}:{current_port} ({current_service})",
                        remediation="Update the affected service to a patched version"
                    )
                    scan_result.add_vulnerability(vuln)
            
            scan_result.complete_scan()
            logger.info("Network scan completed")
            return scan_result
            
        except Exception as e:
            logger.error(f"Network scan failed: {e}")
            vuln = Vulnerability(
                name="Scanner Error",
                description=f"Network scan failed: {str(e)}",
                severity=VulnerabilitySeverity.INFO,
                affected_component="Scanner",
                remediation="Check scanner configuration and target accessibility"
            )
            scan_result.add_vulnerability(vuln)
            scan_result.complete_scan()
            return scan_result

class ReportGenerator:
    """Class for generating vulnerability reports."""
    def __init__(self, scan_result):
        self.scan_result = scan_result
        
    def generate_pdf_report(self, output_path):
        """Generate a PDF report of the scan results."""
        try:
            logger.info(f"Generating PDF report at {output_path}")
            doc = SimpleDocTemplate(output_path, pagesize=letter)
            story = []
            
            # Set up styles
            styles = getSampleStyleSheet()
            title_style = styles['Heading1']
            heading2_style = styles['Heading2']
            normal_style = styles['Normal']
            
            # Title
            title = f"Vulnerability Scan Report: {self.scan_result.target}"
            story.append(Paragraph(title, title_style))
            story.append(Spacer(1, 12))
            
            # Scan Information
            scan_info = f"""
            <b>Target:</b> {self.scan_result.target}<br/>
            <b>Scan Type:</b> {self.scan_result.scan_type}<br/>
            <b>Start Time:</b> {self.scan_result.start_time.strftime('%Y-%m-%d %H:%M:%S')}<br/>
            <b>End Time:</b> {self.scan_result.end_time.strftime('%Y-%m-%d %H:%M:%S') if self.scan_result.end_time else 'N/A'}<br/>
            <b>Duration:</b> {(self.scan_result.end_time - self.scan_result.start_time) if self.scan_result.end_time else 'N/A'}<br/>
            """
            story.append(Paragraph(scan_info, normal_style))
            story.append(Spacer(1, 12))
            
            # Executive Summary
            story.append(Paragraph("Executive Summary", heading2_style))
            summary = self.scan_result.get_summary()
            
            # Count vulnerabilities by severity
            severity_counts = summary['severity_counts']
            summary_text = f"""
            <b>Total Vulnerabilities Found:</b> {summary['total_vulnerabilities']}<br/>
            <b>Critical:</b> {severity_counts.get(VulnerabilitySeverity.CRITICAL, 0)}<br/>
            <b>High:</b> {severity_counts.get(VulnerabilitySeverity.HIGH, 0)}<br/>
            <b>Medium:</b> {severity_counts.get(VulnerabilitySeverity.MEDIUM, 0)}<br/>
            <b>Low:</b> {severity_counts.get(VulnerabilitySeverity.LOW, 0)}<br/>
            <b>Informational:</b> {severity_counts.get(VulnerabilitySeverity.INFO, 0)}<br/>
            """
            story.append(Paragraph(summary_text, normal_style))
            story.append(Spacer(1, 12))
            
            # Findings
            story.append(Paragraph("Detailed Findings", heading2_style))
            
            # Sort vulnerabilities by severity (highest first)
            sorted_vulns = sorted(
                self.scan_result.vulnerabilities, 
                key=lambda v: v.severity.value, 
                reverse=True
            )
            
            for vuln in sorted_vulns:
                vuln_title = f"{vuln.severity.name}: {vuln.name}"
                story.append(Paragraph(vuln_title, styles['Heading3']))
                
                details = f"""
                <b>Description:</b> {vuln.description}<br/>
                <b>Affected Component:</b> {vuln.affected_component}<br/>
                """
                if vuln.cvss_score:
                    details += f"<b>CVSS Score:</b> {vuln.cvss_score}<br/>"
                if vuln.remediation:
                    details += f"<b>Remediation:</b> {vuln.remediation}<br/>"
                    
                story.append(Paragraph(details, normal_style))
                story.append(Spacer(1, 12))
            
            # Build the PDF
            doc.build(story)
            logger.info("PDF report generated successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            return False
            
    def generate_csv_report(self, output_path):
        """Generate a CSV report of the scan results."""
        try:
            logger.info(f"Generating CSV report at {output_path}")
            
            with open(output_path, 'w', newline='') as csv_file:
                writer = csv.writer(csv_file)
                
                # Write header
                writer.writerow([
                    'Severity', 'Name', 'Description', 'Affected Component', 
                    'CVSS Score', 'Remediation'
                ])
                
                # Sort vulnerabilities by severity (highest first)
                sorted_vulns = sorted(
                    self.scan_result.vulnerabilities, 
                    key=lambda v: v.severity.value, 
                    reverse=True
                )
                
                # Write vulnerabilities
                for vuln in sorted_vulns:
                    writer.writerow([
                        vuln.severity.name,
                        vuln.name,
                        vuln.description,
                        vuln.affected_component,
                        vuln.cvss_score if vuln.cvss_score else '',
                        vuln.remediation if vuln.remediation else ''
                    ])
                    
            logger.info("CSV report generated successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate CSV report: {e}")
            return False
            
    def generate_json_report(self, output_path):
        """Generate a JSON report of the scan results."""
        try:
            logger.info(f"Generating JSON report at {output_path}")
            
            with open(output_path, 'w') as json_file:
                json.dump(self.scan_result.to_dict(), json_file, indent=4)
                
            logger.info("JSON report generated successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            return False

class ScanManager:
    """Class for managing vulnerability scans."""
    def __init__(self, config_file=None):
        self.config_file = config_file or "scan_config.ini"
        self.config = configparser.ConfigParser()
        self.load_config()
        
    def load_config(self):
        """Load configuration from file."""
        if os.path.exists(self.config_file):
            try:
                self.config.read(self.config_file)
                logger.info(f"Configuration loaded from {self.config_file}")
            except Exception as e:
                logger.error(f"Failed to load configuration: {e}")
                self.initialize_default_config()
        else:
            logger.info("No configuration file found. Using default configuration.")
            self.initialize_default_config()
            
    def initialize_default_config(self):
        """Initialize default configuration."""
        self.config['General'] = {
            'output_dir': 'reports',
            'log_level': 'INFO'
        }
        
        self.config['ZAP'] = {
            'proxy_host': 'localhost',
            'proxy_port': '8080',
            'api_key': ''
        }
        
        self.config['Scheduled'] = {
            'enabled': 'false',
            'interval': '24',  # hours
            'targets': ''
        }
        
        # Save the default config
        self.save_config()
        
    def save_config(self):
        """Save configuration to file."""
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, 'w') as config_file:
                self.config.write(config_file)
            logger.info(f"Configuration saved to {self.config_file}")
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            
    def create_output_dir(self):
        """Create the output directory for reports if it doesn't exist."""
        output_dir = self.config.get('General', 'output_dir', fallback='reports')
        os.makedirs(output_dir, exist_ok=True)
        return output_dir
        
    def perform_web_scan(self, target_url):
        """Perform a web application scan."""
        logger.info(f"Starting web scan for {target_url}")
        
        # Get ZAP configuration
        zap_host = self.config.get('ZAP', 'proxy_host', fallback='localhost')
        zap_port = self.config.getint('ZAP', 'proxy_port', fallback=8080)
        zap_api_key = self.config.get('ZAP', 'api_key', fallback=None)
        
        # Initialize and run scanner
        scanner = WebScanner(
            target_url=target_url,
            api_key=zap_api_key,
            proxy_host=zap_host,
            proxy_port=zap_port
        )
        
        scan_result = scanner.perform_scan()
        
        # Generate reports
        output_dir = self.create_output_dir()
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        target_name = target_url.replace('://', '_').replace('/', '_').replace(':', '_')
        report_base = os.path.join(output_dir, f"web_scan_{target_name}_{timestamp}")
        
        report_gen = ReportGenerator(scan_result)
        report_gen.generate_pdf_report(f"{report_base}.pdf")
        report_gen.generate_json_report(f"{report_base}.json")
        report_gen.generate_csv_report(f"{report_base}.csv")
        
        logger.info(f"Web scan completed for {target_url}")
        return scan_result
        
    def perform_network_scan(self, target):
        """Perform a network scan."""
        logger.info(f"Starting network scan for {target}")
        
        # Initialize and run scanner
        scanner = NetworkScanner(target=target)
        scan_result = scanner.perform_scan()
        
        # Generate reports
        output_dir = self.create_output_dir()
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        target_name = target.replace(':', '_').replace('/', '_')
        report_base = os.path.join(output_dir, f"network_scan_{target_name}_{timestamp}")
        
        report_gen = ReportGenerator(scan_result)
        report_gen.generate_pdf_report(f"{report_base}.pdf")
        report_gen.generate_json_report(f"{report_base}.json")
        report_gen.generate_csv_report(f"{report_base}.csv")
        
        logger.info(f"Network scan completed for {target}")
        return scan_result
        
    def schedule_scans(self):
        """Schedule regular scans based on configuration."""
        if not self.config.getboolean('Scheduled', 'enabled', fallback=False):
            logger.info("Scheduled scanning is disabled.")
            return
            
        # Get targets and interval
        targets_str = self.config.get('Scheduled', 'targets', fallback='')
        targets = [t.strip() for t in targets_str.split(',') if t.strip()]
        
        if not targets:
            logger.warning("No targets specified for scheduled scanning.")
            return
            
        interval_hours = self.config.getint('Scheduled', 'interval', fallback=24)
        
        # Set up scheduling
        def run_scheduled_scans():
            logger.info("Running scheduled scans")
            for target in targets:
                if '://' in target:  # Web target
                    self.perform_web_scan(target)
                else:  # Network target
                    self.perform_network_scan(target)
        
        # Schedule the job
        schedule.every(interval_hours).hours.do(run_scheduled_scans)
        
        # Run in a separate thread
        def run_scheduler():
            while True:
                schedule.run_pending()
                time.sleep(60)
                
        scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()
        logger.info(f"Scheduled scanning enabled for targets: {targets}")

class WebDashboard:
    """Web dashboard for the vulnerability scanner."""
    def __init__(self, scan_manager):
        self.app = Flask(__name__)
        self.scan_manager = scan_manager
        self.setup_routes()
        
    def setup_routes(self):
        """Set up the Flask routes."""
        @self.app.route('/')
        def index():
            return render_template('index.html')
            
        @self.app.route('/scan', methods=['POST'])
        def start_scan():
            scan_type = request.form.get('scan_type')
            target = request.form.get('target')
            
            if not target:
                return jsonify({'status': 'error', 'message': 'Target is required'})
                
            # Start scan in a separate thread
            def run_scan():
                if scan_type == 'web':
                    self.scan_manager.perform_web_scan(target)
                else:
                    self.scan_manager.perform_network_scan(target)
                    
            threading.Thread(target=run_scan).start()
            
            return jsonify({'status': 'success', 'message': f'{scan_type.title()} scan started for {target}'})
            
        @self.app.route('/reports')
        def list_reports():
            output_dir = self.scan_manager.config.get('General', 'output_dir', fallback='reports')
            
            if not os.path.exists(output_dir):
                return jsonify({'reports': []})
                
            reports = []
            for filename in os.listdir(output_dir):
                if filename.endswith(('.pdf', '.json', '.csv')):
                    file_path = os.path.join(output_dir, filename)
                    reports.append({
                        'name': filename,
                        'path': file_path,
                        'size': os.path.getsize(file_path),
                        'date': datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
                    })
                    
            return jsonify({'reports': reports})
            
        @self.app.route('/download/<path:filename>')
        def download_report(filename):
            output_dir = self.scan_manager.config.get('General', 'output_dir', fallback='reports')
            return send_file(os.path.join(output_dir, filename), as_attachment=True)
            
        @self.app.route('/config', methods=['GET', 'POST'])
        def config():
            if request.method == 'POST':
                # Update configuration
                form_data = request.form
                
                # General settings
                self.scan_manager.config['General']['output_dir'] = form_data.get('output_dir', 'reports')
                self.scan_manager.config['General']['log_level'] = form_data.get('log_level', 'INFO')
                
                # ZAP settings
                self.scan_manager.config['ZAP']['proxy_host'] = form_data.get('zap_host', 'localhost')
                self.scan_manager.config['ZAP']['proxy_port'] = form_data.get('zap_port', '8080')
                self.scan_manager.config['ZAP']['api_key'] = form_data.get('zap_api_key', '')
                
                # Scheduled scan settings
                self.scan
                # Scheduled scan settings
                self.scan_manager.config['Scheduled']['enabled'] = 'true' if form_data.get('scheduled_enabled') else 'false'
                self.scan_manager.config['Scheduled']['interval'] = form_data.get('scheduled_interval', '24')
                self.scan_manager.config['Scheduled']['targets'] = form_data.get('scheduled_targets', '')
                
                # Save configuration
                self.scan_manager.save_config()
                
                # Restart scheduler if needed
                if self.scan_manager.config.getboolean('Scheduled', 'enabled'):
                    self.scan_manager.schedule_scans()
                    
                return jsonify({'status': 'success', 'message': 'Configuration updated'})
            
            # Return current configuration
            config_data = {
                'general': dict(self.scan_manager.config['General']),
                'zap': dict(self.scan_manager.config['ZAP']),
                'scheduled': dict(self.scan_manager.config['Scheduled'])
            }
            
            return jsonify({'config': config_data})
            
    def run(self, host='0.0.0.0', port=5000, debug=False):
        """Run the web dashboard."""
        self.app.run(host=host, port=port, debug=debug)


def create_flask_templates():
    """Create the necessary Flask templates for the web dashboard."""
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    
    # Create index.html
    index_html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Vulnerability Scanner Dashboard</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css">
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
            <div class="container">
                <a class="navbar-brand" href="#">AutoVulnScanner</a>
                <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                    <span class="navbar-toggler-icon"></span>
                </button>
                <div class="collapse navbar-collapse" id="navbarNav">
                    <ul class="navbar-nav">
                        <li class="nav-item">
                            <a class="nav-link active" href="#scan-tab" data-bs-toggle="tab">Scan</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#reports-tab" data-bs-toggle="tab">Reports</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#config-tab" data-bs-toggle="tab">Configuration</a>
                        </li>
                    </ul>
                </div>
            </div>
        </nav>
        
        <div class="container mt-4">
            <div class="tab-content">
                <!-- Scan Tab -->
                <div class="tab-pane fade show active" id="scan-tab">
                    <div class="card">
                        <div class="card-header">
                            <h4>Start New Scan</h4>
                        </div>
                        <div class="card-body">
                            <form id="scan-form">
                                <div class="mb-3">
                                    <label for="scan-type" class="form-label">Scan Type</label>
                                    <select class="form-select" id="scan-type" name="scan_type" required>
                                        <option value="web">Web Application Scan</option>
                                        <option value="network">Network Scan</option>
                                    </select>
                                </div>
                                <div class="mb-3">
                                    <label for="target" class="form-label">Target</label>
                                    <input type="text" class="form-control" id="target" name="target" 
                                           placeholder="For web: https://example.com, For network: 192.168.1.0/24" required>
                                </div>
                                <button type="submit" class="btn btn-primary">Start Scan</button>
                            </form>
                            
                            <div class="mt-4" id="scan-status" style="display: none;">
                                <div class="alert alert-info">
                                    <div class="d-flex align-items-center">
                                        <div class="spinner-border spinner-border-sm me-2" role="status"></div>
                                        <div id="scan-status-message">Scan in progress...</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Reports Tab -->
                <div class="tab-pane fade" id="reports-tab">
                    <div class="card">
                        <div class="card-header">
                            <h4>Scan Reports</h4>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-striped">
                                    <thead>
                                        <tr>
                                            <th>Report Name</th>
                                            <th>Date</th>
                                            <th>Size</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody id="reports-table-body">
                                        <tr>
                                            <td colspan="4" class="text-center">Loading reports...</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Configuration Tab -->
                <div class="tab-pane fade" id="config-tab">
                    <div class="card">
                        <div class="card-header">
                            <h4>Scanner Configuration</h4>
                        </div>
                        <div class="card-body">
                            <form id="config-form">
                                <h5>General Settings</h5>
                                <div class="mb-3">
                                    <label for="output-dir" class="form-label">Reports Directory</label>
                                    <input type="text" class="form-control" id="output-dir" name="output_dir" value="reports">
                                </div>
                                <div class="mb-3">
                                    <label for="log-level" class="form-label">Log Level</label>
                                    <select class="form-select" id="log-level" name="log_level">
                                        <option value="DEBUG">DEBUG</option>
                                        <option value="INFO" selected>INFO</option>
                                        <option value="WARNING">WARNING</option>
                                        <option value="ERROR">ERROR</option>
                                    </select>
                                </div>
                                
                                <h5 class="mt-4">ZAP Settings</h5>
                                <div class="mb-3">
                                    <label for="zap-host" class="form-label">ZAP Proxy Host</label>
                                    <input type="text" class="form-control" id="zap-host" name="zap_host" value="localhost">
                                </div>
                                <div class="mb-3">
                                    <label for="zap-port" class="form-label">ZAP Proxy Port</label>
                                    <input type="number" class="form-control" id="zap-port" name="zap_port" value="8080">
                                </div>
                                <div class="mb-3">
                                    <label for="zap-api-key" class="form-label">ZAP API Key (if required)</label>
                                    <input type="text" class="form-control" id="zap-api-key" name="zap_api_key">
                                </div>
                                
                                <h5 class="mt-4">Scheduled Scanning</h5>
                                <div class="mb-3 form-check">
                                    <input type="checkbox" class="form-check-input" id="scheduled-enabled" name="scheduled_enabled">
                                    <label class="form-check-label" for="scheduled-enabled">Enable Scheduled Scanning</label>
                                </div>
                                <div class="mb-3">
                                    <label for="scheduled-interval" class="form-label">Scan Interval (hours)</label>
                                    <input type="number" class="form-control" id="scheduled-interval" name="scheduled_interval" value="24">
                                </div>
                                <div class="mb-3">
                                    <label for="scheduled-targets" class="form-label">Targets (comma-separated)</label>
                                    <textarea class="form-control" id="scheduled-targets" name="scheduled_targets" 
                                              placeholder="https://example.com, 192.168.1.0/24" rows="3"></textarea>
                                </div>
                                
                                <button type="submit" class="btn btn-primary">Save Configuration</button>
                            </form>
                            
                            <div class="mt-3" id="config-status" style="display: none;"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
        // Scan form submission
        $('#scan-form').on('submit', function(e) {
            e.preventDefault();

            const formData = $(this).serialize();
            $('#scan-status').show();

            $.ajax({
                url: '/scan',
                method: 'POST',
                data: formData,
                success: function(response) {
                    $('#scan-status-message').text(response.message + ' Please check your PC for the scanned reports.');
                    setTimeout(function() {
                        $('#scan-status').hide();
                    }, 5000);
                },
                error: function() {
                    $('#scan-status').removeClass('alert-info').addClass('alert-danger');
                    $('#scan-status-message').text('Error starting scan');
                }
            });
        });

        // Load reports
        function loadReports() {
            $.ajax({
                url: '/reports',
                method: 'GET',
                success: function(response) {
                    const reports = response.reports;
                    let html = '';

                    if (reports.length === 0) {
                        html = '<tr><td colspan="4" class="text-center">No reports found</td></tr>';
                    } else {
                        reports.forEach(function(report) {
                            html += `
                                <tr>
                                    <td>${report.name}</td>
                                    <td>${report.date}</td>
                                    <td>${formatFileSize(report.size)}</td>
                                    <td>
                                        <a href="/download/${report.name}" class="btn btn-sm btn-primary">Download</a>
                                    </td>
                                </tr>
                            `;
                        });
                    }

                    $('#reports-table-body').html(html);
                },
                error: function() {
                    $('#reports-table-body').html('<tr><td colspan="4" class="text-center text-danger">Error loading reports</td></tr>');
                }
            });
        }

        // Format file size
        function formatFileSize(bytes) {
            if (bytes < 1024) return bytes + ' B';
            else if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
            else return (bytes / 1048576).toFixed(1) + ' MB';
        }

        // Load configuration
        function loadConfig() {
            $.ajax({
                url: '/config',
                method: 'GET',
                success: function(response) {
                    const config = response.config;

                    // General settings
                    $('#output-dir').val(config.general.output_dir);
                    $('#log-level').val(config.general.log_level);

                    // ZAP settings
                    $('#zap-host').val(config.zap.proxy_host);
                    $('#zap-port').val(config.zap.proxy_port);
                    $('#zap-api-key').val(config.zap.api_key);

                    // Scheduled settings
                    $('#scheduled-enabled').prop('checked', config.scheduled.enabled === 'true');
                    $('#scheduled-interval').val(config.scheduled.interval);
                    $('#scheduled-targets').val(config.scheduled.targets);
                }
            });
        }

        // Save configuration
        $('#config-form').on('submit', function(e) {
            e.preventDefault();

            const formData = $(this).serialize();

            $.ajax({
                url: '/config',
                method: 'POST',
                data: formData,
                success: function(response) {
                    $('#config-status').removeClass('alert-danger').addClass('alert-success')
                        .text(response.message).show();

                    setTimeout(function() {
                        $('#config-status').hide();
                    }, 3000);
                },
                error: function() {
                    $('#config-status').removeClass('alert-success').addClass('alert-danger')
                        .text('Error saving configuration').show();
                }
            });
        });

        // Tab change event
        $('a[data-bs-toggle="tab"]').on('shown.bs.tab', function(e) {
            const target = $(e.target).attr('href');

            if (target === '#reports-tab') {
                loadReports();
            } else if (target === '#config-tab') {
                loadConfig();
            }
        });

        // Initial load
        $(document).ready(function() {
            const hash = window.location.hash || '#scan-tab';
            $(`a[href="${hash}"]`).tab('show');

            if (hash === '#reports-tab') {
                loadReports();
            } else if (hash === '#config-tab') {
                loadConfig();
            }
        });
        </script>
    </body>
    </html>
    """
    
    with open('templates/index.html', 'w') as f:
        f.write(index_html)


def main():
    """Main function to run the vulnerability scanner."""
    parser = argparse.ArgumentParser(description='Automated Vulnerability Scanner')
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Web scan command
    web_parser = subparsers.add_parser('web', help='Run a web application scan')
    web_parser.add_argument('target', help='Target URL to scan')
    
    # Network scan command
    network_parser = subparsers.add_parser('network', help='Run a network scan')
    network_parser.add_argument('target', help='Target to scan (IP, hostname, or CIDR range)')
    
    # Dashboard command
    dashboard_parser = subparsers.add_parser('dashboard', help='Run the web dashboard')
    dashboard_parser.add_argument('--host', default='0.0.0.0', help='Host to bind the dashboard to')
    dashboard_parser.add_argument('--port', type=int, default=5000, help='Port to run the dashboard on')
    dashboard_parser.add_argument('--debug', action='store_true', help='Run the dashboard in debug mode')
    
    # Scheduled command
    scheduled_parser = subparsers.add_parser('scheduled', help='Run scheduled scans')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Initialize scan manager
    scan_manager = ScanManager()
    
    # Create templates for web dashboard
    create_flask_templates()
    
    # Execute command
    if args.command == 'web':
        scan_manager.perform_web_scan(args.target)
    elif args.command == 'network':
        scan_manager.perform_network_scan(args.target)
    elif args.command == 'dashboard':
        dashboard = WebDashboard(scan_manager)
        print(f"Dashboard running on http://{args.host}:{args.port}")
        dashboard.run(host=args.host, port=args.port, debug=args.debug)
    elif args.command == 'scheduled':
        scan_manager.schedule_scans()
        print("Scheduled scans are running in the background.")
        # Keep the main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Exiting...")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()