#!/usr/bin/env python3
"""
ThreatPulse - Professional Real-Time SOC Threat Intelligence & Correlation Tool
Version: 2.0.0
NO EXTERNAL DEPENDENCIES - Pure Python Standard Library
Author: SOC Engineering Team
License: MIT
"""

import sys
import os
import json
import csv
import time
import subprocess
import socket
import threading
import queue
import signal
import hashlib
import re
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
from pathlib import Path
import platform
import ctypes
import ssl

# Severity Enum
class Severity(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"

# Alert dataclass
@dataclass
class Alert:
    timestamp: str
    severity: Severity
    source: str
    indicator: str
    description: str
    evidence: Dict[str, Any]
    correlation_id: str

# Global alert queue
alert_queue = queue.Queue(maxsize=1000)
shutdown_event = threading.Event()

# ANSI color codes for cross-platform color output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    BG_RED = '\033[41m'
    BG_YELLOW = '\033[43m'
    BG_GREEN = '\033[42m'

# Check for admin/root privileges
def is_admin() -> bool:
    """Check if the script is running with admin/root privileges."""
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False

class ThreatIntelligence:
    """Threat intelligence collector - NO external dependencies"""
    
    def __init__(self):
        self.threat_feeds = {
            'malicious_ips': 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
            'malware_domains': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
            'tor_exits': 'https://check.torproject.org/torbulkexitlist'
        }
        
        self.malicious_ips = set()
        self.malicious_domains = set()
        self.tor_exit_nodes = set()
        
        # Fallback data in case feeds fail
        self._load_fallback_data()
    
    def fetch_threat_feeds(self) -> Dict[str, int]:
        """Fetch and normalize threat intelligence using urllib"""
        results = {}
        
        print(f"{Colors.CYAN}[*] Fetching threat intelligence feeds...{Colors.RESET}")
        
        for feed_name, url in self.threat_feeds.items():
            try:
                # Create SSL context to avoid certificate issues
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # Add user-agent header
                req = urllib.request.Request(
                    url,
                    headers={'User-Agent': 'ThreatPulse-SOC/2.0'}
                )
                
                with urllib.request.urlopen(req, timeout=10, context=context) as response:
                    content = response.read().decode('utf-8')
                    
                    if feed_name == 'malicious_ips':
                        for line in content.split('\n'):
                            ip = line.strip()
                            if ip and not ip.startswith('#'):
                                self.malicious_ips.add(ip)
                        results[feed_name] = len(self.malicious_ips)
                        
                    elif feed_name == 'malware_domains':
                        for line in content.split('\n'):
                            if not line.startswith('#') and line.strip():
                                parts = line.split()
                                if len(parts) >= 2:
                                    domain = parts[1].strip()
                                    if '.' in domain:
                                        self.malicious_domains.add(domain)
                        results[feed_name] = len(self.malicious_domains)
                        
                    elif feed_name == 'tor_exits':
                        for line in content.split('\n'):
                            ip = line.strip()
                            if ip:
                                self.tor_exit_nodes.add(ip)
                        results[feed_name] = len(self.tor_exit_nodes)
                            
            except Exception as e:
                print(f"{Colors.YELLOW}[!] Failed to fetch {feed_name}: {e}{Colors.RESET}")
        
        print(f"{Colors.GREEN}[+] Threat intelligence updated")
        for feed, count in results.items():
            print(f"    {feed}: {count} indicators")
        
        return results
    
    def _load_fallback_data(self):
        """Load fallback threat data if feeds fail"""
        # Example malicious IPs for testing
        test_malicious_ips = [
            '185.220.101.34',  # Known malicious
            '45.155.205.233',
            '91.92.240.119',
            '103.253.24.120'
        ]
        
        test_malicious_domains = [
            'malware.com',
            'evil-domain.org',
            'phishing-site.net'
        ]
        
        test_tor_exits = [
            '185.220.101.34',
            '185.220.101.35',
            '185.220.101.36'
        ]
        
        self.malicious_ips.update(test_malicious_ips)
        self.malicious_domains.update(test_malicious_domains)
        self.tor_exit_nodes.update(test_tor_exits)

class NetworkAnalyzer:
    """Network traffic analysis - NO external dependencies"""
    
    def __init__(self, threat_intel: ThreatIntelligence):
        self.threat_intel = threat_intel
    
    def analyze_network(self) -> List[Alert]:
        """Analyze network connections using system commands"""
        alerts = []
        
        print(f"{Colors.CYAN}[*] Analyzing network connections...{Colors.RESET}")
        
        try:
            # Use netstat for cross-platform compatibility
            if platform.system() == "Windows":
                cmd = ['netstat', '-ano']
            else:
                cmd = ['netstat', '-tunap']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            lines = result.stdout.split('\n')
            
            for line in lines:
                if 'ESTABLISHED' in line or 'LISTENING' in line or 'LISTEN' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        # Extract foreign IP (different positions for Windows vs Unix)
                        if platform.system() == "Windows":
                            # Windows: Proto Local Address Foreign Address State PID
                            foreign_addr = parts[2]
                        else:
                            # Unix: Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program
                            foreign_addr = parts[4]
                        
                        # Parse IP address
                        if ':' in foreign_addr:
                            foreign_ip = foreign_addr.split(':')[0]
                            
                            # Check against threat intelligence
                            if foreign_ip in self.threat_intel.malicious_ips:
                                alert = Alert(
                                    timestamp=datetime.now().isoformat(),
                                    severity=Severity.CRITICAL,
                                    source="Network Analysis",
                                    indicator=foreign_ip,
                                    description="Connection to known malicious IP",
                                    evidence={
                                        'foreign_ip': foreign_ip,
                                        'connection_line': line.strip()
                                    },
                                    correlation_id=f"NET_{foreign_ip}_{int(time.time())}"
                                )
                                alerts.append(alert)
                            
                            elif foreign_ip in self.threat_intel.tor_exit_nodes:
                                alert = Alert(
                                    timestamp=datetime.now().isoformat(),
                                    severity=Severity.WARNING,
                                    source="Network Analysis",
                                    indicator=foreign_ip,
                                    description="Connection to Tor exit node",
                                    evidence={
                                        'foreign_ip': foreign_ip,
                                        'connection_line': line.strip()
                                    },
                                    correlation_id=f"TOR_{foreign_ip}_{int(time.time())}"
                                )
                                alerts.append(alert)
        
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Network analysis error: {e}{Colors.RESET}")
        
        return alerts

class LogAnalyzer:
    """System log analysis - NO external dependencies"""
    
    def __init__(self, threat_intel: ThreatIntelligence):
        self.threat_intel = threat_intel
        
        # Log patterns for suspicious activity
        self.suspicious_patterns = {
            'ssh_bruteforce': r'Failed password|authentication failure',
            'sudo_abuse': r'sudo.*COMMAND|session opened for user root',
            'privilege_escalation': r'su:|password changed|new user',
            'file_tampering': r'permission changed|ownership changed',
            'malicious_commands': r'wget.*http|curl.*http|base64.*decode'
        }
    
    def analyze_logs(self) -> List[Alert]:
        """Analyze system logs"""
        alerts = []
        
        print(f"{Colors.CYAN}[*] Analyzing system logs...{Colors.RESET}")
        
        # Determine log files based on OS
        if platform.system() == "Windows":
            log_files = self._get_windows_logs()
        else:
            log_files = ['/var/log/auth.log', '/var/log/syslog', '/var/log/secure']
        
        for log_file in log_files:
            if not os.path.exists(log_file):
                continue
                
            try:
                # Read last 1000 lines
                with open(log_file, 'r', errors='ignore') as f:
                    lines = f.readlines()[-1000:]
                
                for line in lines:
                    line_lower = line.lower()
                    
                    # Check for suspicious patterns
                    for pattern_name, pattern in self.suspicious_patterns.items():
                        if re.search(pattern, line_lower, re.IGNORECASE):
                            # Extract IP if present
                            ips = self._extract_ips(line)
                            
                            severity = Severity.WARNING
                            # Check if IP is malicious
                            if any(ip in self.threat_intel.malicious_ips for ip in ips):
                                severity = Severity.CRITICAL
                            
                            alert = Alert(
                                timestamp=datetime.now().isoformat(),
                                severity=severity,
                                source="Log Analysis",
                                indicator=pattern_name,
                                description=f"Suspicious activity in {os.path.basename(log_file)}",
                                evidence={
                                    'log_file': log_file,
                                    'log_entry': line.strip(),
                                    'pattern': pattern_name,
                                    'extracted_ips': ips
                                },
                                correlation_id=f"LOG_{hash(line) % 10000}"
                            )
                            alerts.append(alert)
                            
            except Exception as e:
                print(f"{Colors.YELLOW}[!] Error reading {log_file}: {e}{Colors.RESET}")
        
        return alerts
    
    def _get_windows_logs(self) -> List[str]:
        """Get Windows log file paths"""
        log_files = []
        event_logs = ['Security', 'System', 'Application']
        
        for log_name in event_logs:
            # Try to read Windows Event Log via PowerShell
            try:
                ps_command = f"Get-EventLog -LogName {log_name} -Newest 50 | Select-Object Source, Message"
                result = subprocess.run(['powershell', '-Command', ps_command], 
                                      capture_output=True, text=True, timeout=10)
                
                if result.stdout:
                    # Create a temporary log file for analysis
                    temp_file = f"/tmp/windows_{log_name}_log.txt"
                    with open(temp_file, 'w') as f:
                        f.write(result.stdout)
                    log_files.append(temp_file)
                    
            except Exception:
                pass
        
        return log_files
    
    def _extract_ips(self, text: str) -> List[str]:
        """Extract IP addresses from text"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return re.findall(ip_pattern, text)

class ProcessAnalyzer:
    """Process and service analysis - NO external dependencies"""
    
    def __init__(self, threat_intel: ThreatIntelligence):
        self.threat_intel = threat_intel
        
        # Known malicious process patterns
        self.malicious_patterns = [
            'miner', 'xmrig', 'cryptonight',
            'backdoor', 'reverse_shell',
            'keylogger', 'sniffer', 'pwdump'
        ]
    
    def analyze_processes(self) -> List[Alert]:
        """Analyze running processes using system commands"""
        alerts = []
        
        print(f"{Colors.CYAN}[*] Analyzing running processes...{Colors.RESET}")
        
        try:
            # Use system commands to get process list
            if platform.system() == "Windows":
                cmd = ['tasklist', '/FO', 'CSV', '/V']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                processes = self._parse_windows_tasklist(result.stdout)
            else:
                cmd = ['ps', 'aux']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                processes = self._parse_unix_ps(result.stdout)
            
            for proc in processes:
                # Check for malicious patterns
                for pattern in self.malicious_patterns:
                    if pattern in proc.get('command', '').lower():
                        alert = Alert(
                            timestamp=datetime.now().isoformat(),
                            severity=Severity.CRITICAL,
                            source="Process Analysis",
                            indicator=pattern,
                            description=f"Potential malicious process: {proc.get('name', 'unknown')}",
                            evidence=proc,
                            correlation_id=f"PROC_{proc.get('pid', 'unknown')}"
                        )
                        alerts.append(alert)
        
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Process analysis error: {e}{Colors.RESET}")
        
        return alerts
    
    def _parse_windows_tasklist(self, output: str) -> List[Dict]:
        """Parse Windows tasklist output"""
        processes = []
        lines = output.strip().split('\n')
        
        if len(lines) > 1:  # Has header
            headers = [h.strip('"') for h in lines[0].split('","')]
            for line in lines[1:]:
                values = [v.strip('"') for v in line.split('","')]
                if len(values) >= len(headers):
                    proc_info = {headers[i]: values[i] for i in range(len(headers))}
                    processes.append({
                        'name': proc_info.get('Image Name', ''),
                        'pid': proc_info.get('PID', ''),
                        'user': proc_info.get('User Name', ''),
                        'command': proc_info.get('Window Title', '') or proc_info.get('Image Name', '')
                    })
        
        return processes
    
    def _parse_unix_ps(self, output: str) -> List[Dict]:
        """Parse Unix ps aux output"""
        processes = []
        lines = output.strip().split('\n')
        
        if len(lines) > 1:  # Has header
            headers = lines[0].split()
            for line in lines[1:]:
                parts = line.split(None, len(headers)-1)
                if len(parts) == len(headers):
                    proc_info = {headers[i]: parts[i] for i in range(len(headers))}
                    processes.append({
                        'user': proc_info.get('USER', ''),
                        'pid': proc_info.get('PID', ''),
                        'cpu': proc_info.get('%CPU', ''),
                        'mem': proc_info.get('%MEM', ''),
                        'command': proc_info.get('COMMAND', '')
                    })
        
        return processes

class UserAnalyzer:
    """User and account analysis - NO external dependencies"""
    
    def __init__(self, threat_intel: ThreatIntelligence):
        self.threat_intel = threat_intel
        
        # Suspicious user patterns
        self.suspicious_users = ['backdoor', 'hacker', 'rootkit', 'malware']
    
    def analyze_users(self) -> List[Alert]:
        """Analyze user accounts and sessions"""
        alerts = []
        
        print(f"{Colors.CYAN}[*] Analyzing user accounts and sessions...{Colors.RESET}")
        
        try:
            if platform.system() == "Windows":
                alerts.extend(self._analyze_windows_users())
            else:
                alerts.extend(self._analyze_unix_users())
            
            # Check for suspicious login sessions
            alerts.extend(self._analyze_login_sessions())
            
        except Exception as e:
            print(f"{Colors.YELLOW}[!] User analysis error: {e}{Colors.RESET}")
        
        return alerts
    
    def _analyze_unix_users(self) -> List[Alert]:
        """Analyze Unix/Linux users"""
        alerts = []
        
        try:
            # Read /etc/passwd
            if os.path.exists('/etc/passwd'):
                with open('/etc/passwd', 'r') as f:
                    users = f.readlines()
                
                for user_line in users:
                    parts = user_line.strip().split(':')
                    if len(parts) >= 7:
                        username = parts[0]
                        uid = parts[2]
                        gid = parts[3]
                        shell = parts[6]
                        
                        # Check for suspicious usernames
                        for suspicious in self.suspicious_users:
                            if suspicious in username.lower():
                                alert = Alert(
                                    timestamp=datetime.now().isoformat(),
                                    severity=Severity.WARNING,
                                    source="User Analysis",
                                    indicator=username,
                                    description="Suspicious username detected",
                                    evidence={
                                        'username': username,
                                        'uid': uid,
                                        'gid': gid,
                                        'shell': shell,
                                        'reason': 'Matches suspicious pattern'
                                    },
                                    correlation_id=f"USER_{username}"
                                )
                                alerts.append(alert)
                        
                        # Check for users with UID 0 (other than root)
                        if uid == '0' and username != 'root':
                            alert = Alert(
                                timestamp=datetime.now().isoformat(),
                                severity=Severity.CRITICAL,
                                source="User Analysis",
                                indicator=username,
                                description="Non-root user with UID 0",
                                evidence={
                                    'username': username,
                                    'uid': uid,
                                    'gid': gid,
                                    'shell': shell
                                },
                                correlation_id=f"UID0_{username}"
                            )
                            alerts.append(alert)
        
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Unix user analysis error: {e}{Colors.RESET}")
        
        return alerts
    
    def _analyze_windows_users(self) -> List[Alert]:
        """Analyze Windows users"""
        alerts = []
        
        try:
            # Use net user command to get user list
            result = subprocess.run(['net', 'user'], capture_output=True, text=True, timeout=10)
            
            if result.stdout:
                lines = result.stdout.split('\n')
                user_section = False
                for line in lines:
                    line = line.strip()
                    if 'User accounts' in line:
                        user_section = True
                        continue
                    if user_section and line and '---' not in line and '\\' not in line:
                        username = line.split()[0] if ' ' in line else line
                        
                        # Check for suspicious usernames
                        for suspicious in self.suspicious_users:
                            if suspicious in username.lower():
                                alert = Alert(
                                    timestamp=datetime.now().isoformat(),
                                    severity=Severity.WARNING,
                                    source="User Analysis",
                                    indicator=username,
                                    description="Suspicious Windows username detected",
                                    evidence={
                                        'username': username,
                                        'reason': 'Matches suspicious pattern'
                                    },
                                    correlation_id=f"WIN_USER_{username}"
                                )
                                alerts.append(alert)
        
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Windows user analysis error: {e}{Colors.RESET}")
        
        return alerts
    
    def _analyze_login_sessions(self) -> List[Alert]:
        """Analyze current login sessions"""
        alerts = []
        
        try:
            if platform.system() == "Windows":
                # Use query session on Windows
                result = subprocess.run(['query', 'session'], capture_output=True, text=True, timeout=10)
                if result.stdout:
                    lines = result.stdout.split('\n')[2:]  # Skip headers
                    for line in lines:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 3:
                                username = parts[0]
                                session_name = parts[1]
                                session_id = parts[2]
                                
                                if username not in ['SESSIONNAME', 'services', 'console']:
                                    alert = Alert(
                                        timestamp=datetime.now().isoformat(),
                                        severity=Severity.INFO,
                                        source="User Analysis",
                                        indicator=username,
                                        description=f"Active Windows session: {session_name}",
                                        evidence={
                                            'username': username,
                                            'session_name': session_name,
                                            'session_id': session_id
                                        },
                                        correlation_id=f"SESS_{username}_{session_id}"
                                    )
                                    alerts.append(alert)
            else:
                # Use who command on Unix/Linux
                result = subprocess.run(['who'], capture_output=True, text=True, timeout=10)
                if result.stdout:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 5:
                                username = parts[0]
                                terminal = parts[1]
                                login_time = ' '.join(parts[2:5])
                                
                                alert = Alert(
                                    timestamp=datetime.now().isoformat(),
                                    severity=Severity.INFO,
                                    source="User Analysis",
                                    indicator=username,
                                    description=f"Active login session",
                                    evidence={
                                        'username': username,
                                        'terminal': terminal,
                                        'login_time': login_time
                                    },
                                    correlation_id=f"LOGIN_{username}"
                                )
                                alerts.append(alert)
        
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Session analysis error: {e}{Colors.RESET}")
        
        return alerts

class FileSystemAnalyzer:
    """File system analysis - NO external dependencies"""
    
    def __init__(self, threat_intel: ThreatIntelligence):
        self.threat_intel = threat_intel
        
        # Suspicious directories to check
        self.suspicious_dirs = []
        if platform.system() == "Windows":
            self.suspicious_dirs = [
                os.environ.get('TEMP', 'C:\\Windows\\Temp'),
                os.environ.get('APPDATA', 'C:\\Users'),
                'C:\\Windows\\System32\\Tasks'
            ]
        else:
            self.suspicious_dirs = [
                '/tmp',
                '/var/tmp',
                '/dev/shm',
                '/root/.ssh'
            ]
        
        # Suspicious file extensions
        self.suspicious_extensions = ['.exe', '.dll', '.so', '.bin', '.sh', '.py', '.ps1']
    
    def analyze_filesystem(self) -> List[Alert]:
        """Analyze file system for suspicious files"""
        alerts = []
        
        print(f"{Colors.CYAN}[*] Analyzing file system for suspicious files...{Colors.RESET}")
        
        for directory in self.suspicious_dirs:
            if os.path.exists(directory):
                alerts.extend(self._scan_directory(directory))
        
        return alerts
    
    def _scan_directory(self, directory: str) -> List[Alert]:
        """Scan directory for suspicious files"""
        alerts = []
        
        try:
            for root, dirs, files in os.walk(directory, topdown=True):
                for file in files:
                    filepath = os.path.join(root, file)
                    
                    # Check for suspicious extensions
                    if any(file.endswith(ext) for ext in self.suspicious_extensions):
                        try:
                            # Get file stats
                            stat = os.stat(filepath)
                            file_size = stat.st_size
                            mod_time = datetime.fromtimestamp(stat.st_mtime)
                            
                            # Check if recently modified (within 24 hours)
                            time_diff = datetime.now() - mod_time
                            if time_diff.days < 1:
                                alert = Alert(
                                    timestamp=datetime.now().isoformat(),
                                    severity=Severity.WARNING,
                                    source="File System Analysis",
                                    indicator=file,
                                    description=f"Recently modified executable in {directory}",
                                    evidence={
                                        'file_path': filepath,
                                        'size': file_size,
                                        'modified_time': mod_time.isoformat(),
                                        'directory': directory
                                    },
                                    correlation_id=f"FILE_{hash(filepath) % 10000}"
                                )
                                alerts.append(alert)
                                
                        except OSError:
                            continue
                
                # Limit depth for performance
                if root.count(os.sep) - directory.count(os.sep) > 2:
                    dirs[:] = []  # Don't recurse deeper
        
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Error scanning {directory}: {e}{Colors.RESET}")
        
        return alerts

class AlertEngine:
    """Alert generation and reporting - NO external dependencies"""
    
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Alert statistics
        self.alert_stats = {
            'total': 0,
            'critical': 0,
            'warning': 0,
            'info': 0
        }
    
    def generate_alert(self, alert: Alert):
        """Generate and display alert"""
        # Color coding
        if alert.severity == Severity.CRITICAL:
            color = Colors.RED
            banner = f"{Colors.BG_RED}{Colors.BOLD} CRITICAL {Colors.RESET}"
        elif alert.severity == Severity.WARNING:
            color = Colors.YELLOW
            banner = f"{Colors.BG_YELLOW}{Colors.BOLD} WARNING {Colors.RESET}"
        else:
            color = Colors.GREEN
            banner = f"{Colors.BG_GREEN}{Colors.BOLD} INFO {Colors.RESET}"
        
        # Display alert
        print(f"\n{banner}")
        print(f"{color}├─ Time: {alert.timestamp}")
        print(f"├─ Source: {alert.source}")
        print(f"├─ Indicator: {alert.indicator}")
        print(f"├─ Description: {alert.description}")
        print(f"└─ Correlation ID: {alert.correlation_id}{Colors.RESET}")
        
        # Update statistics
        self.alert_stats['total'] += 1
        if alert.severity == Severity.CRITICAL:
            self.alert_stats['critical'] += 1
        elif alert.severity == Severity.WARNING:
            self.alert_stats['warning'] += 1
        else:
            self.alert_stats['info'] += 1
        
        # Log to file
        self._log_alert(alert)
    
    def _log_alert(self, alert: Alert):
        """Log alert to CSV and JSON"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # CSV logging
        csv_file = self.output_dir / f"alerts_{datetime.now().strftime('%Y%m%d')}.csv"
        file_exists = csv_file.exists()
        
        with open(csv_file, 'a', newline='') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(['timestamp', 'severity', 'source', 'indicator',
                               'description', 'correlation_id', 'evidence'])
            
            writer.writerow([
                alert.timestamp,
                alert.severity.value,
                alert.source,
                alert.indicator,
                alert.description,
                alert.correlation_id,
                json.dumps(alert.evidence)
            ])
        
        # JSON logging
        json_file = self.output_dir / f"alerts_{datetime.now().strftime('%Y%m%d')}.json"
        alert_data = {
            'timestamp': alert.timestamp,
            'severity': alert.severity.value,
            'source': alert.source,
            'indicator': alert.indicator,
            'description': alert.description,
            'correlation_id': alert.correlation_id,
            'evidence': alert.evidence
        }
        
        alerts_list = []
        if json_file.exists():
            try:
                with open(json_file, 'r') as f:
                    alerts_list = json.load(f)
            except:
                alerts_list = []
        
        alerts_list.append(alert_data)
        
        with open(json_file, 'w') as f:
            json.dump(alerts_list, f, indent=2)
    
    def generate_report(self, alerts: List[Alert]):
        """Generate summary report"""
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}THREATPULSE ANALYSIS REPORT{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        
        print(f"\n{Colors.BOLD}Summary Statistics:{Colors.RESET}")
        print(f"  {Colors.RED}● Critical alerts: {self.alert_stats['critical']}{Colors.RESET}")
        print(f"  {Colors.YELLOW}● Warning alerts: {self.alert_stats['warning']}{Colors.RESET}")
        print(f"  {Colors.GREEN}● Info alerts: {self.alert_stats['info']}{Colors.RESET}")
        print(f"  {Colors.BOLD}● Total alerts: {self.alert_stats['total']}{Colors.RESET}")
        
        # Group alerts by source
        source_groups = {}
        for alert in alerts:
            source = alert.source
            if source not in source_groups:
                source_groups[source] = []
            source_groups[source].append(alert)
        
        print(f"\n{Colors.BOLD}Alerts by Source:{Colors.RESET}")
        for source, source_alerts in source_groups.items():
            critical_count = sum(1 for a in source_alerts if a.severity == Severity.CRITICAL)
            warning_count = sum(1 for a in source_alerts if a.severity == Severity.WARNING)
            print(f"  {source}: {len(source_alerts)} alerts ({critical_count} critical, {warning_count} warnings)")
        
        print(f"\n{Colors.CYAN}Reports saved to: {self.output_dir}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")

class ThreatPulse:
    """Main SOC tool orchestrator - NO external dependencies"""
    
    def __init__(self):
        self.banner()
        
        # Initialize components
        self.threat_intel = ThreatIntelligence()
        self.network_analyzer = NetworkAnalyzer(self.threat_intel)
        self.log_analyzer = LogAnalyzer(self.threat_intel)
        self.process_analyzer = ProcessAnalyzer(self.threat_intel)
        self.user_analyzer = UserAnalyzer(self.threat_intel)
        self.filesystem_analyzer = FileSystemAnalyzer(self.threat_intel)
        self.alert_engine = AlertEngine()
    
    def banner(self):
        """Display startup banner"""
        banner_text = f"""
{Colors.CYAN}{'='*60}{Colors.RESET}
{Colors.BOLD}{Colors.RED}╔══════════════════════════════════════════════════════════╗{Colors.RESET}
{Colors.BOLD}{Colors.YELLOW}    ████████╗██╗  ██╗██████╗ ███████╗██████╗ ███████╗    {Colors.RESET}
{Colors.BOLD}{Colors.YELLOW}    ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗██╔════╝    {Colors.RESET}
{Colors.BOLD}{Colors.YELLOW}       ██║   ███████║██████╔╝█████╗  ██████╔╝███████╗    {Colors.RESET}
{Colors.BOLD}{Colors.YELLOW}       ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██╗╚════██║    {Colors.RESET}
{Colors.BOLD}{Colors.YELLOW}       ██║   ██║  ██║██║  ██║███████╗██║  ██║███████║    {Colors.RESET}
{Colors.BOLD}{Colors.YELLOW}       ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝    {Colors.RESET}
{Colors.BOLD}{Colors.YELLOW}                                                      {Colors.RESET}
{Colors.BOLD}{Colors.WHITE}         Professional SOC Threat Intelligence          {Colors.RESET}
{Colors.BOLD}{Colors.WHITE}                 Real-Time Correlation Engine           {Colors.RESET}
{Colors.BOLD}{Colors.RED}╚══════════════════════════════════════════════════════════╝{Colors.RESET}
{Colors.CYAN}{'='*60}{Colors.RESET}
{Colors.BOLD}{Colors.CYAN}Created by Hassan Hamisi{Colors.RESET}
{Colors.BOLD}{Colors.YELLOW}Version 2.0.0 | Zero Dependencies | Pure Python Standard Library{Colors.RESET}
{Colors.CYAN}{'='*60}{Colors.RESET}
        """
        print(banner_text)
    
    def run_full_scan(self):
        """Run complete threat analysis"""
        print(f"{Colors.CYAN}[*] Starting complete threat analysis...{Colors.RESET}")
        
        all_alerts = []
        
        # Update threat intelligence
        self.threat_intel.fetch_threat_feeds()
        
        # Run all analyzers
        print(f"\n{Colors.CYAN}[*] Running analysis modules...{Colors.RESET}")
        
        print(f"{Colors.CYAN}  [1/6] Network analysis...{Colors.RESET}")
        all_alerts.extend(self.network_analyzer.analyze_network())
        
        print(f"{Colors.CYAN}  [2/6] Log analysis...{Colors.RESET}")
        all_alerts.extend(self.log_analyzer.analyze_logs())
        
        print(f"{Colors.CYAN}  [3/6] Process analysis...{Colors.RESET}")
        all_alerts.extend(self.process_analyzer.analyze_processes())
        
        print(f"{Colors.CYAN}  [4/6] User analysis...{Colors.RESET}")
        all_alerts.extend(self.user_analyzer.analyze_users())
        
        print(f"{Colors.CYAN}  [5/6] File system analysis...{Colors.RESET}")
        all_alerts.extend(self.filesystem_analyzer.analyze_filesystem())
        
        print(f"{Colors.CYAN}  [6/6] Threat correlation...{Colors.RESET}")
        all_alerts.extend(self._correlate_threats(all_alerts))
        
        # Display all alerts
        for alert in all_alerts:
            self.alert_engine.generate_alert(alert)
        
        # Generate report
        self.alert_engine.generate_report(all_alerts)
        
        return all_alerts
    
    def run_network_scan(self):
        """Run network analysis only"""
        print(f"{Colors.CYAN}[*] Running network analysis...{Colors.RESET}")
        self.threat_intel.fetch_threat_feeds()
        alerts = self.network_analyzer.analyze_network()
        for alert in alerts:
            self.alert_engine.generate_alert(alert)
        return alerts
    
    def run_log_scan(self):
        """Run log analysis only"""
        print(f"{Colors.CYAN}[*] Running log analysis...{Colors.RESET}")
        self.threat_intel.fetch_threat_feeds()
        alerts = self.log_analyzer.analyze_logs()
        for alert in alerts:
            self.alert_engine.generate_alert(alert)
        return alerts
    
    def run_process_scan(self):
        """Run process analysis only"""
        print(f"{Colors.CYAN}[*] Running process analysis...{Colors.RESET}")
        alerts = self.process_analyzer.analyze_processes()
        for alert in alerts:
            self.alert_engine.generate_alert(alert)
        return alerts
    
    def run_user_scan(self):
        """Run user analysis only"""
        print(f"{Colors.CYAN}[*] Running user analysis...{Colors.RESET}")
        alerts = self.user_analyzer.analyze_users()
        for alert in alerts:
            self.alert_engine.generate_alert(alert)
        return alerts
    
    def run_filesystem_scan(self):
        """Run file system analysis only"""
        print(f"{Colors.CYAN}[*] Running file system analysis...{Colors.RESET}")
        alerts = self.filesystem_analyzer.analyze_filesystem()
        for alert in alerts:
            self.alert_engine.generate_alert(alert)
        return alerts
    
    def _correlate_threats(self, alerts: List[Alert]) -> List[Alert]:
        """Correlate alerts to identify multi-vector attacks"""
        correlated_alerts = []
        
        # Group alerts by IP address
        ip_alerts = {}
        for alert in alerts:
            evidence = alert.evidence
            # Extract IPs from evidence
            if 'foreign_ip' in evidence:
                ip = evidence['foreign_ip']
                if ip not in ip_alerts:
                    ip_alerts[ip] = []
                ip_alerts[ip].append(alert)
            elif 'extracted_ips' in evidence:
                for ip in evidence['extracted_ips']:
                    if ip not in ip_alerts:
                        ip_alerts[ip] = []
                    ip_alerts[ip].append(alert)
        
        # Create correlation alerts for IPs with multiple alerts
        for ip, ip_alert_list in ip_alerts.items():
            if len(ip_alert_list) > 1:
                alert = Alert(
                    timestamp=datetime.now().isoformat(),
                    severity=Severity.CRITICAL,
                    source="Threat Correlation",
                    indicator=ip,
                    description=f"Multiple threat indicators for IP {ip}",
                    evidence={
                        'ip_address': ip,
                        'alert_count': len(ip_alert_list),
                        'alert_types': [a.source for a in ip_alert_list],
                        'alerts': [a.description for a in ip_alert_list]
                    },
                    correlation_id=f"CORR_{ip}_{int(time.time())}"
                )
                correlated_alerts.append(alert)
        
        return correlated_alerts
    
    def real_time_monitoring(self, interval: int = 60):
        """Continuous real-time monitoring"""
        print(f"\n{Colors.CYAN}[*] Starting real-time monitoring...{Colors.RESET}")
        print(f"[*] Update interval: {interval} seconds")
        print(f"[*] Press Ctrl+C to stop{Colors.RESET}")
        
        cycle = 0
        
        # Initial threat intelligence update
        self.threat_intel.fetch_threat_feeds()
        
        try:
            while True:
                cycle += 1
                print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
                print(f"{Colors.CYAN}[*] Monitoring Cycle #{cycle}{Colors.RESET}")
                print(f"{Colors.CYAN}[*] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
                
                # Update threat intelligence every 5 cycles
                if cycle % 5 == 0:
                    self.threat_intel.fetch_threat_feeds()
                
                # Run real-time checks
                alerts = []
                alerts.extend(self.network_analyzer.analyze_network())
                alerts.extend(self.process_analyzer.analyze_processes())
                
                for alert in alerts:
                    self.alert_engine.generate_alert(alert)
                
                # Wait for next cycle
                for i in range(interval, 0, -1):
                    print(f"\r[+] Next scan in {i} seconds...", end="", flush=True)
                    time.sleep(1)
                print()
                    
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Monitoring stopped by user{Colors.RESET}")
    
    def print_usage(self):
        """Display usage information"""
        usage_text = f"""
{Colors.CYAN}Usage:{Colors.RESET}
  python threatpulse.py [OPTIONS]

{Colors.CYAN}Options:{Colors.RESET}
  --network         Analyze network connections and traffic
  --logs            Analyze system logs for suspicious activity
  --processes       Analyze running processes and services
  --users           Analyze user accounts and sessions
  --filesystem      Analyze file system for suspicious files
  --full-scan       Run complete threat analysis (all checks)
  --real-time       Start continuous real-time monitoring
  --interval N      Monitoring interval in seconds (default: 60)

{Colors.CYAN}Examples:{Colors.RESET}
  python threatpulse.py --full-scan
  python threatpulse.py --network --logs
  python threatpulse.py --real-time --interval 30
  python threatpulse.py --users --processes

{Colors.YELLOW}Note: Admin/root privileges recommended for full functionality{Colors.RESET}
{Colors.YELLOW}Note: NO external dependencies required - Pure Python Standard Library{Colors.RESET}
        """
        print(usage_text)

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print(f"\n{Colors.YELLOW}[!] Received shutdown signal{Colors.RESET}")
    shutdown_event.set()
    sys.exit(0)

def main():
    """Main entry point"""
    import argparse
    
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(
        description='ThreatPulse - SOC Threat Intelligence Tool (No Dependencies)',
        add_help=False  # Disable the default --help
    )
    
    parser.add_argument('--network', action='store_true', help='Analyze network connections')
    parser.add_argument('--logs', action='store_true', help='Analyze system logs')
    parser.add_argument('--processes', action='store_true', help='Analyze running processes')
    parser.add_argument('--users', action='store_true', help='Analyze user accounts and sessions')
    parser.add_argument('--filesystem', action='store_true', help='Analyze file system for suspicious files')
    parser.add_argument('--full-scan', action='store_true', help='Run complete threat analysis')
    parser.add_argument('--real-time', action='store_true', help='Start continuous monitoring')
    parser.add_argument('--interval', type=int, default=60, help='Monitoring interval in seconds')
    
    # Custom help argument
    parser.add_argument('-h', '--help', action='store_true', help='Show help message')
    
    args = parser.parse_args()
    
    # Create ThreatPulse instance
    tp = ThreatPulse()
    
    # Check if help requested
    if args.help or len(sys.argv) == 1:
        tp.print_usage()
        return
    
    # Execute based on arguments
    if args.full_scan:
        tp.run_full_scan()
    elif args.real_time:
        tp.real_time_monitoring(interval=args.interval)
    else:
        # Run selected modules
        all_alerts = []
        
        if args.network:
            print(f"{Colors.CYAN}[*] Updating threat intelligence...{Colors.RESET}")
            tp.threat_intel.fetch_threat_feeds()
            all_alerts.extend(tp.run_network_scan())
        
        if args.logs:
            print(f"{Colors.CYAN}[*] Updating threat intelligence...{Colors.RESET}")
            tp.threat_intel.fetch_threat_feeds()
            all_alerts.extend(tp.run_log_scan())
        
        if args.processes:
            all_alerts.extend(tp.run_process_scan())
        
        if args.users:
            all_alerts.extend(tp.run_user_scan())
        
        if args.filesystem:
            all_alerts.extend(tp.run_filesystem_scan())
        
        # Generate report if any scans were run
        if all_alerts:
            tp.alert_engine.generate_report(all_alerts)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Tool terminated by user{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Fatal error: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)