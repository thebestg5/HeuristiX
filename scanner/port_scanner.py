"""
Port Scanner Module
Scans for open ports on a target host.
"""

import socket
import threading
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


class PortScanner:
    """Scans for open ports on a target host."""
    
    # Common ports to scan
    COMMON_PORTS = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        993: 'IMAPS',
        995: 'POP3S',
        1433: 'MSSQL',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt',
        27017: 'MongoDB'
    }
    
    def __init__(self, timeout: int = 2, max_workers: int = 50):
        """Initialize port scanner."""
        self.timeout = timeout
        self.max_workers = max_workers
    
    def scan(self, host: str, ports: Optional[List[int]] = None) -> Dict:
        """
        Scan host for open ports.
        
        Args:
            host: The host to scan
            ports: List of ports to scan (default: common ports)
            
        Returns:
            Dictionary with scan results
        """
        result = {
            'host': host,
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'security_issues': [],
            'warnings': []
        }
        
        if ports is None:
            ports = list(self.COMMON_PORTS.keys())
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    return ('open', port)
                else:
                    return ('closed', port)
            except socket.timeout:
                return ('filtered', port)
            except Exception:
                return ('filtered', port)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(check_port, port): port for port in ports}
            
            for future in as_completed(futures):
                status, port = future.result()
                
                if status == 'open':
                    service = self.COMMON_PORTS.get(port, 'Unknown')
                    result['open_ports'].append({
                        'port': port,
                        'service': service
                    })
                elif status == 'closed':
                    result['closed_ports'].append(port)
                else:
                    result['filtered_ports'].append(port)
        
        # Analyze open ports
        self._analyze_ports(result)
        
        return result
    
    def _analyze_ports(self, result: Dict):
        """Analyze open ports for security issues."""
        
        for port_info in result['open_ports']:
            port = port_info['port']
            service = port_info['service']
            
            # Check for dangerous ports exposed
            if port in [21, 23, 135, 139, 445, 3389]:
                result['security_issues'].append({
                    'severity': 'high',
                    'issue': f'Dangerous Port Exposed: {port}',
                    'description': f'{service} (port {port}) should not be exposed to the internet'
                })
            
            # Check for database ports
            if port in [3306, 5432, 1433, 27017, 6379]:
                result['security_issues'].append({
                    'severity': 'critical',
                    'issue': f'Database Port Exposed: {port}',
                    'description': f'{service} (port {port}) is exposed - potential data breach risk'
                })
            
            # Check for non-standard HTTP ports
            if port in [8080, 8443, 8888]:
                result['warnings'].append({
                    'severity': 'low',
                    'issue': f'Non-Standard HTTP Port: {port}',
                    'description': f'{service} (port {port}) - may expose admin interfaces'
                })
        
        # Check for too many open ports
        if len(result['open_ports']) > 5:
            result['warnings'].append({
                'severity': 'medium',
                'issue': 'Many Open Ports',
                'description': f'{len(result["open_ports"])} ports open - reduce attack surface'
            })
