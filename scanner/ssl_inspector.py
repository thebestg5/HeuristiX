"""
SSL/TLS Certificate Inspector
Analyzes SSL/TLS certificates for security issues and misconfigurations.
"""

import ssl
import socket
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse


class SSLInspector:
    """Inspects SSL/TLS certificates for security issues."""
    
    # Weak cipher suites and protocols
    WEAK_PROTOCOLS = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
    WEAK_CIPHERS = [
        'RC4', 'DES', '3DES', 'MD5', 'SHA1', 'NULL', 'anon', 'EXPORT'
    ]
    
    # Trusted CAs (simplified list)
    TRUSTED_CAS = [
        'DigiCert', 'Let\'s Encrypt', 'Google Trust Services', 'Amazon',
        'Microsoft', 'Sectigo', 'GlobalSign', 'Comodo', 'GoDaddy'
    ]
    
    @staticmethod
    def inspect(hostname: str, port: int = 443) -> Dict:
        """
        Perform deep SSL/TLS certificate inspection.
        
        Args:
            hostname: The hostname to inspect
            port: The port (default 443)
            
        Returns:
            Dictionary with certificate information and security issues
        """
        result = {
            'hostname': hostname,
            'port': port,
            'certificate': {},
            'security_issues': [],
            'warnings': []
        }
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher = ssock.cipher()
                    
                    result['certificate'] = SSLInspector._parse_certificate(cert)
                    result['protocol'] = protocol
                    result['cipher'] = cipher
                    
                    # Check for security issues
                    SSLInspector._check_protocol(result, protocol)
                    SSLInspector._check_cipher(result, cipher)
                    SSLInspector._check_certificate_validity(result, cert)
                    SSLInspector._check_certificate_issuer(result, cert)
                    SSLInspector._check_certificate_chain(result, cert)
                    
        except Exception as e:
            result['error'] = str(e)
            result['security_issues'].append({
                'severity': 'high',
                'issue': 'SSL/TLS Connection Failed',
                'description': f'Could not establish SSL connection: {str(e)}'
            })
        
        return result
    
    @staticmethod
    def _parse_certificate(cert: dict) -> Dict:
        """Parse certificate information."""
        return {
            'subject': dict(x[0] for x in cert.get('subject', ())),
            'issuer': dict(x[0] for x in cert.get('issuer', ())),
            'version': cert.get('version'),
            'serial_number': cert.get('serialNumber'),
            'not_before': cert.get('notBefore'),
            'not_after': cert.get('notAfter'),
            'signature_algorithm': cert.get('signatureAlgorithm'),
        }
    
    @staticmethod
    def _check_protocol(result: Dict, protocol: str):
        """Check for weak SSL/TLS protocols."""
        if protocol in SSLInspector.WEAK_PROTOCOLS:
            result['security_issues'].append({
                'severity': 'critical',
                'issue': 'Weak SSL/TLS Protocol',
                'description': f'Server uses deprecated protocol: {protocol}'
            })
        elif protocol == 'TLSv1.2':
            result['warnings'].append({
                'severity': 'medium',
                'issue': 'Not Using TLS 1.3',
                'description': 'Server supports TLS 1.2 but not TLS 1.3 (latest)'
            })
    
    @staticmethod
    def _check_cipher(result: Dict, cipher: Tuple):
        """Check for weak cipher suites."""
        if not cipher:
            return
        
        cipher_name = cipher[0]
        for weak in SSLInspector.WEAK_CIPHERS:
            if weak in cipher_name:
                result['security_issues'].append({
                    'severity': 'high',
                    'issue': 'Weak Cipher Suite',
                    'description': f'Server uses weak cipher: {cipher_name}'
                })
                break
    
    @staticmethod
    def _check_certificate_validity(result: Dict, cert: dict):
        """Check certificate validity period."""
        try:
            not_after = cert.get('notAfter', '')
            if not_after:
                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (expiry_date - datetime.utcnow()).days
                
                if days_until_expiry < 0:
                    result['security_issues'].append({
                        'severity': 'critical',
                        'issue': 'Expired Certificate',
                        'description': f'Certificate expired {abs(days_until_expiry)} days ago'
                    })
                elif days_until_expiry < 30:
                    result['security_issues'].append({
                        'severity': 'high',
                        'issue': 'Certificate Expiring Soon',
                        'description': f'Certificate expires in {days_until_expiry} days'
                    })
                elif days_until_expiry < 90:
                    result['warnings'].append({
                        'severity': 'medium',
                        'issue': 'Certificate Expiring',
                        'description': f'Certificate expires in {days_until_expiry} days'
                    })
        except Exception as e:
            result['warnings'].append({
                'severity': 'low',
                'issue': 'Could Not Parse Certificate Expiry',
                'description': str(e)
            })
    
    @staticmethod
    def _check_certificate_issuer(result: Dict, cert: dict):
        """Check if certificate is from a trusted CA."""
        try:
            issuer = dict(x[0] for x in cert.get('issuer', ()))
            issuer_org = issuer.get('organizationName', '')
            
            is_trusted = any(ca.lower() in issuer_org.lower() for ca in SSLInspector.TRUSTED_CAS)
            
            if not is_trusted and issuer_org:
                result['warnings'].append({
                    'severity': 'medium',
                    'issue': 'Unrecognized Certificate Authority',
                    'description': f'Certificate issued by: {issuer_org}'
                })
        except Exception:
            pass
    
    @staticmethod
    def _check_certificate_chain(result: Dict, cert: dict):
        """Check for self-signed certificates."""
        try:
            subject = dict(x[0] for x in cert.get('subject', ()))
            issuer = dict(x[0] for x in cert.get('issuer', ()))
            
            if subject == issuer:
                result['security_issues'].append({
                    'severity': 'high',
                    'issue': 'Self-Signed Certificate',
                    'description': 'Certificate is self-signed (not trusted by default)'
                })
        except Exception:
            pass
    
    @staticmethod
    def get_security_score(inspection_result: Dict) -> int:
        """
        Calculate a security score based on SSL/TLS inspection.
        
        Args:
            inspection_result: Result from inspect() method
            
        Returns:
            Security score (0-100)
        """
        score = 100
        
        for issue in inspection_result.get('security_issues', []):
            severity = issue.get('severity', 'low')
            if severity == 'critical':
                score -= 30
            elif severity == 'high':
                score -= 20
            elif severity == 'medium':
                score -= 10
            elif severity == 'low':
                score -= 5
        
        for warning in inspection_result.get('warnings', []):
            severity = warning.get('severity', 'low')
            if severity == 'critical':
                score -= 15
            elif severity == 'high':
                score -= 10
            elif severity == 'medium':
                score -= 5
            elif severity == 'low':
                score -= 2
        
        return max(0, score)
