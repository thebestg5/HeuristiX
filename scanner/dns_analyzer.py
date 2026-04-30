"""
DNS Record Analyzer
Analyzes DNS records for suspicious configurations and security issues.
"""

import dns.resolver
import dns.exception
from typing import Dict, List, Optional
from ipaddress import ip_address, ip_network


class DNSAnalyzer:
    """Analyzes DNS records for security issues and suspicious configurations."""
    
    # Suspicious TLDs often used for phishing
    SUSPICIOUS_TLDS = [
        '.xyz', '.top', '.win', '.loan', '.club', '.online', '.site', '.racing',
        '.download', '.stream', '.gq', '.tk', '.ml', '.ga', '.cf'
    ]
    
    # Known malicious DNS providers
    MALICIOUS_DNS_PROVIDERS = [
        'ns1.suspended-domain.com',
        'ns2.suspended-domain.com',
        'parkingcrew.net',
        'above.com',
        'namecheap.com'
    ]
    
    @staticmethod
    def analyze_domain(domain: str) -> Dict:
        """
        Perform comprehensive DNS analysis for a domain.
        
        Args:
            domain: The domain to analyze
            
        Returns:
            Dictionary with DNS information and security issues
        """
        result = {
            'domain': domain,
            'records': {},
            'security_issues': [],
            'warnings': []
        }
        
        try:
            # Analyze various DNS record types
            DNSAnalyzer._analyze_a_records(result, domain)
            DNSAnalyzer._analyze_mx_records(result, domain)
            DNSAnalyzer._analyze_txt_records(result, domain)
            DNSAnalyzer._analyze_ns_records(result, domain)
            DNSAnalyzer._analyze_cname_records(result, domain)
            DNSAnalyzer._analyze_spf(result, domain)
            DNSAnalyzer._analyze_dmarc(result, domain)
            DNSAnalyzer._check_tld(result, domain)
            DNSAnalyzer._check_dnssec(result, domain)
            
        except Exception as e:
            result['error'] = str(e)
            result['security_issues'].append({
                'severity': 'medium',
                'issue': 'DNS Analysis Failed',
                'description': f'Could not analyze DNS records: {str(e)}'
            })
        
        return result
    
    @staticmethod
    def _analyze_a_records(result: Dict, domain: str):
        """Analyze A records for suspicious IPs."""
        try:
            answers = dns.resolver.resolve(domain, 'A')
            a_records = []
            for rdata in answers:
                ip = str(rdata)
                a_records.append(ip)
                
                # Check for suspicious IP ranges
                try:
                    ip_obj = ip_address(ip)
                    # Check if IP is in private range (suspicious for public sites)
                    if ip_obj.is_private:
                        result['security_issues'].append({
                            'severity': 'high',
                            'issue': 'Private IP Address',
                            'description': f'Domain resolves to private IP: {ip}'
                        })
                except ValueError:
                    pass
            
            result['records']['A'] = a_records
        except dns.exception.DNSException:
            result['warnings'].append({
                'severity': 'medium',
                'issue': 'No A Records',
                'description': 'Domain has no A records'
            })
    
    @staticmethod
    def _analyze_mx_records(result: Dict, domain: str):
        """Analyze MX records for email configuration."""
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            mx_records = []
            for rdata in answers:
                mx_records.append(f"{rdata.preference} {rdata.exchange}")
            
            result['records']['MX'] = mx_records
            
            if not mx_records:
                result['warnings'].append({
                    'severity': 'low',
                    'issue': 'No MX Records',
                    'description': 'Domain has no MX records (no email configured)'
                })
        except dns.exception.DNSException:
            result['warnings'].append({
                'severity': 'low',
                'issue': 'No MX Records',
                'description': 'Domain has no MX records'
            })
    
    @staticmethod
    def _analyze_txt_records(result: Dict, domain: str):
        """Analyze TXT records for SPF and other information."""
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            txt_records = []
            for rdata in answers:
                txt = ' '.join(rdata.strings).decode('utf-8')
                txt_records.append(txt)
            
            result['records']['TXT'] = txt_records
        except dns.exception.DNSException:
            pass
    
    @staticmethod
    def _analyze_ns_records(result: Dict, domain: str):
        """Analyze NS records for suspicious name servers."""
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            ns_records = []
            for rdata in answers:
                ns = str(rdata).lower()
                ns_records.append(ns)
                
                # Check for known malicious DNS providers
                for malicious in DNSAnalyzer.MALICIOUS_DNS_PROVIDERS:
                    if malicious in ns:
                        result['security_issues'].append({
                            'severity': 'high',
                            'issue': 'Suspicious DNS Provider',
                            'description': f'Domain uses suspicious DNS provider: {ns}'
                        })
            
            result['records']['NS'] = ns_records
        except dns.exception.DNSException:
            result['security_issues'].append({
                'severity': 'high',
                'issue': 'No NS Records',
                'description': 'Domain has no NS records (domain may be suspended)'
            })
    
    @staticmethod
    def _analyze_cname_records(result: Dict, domain: str):
        """Analyze CNAME records for redirects."""
        try:
            answers = dns.resolver.resolve(domain, 'CNAME')
            cname_records = []
            for rdata in answers:
                cname = str(rdata)
                cname_records.append(cname)
                
                # Check for suspicious CNAME targets
                if any(suspicious in cname.lower() for suspicious in ['suspended', 'parking', 'expired']):
                    result['security_issues'].append({
                        'severity': 'high',
                        'issue': 'Suspicious CNAME',
                        'description': f'Domain has suspicious CNAME: {cname}'
                    })
            
            result['records']['CNAME'] = cname_records
        except dns.exception.DNSException:
            pass
    
    @staticmethod
    def _analyze_spf(result: Dict, domain: str):
        """Analyze SPF record for email security."""
        txt_records = result['records'].get('TXT', [])
        spf_found = False
        
        for txt in txt_records:
            if txt.startswith('v=spf1'):
                spf_found = True
                if '-all' not in txt and '~all' not in txt:
                    result['security_issues'].append({
                        'severity': 'medium',
                        'issue': 'Weak SPF Policy',
                        'description': 'SPF record does not end with -all or ~all'
                    })
                break
        
        if not spf_found:
            result['warnings'].append({
                'severity': 'medium',
                'issue': 'No SPF Record',
                'description': 'Domain has no SPF record (email spoofing risk)'
            })
    
    @staticmethod
    def _analyze_dmarc(result: Dict, domain: str):
        """Analyze DMARC record for email security."""
        try:
            dmarc_domain = f'_dmarc.{domain}'
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            dmarc_found = False
            
            for rdata in answers:
                txt = ' '.join(rdata.strings).decode('utf-8')
                if txt.startswith('v=DMARC1'):
                    dmarc_found = True
                    if 'p=none' in txt:
                        result['warnings'].append({
                            'severity': 'medium',
                            'issue': 'Weak DMARC Policy',
                            'description': 'DMARC policy is set to none (no enforcement)'
                        })
                    break
            
            if not dmarc_found:
                result['warnings'].append({
                    'severity': 'medium',
                    'issue': 'No DMARC Record',
                    'description': 'Domain has no DMARC record'
                })
        except dns.exception.DNSException:
            result['warnings'].append({
                'severity': 'medium',
                'issue': 'No DMARC Record',
                'description': 'Domain has no DMARC record'
            })
    
    @staticmethod
    def _check_tld(result: Dict, domain: str):
        """Check if domain uses suspicious TLD."""
        domain_lower = domain.lower()
        for tld in DNSAnalyzer.SUSPICIOUS_TLDS:
            if domain_lower.endswith(tld):
                result['warnings'].append({
                    'severity': 'low',
                    'issue': 'Suspicious TLD',
                    'description': f'Domain uses TLD often associated with phishing: {tld}'
                })
                break
    
    @staticmethod
    def _check_dnssec(result: Dict, domain: str):
        """Check if DNSSEC is enabled."""
        try:
            answers = dns.resolver.resolve(domain, 'DNSKEY')
            result['records']['DNSSEC'] = True
        except dns.exception.DNSException:
            result['records']['DNSSEC'] = False
            result['warnings'].append({
                'severity': 'low',
                'issue': 'DNSSEC Not Enabled',
                'description': 'Domain does not have DNSSEC enabled'
            })
    
    @staticmethod
    def get_security_score(analysis_result: Dict) -> int:
        """
        Calculate a security score based on DNS analysis.
        
        Args:
            analysis_result: Result from analyze_domain() method
            
        Returns:
            Security score (0-100)
        """
        score = 100
        
        for issue in analysis_result.get('security_issues', []):
            severity = issue.get('severity', 'low')
            if severity == 'critical':
                score -= 30
            elif severity == 'high':
                score -= 20
            elif severity == 'medium':
                score -= 10
            elif severity == 'low':
                score -= 5
        
        for warning in analysis_result.get('warnings', []):
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
