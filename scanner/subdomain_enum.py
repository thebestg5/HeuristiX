"""
Subdomain Enumeration Module
Discovers subdomains through various techniques.
"""

import dns.resolver
import requests
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


class SubdomainEnumerator:
    """Enumerates subdomains for a given domain."""
    
    # Common subdomain wordlist
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'admin', 'blog', 'api', 'dev', 'staging',
        'test', 'prod', 'production', 'app', 'web', 'portal', 'dashboard',
        'secure', 'vpn', 'remote', 'cdn', 'static', 'assets', 'img', 'images',
        'video', 'media', 'shop', 'store', 'cart', 'checkout', 'account',
        'login', 'auth', 'sso', 'oauth', 'support', 'help', 'docs', 'wiki',
        'forum', 'community', 'news', 'blog', 'status', 'health', 'monitor',
        'metrics', 'logs', 'analytics', 'tracking', 'ads', 'promo', 'marketing',
        'm', 'mobile', 'beta', 'alpha', 'demo', 'sandbox', 'lab', 'internal',
        'intranet', 'extranet', 'partner', 'vendors', 'suppliers', 'clients',
        'email', 'smtp', 'pop', 'imap', 'ns1', 'ns2', 'dns', 'mx', 'relay',
        'gateway', 'proxy', 'firewall', 'ids', 'ips', 'siem', 'soc', 'security',
        'backup', 'db', 'database', 'mysql', 'postgres', 'mongo', 'redis',
        'elastic', 'search', 'solr', 'kibana', 'grafana', 'jenkins', 'gitlab',
        'github', 'bitbucket', 'jira', 'confluence', 'slack', 'teams', 'zoom'
    ]
    
    def __init__(self, max_workers: int = 10):
        """Initialize subdomain enumerator."""
        self.max_workers = max_workers
    
    def enumerate(self, domain: str) -> Dict:
        """
        Enumerate subdomains for a domain.
        
        Args:
            domain: The domain to enumerate (e.g., example.com)
            
        Returns:
            Dictionary with discovered subdomains and analysis
        """
        result = {
            'domain': domain,
            'subdomains': [],
            'total_found': 0,
            'security_issues': [],
            'warnings': []
        }
        
        # Remove www if present
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Method 1: DNS bruteforce
        dns_results = self._dns_bruteforce(domain)
        result['subdomains'].extend(dns_results)
        
        # Method 2: Certificate Transparency logs
        ct_results = self._certificate_transparency(domain)
        result['subdomains'].extend(ct_results)
        
        # Remove duplicates
        result['subdomains'] = list(set(result['subdomains']))
        result['total_found'] = len(result['subdomains'])
        
        # Analyze subdomains
        self._analyze_subdomains(result, domain)
        
        return result
    
    def _dns_bruteforce(self, domain: str) -> List[str]:
        """Bruteforce common subdomains via DNS."""
        found = []
        
        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{domain}"
                dns.resolver.resolve(full_domain, 'A')
                return full_domain
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in self.COMMON_SUBDOMAINS]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
        
        return found
    
    def _certificate_transparency(self, domain: str) -> List[str]:
        """Query Certificate Transparency logs for subdomains."""
        found = []
        
        try:
            # Use crt.sh API
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    if name_value:
                        # Split by newlines and clean
                        for name in name_value.split('\n'):
                            name = name.strip()
                            if name and name.endswith(domain) and name != domain:
                                # Remove wildcard
                                if not name.startswith('*.'):
                                    found.append(name)
        except Exception as e:
            pass
        
        return found
    
    def _analyze_subdomains(self, result: Dict, base_domain: str):
        """Analyze discovered subdomains for security issues."""
        for subdomain in result['subdomains']:
            # Check for forgotten/abandoned subdomains
            if any(keyword in subdomain for keyword in ['dev', 'test', 'staging', 'old', 'legacy', 'backup']):
                result['warnings'].append({
                    'severity': 'medium',
                    'issue': 'Potentially Forgotten Subdomain',
                    'description': f'Subdomain {subdomain} may be abandoned or forgotten'
                })
            
            # Check for admin/management interfaces
            if any(keyword in subdomain for keyword in ['admin', 'management', 'dashboard', 'console', 'panel']):
                result['security_issues'].append({
                    'severity': 'high',
                    'issue': 'Exposed Admin Interface',
                    'description': f'Subdomain {subdomain} may expose admin interface'
                })
            
            # Check for internal-only subdomains
            if any(keyword in subdomain for keyword in ['internal', 'intranet', 'private', 'corp']):
                result['security_issues'].append({
                    'severity': 'critical',
                    'issue': 'Exposed Internal Subdomain',
                    'description': f'Subdomain {subdomain} should be internal-only'
                })
