"""
Broken Link Checker
Checks for broken links and mixed content issues.
"""

import requests
from typing import Dict, List, Optional
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed


class LinkChecker:
    """Checks for broken links and mixed content."""
    
    def __init__(self, timeout: int = 5, max_workers: int = 20):
        """Initialize link checker."""
        self.timeout = timeout
        self.max_workers = max_workers
    
    def check_links(self, base_url: str, links: List[str]) -> Dict:
        """
        Check a list of links for broken links.
        
        Args:
            base_url: The base URL for resolving relative links
            links: List of URLs to check
            
        Returns:
            Dictionary with link check results
        """
        result = {
            'total_links': len(links),
            'valid_links': [],
            'broken_links': [],
            'redirects': [],
            'mixed_content': [],
            'security_issues': [],
            'warnings': []
        }
        
        def check_link(url):
            try:
                # Resolve relative URLs
                if not url.startswith(('http://', 'https://')):
                    url = self._resolve_url(base_url, url)
                
                response = requests.head(url, timeout=self.timeout, allow_redirects=True)
                
                # Check for mixed content
                if base_url.startswith('https://') and url.startswith('http://'):
                    return ('mixed_content', url, response.status_code)
                
                # Check status code
                if response.status_code >= 400:
                    return ('broken', url, response.status_code)
                elif 300 <= response.status_code < 400:
                    return ('redirect', url, response.status_code)
                else:
                    return ('valid', url, response.status_code)
                    
            except requests.RequestException as e:
                return ('broken', url, str(e))
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(check_link, link): link for link in links}
            
            for future in as_completed(futures):
                status, url, info = future.result()
                
                if status == 'valid':
                    result['valid_links'].append({'url': url, 'status': info})
                elif status == 'broken':
                    result['broken_links'].append({'url': url, 'error': str(info)})
                elif status == 'redirect':
                    result['redirects'].append({'url': url, 'status': info})
                elif status == 'mixed_content':
                    result['mixed_content'].append({'url': url, 'status': info})
        
        # Analyze results
        self._analyze_results(result)
        
        return result
    
    def _resolve_url(self, base_url: str, relative_url: str) -> str:
        """Resolve relative URL against base URL."""
        try:
            from urllib.parse import urljoin
            return urljoin(base_url, relative_url)
        except:
            return relative_url
    
    def _analyze_results(self, result: Dict):
        """Analyze link check results for security issues."""
        
        # Check for high broken link ratio
        if result['total_links'] > 0:
            broken_ratio = len(result['broken_links']) / result['total_links']
            if broken_ratio > 0.2:
                result['warnings'].append({
                    'severity': 'medium',
                    'issue': 'High Broken Link Ratio',
                    'description': f'{broken_ratio * 100:.1f}% of links are broken'
                })
        
        # Check for mixed content
        if result['mixed_content']:
            result['security_issues'].append({
                'severity': 'high',
                'issue': 'Mixed Content Detected',
                'description': f'{len(result["mixed_content"])} HTTP resources on HTTPS page'
            })
        
        # Check for excessive redirects
        if len(result['redirects']) > 5:
            result['warnings'].append({
                'severity': 'low',
                'issue': 'Many Redirects',
                'description': f'{len(result["redirects"])} links redirect'
            })
