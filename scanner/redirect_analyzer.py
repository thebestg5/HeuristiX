"""
Redirect Chain Analyzer
Analyzes HTTP redirect chains for security issues.
"""

import requests
from typing import Dict, List, Optional
from urllib.parse import urlparse


class RedirectAnalyzer:
    """Analyzes HTTP redirect chains."""
    
    MAX_REDIRECTS = 10
    
    @staticmethod
    def analyze_redirects(url: str, timeout: int = 10) -> Dict:
        """
        Analyze the redirect chain for a URL.
        
        Args:
            url: The URL to analyze
            timeout: Request timeout in seconds
            
        Returns:
            Dictionary with redirect chain analysis
        """
        result = {
            'url': url,
            'redirect_chain': [],
            'total_redirects': 0,
            'final_url': '',
            'security_issues': [],
            'warnings': []
        }
        
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=True)
            
            # Get redirect history
            history = response.history
            
            # Add initial URL
            result['redirect_chain'].append({
                'url': url,
                'status_code': None,
                'headers': {}
            })
            
            # Add each redirect
            for resp in history:
                result['redirect_chain'].append({
                    'url': resp.url,
                    'status_code': resp.status_code,
                    'headers': dict(resp.headers)
                })
            
            # Add final response
            result['redirect_chain'].append({
                'url': response.url,
                'status_code': response.status_code,
                'headers': dict(response.headers)
            })
            
            result['total_redirects'] = len(history)
            result['final_url'] = response.url
            
            # Analyze redirect chain
            RedirectAnalyzer._analyze_chain(result, history, response)
            
        except requests.RequestException as e:
            result['security_issues'].append({
                'severity': 'high',
                'issue': 'Redirect Analysis Failed',
                'description': f'Could not analyze redirects: {str(e)}'
            })
        
        return result
    
    @staticmethod
    def _analyze_chain(result: Dict, history: List, final_response):
        """Analyze the redirect chain for security issues."""
        
        # Check for too many redirects
        if len(history) > 5:
            result['security_issues'].append({
                'severity': 'medium',
                'issue': 'Excessive Redirects',
                'description': f'Chain has {len(history)} redirects (potential redirect loop)'
            })
        
        # Check for redirect loops
        urls = [url for url in [result['url']] + [r.url for r in history]]
        if len(urls) != len(set(urls)):
            result['security_issues'].append({
                'severity': 'critical',
                'issue': 'Redirect Loop Detected',
                'description': 'Redirect chain contains duplicate URLs (loop)'
            })
        
        # Check for HTTP to HTTPS redirects
        for i, resp in enumerate(history):
            if resp.url.startswith('http://') and (i + 1 < len(history) and history[i + 1].url.startswith('https://')):
                # This is good - upgrading to HTTPS
                pass
            elif resp.url.startswith('https://') and (i + 1 < len(history) and history[i + 1].url.startswith('http://')):
                result['security_issues'].append({
                    'severity': 'high',
                    'issue': 'HTTPS to HTTP Downgrade',
                    'description': f'Redirect from HTTPS to HTTP at step {i + 1}'
                })
        
        # Check for open redirects
        for i, resp in enumerate(history):
            location = resp.headers.get('Location', '')
            if location and '?' in location:
                # Check if redirect includes user input
                if any(param in location.lower() for param in ['url=', 'redirect=', 'next=', 'return=', 'goto=']):
                    result['security_issues'].append({
                        'severity': 'high',
                        'issue': 'Potential Open Redirect',
                        'description': f'Redirect at step {i + 1} may be an open redirect vulnerability'
                    })
        
        # Check for cross-domain redirects
        initial_domain = urlparse(result['url']).netloc
        for i, resp in enumerate(history):
            redirect_domain = urlparse(resp.url).netloc
            if redirect_domain != initial_domain:
                result['warnings'].append({
                    'severity': 'low',
                    'issue': 'Cross-Domain Redirect',
                    'description': f'Redirect to different domain at step {i + 1}: {redirect_domain}'
                })
        
        # Check for suspicious final domain
        final_domain = urlparse(final_response.url).netloc
        if final_domain != initial_domain:
            result['warnings'].append({
                'severity': 'medium',
                'issue': 'Final URL Different Domain',
                'description': f'Final URL is on different domain: {final_domain}'
            })
        
        # Check for URL shortening services
        shortener_domains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
            'is.gd', 'buff.ly', 'short.link', 'rebrand.ly'
        ]
        for i, resp in enumerate(history):
            domain = urlparse(resp.url).netloc
            if any(shortener in domain for shortener in shortener_domains):
                result['warnings'].append({
                    'severity': 'medium',
                    'issue': 'URL Shortener Detected',
                    'description': f'Redirect through URL shortener at step {i + 1}: {domain}'
                })
