"""
HTTP Method Tester
Tests for unsafe HTTP methods and CORS misconfigurations.
"""

import requests
from typing import Dict, List, Optional


class HTTPMethodTester:
    """Tests HTTP methods for security issues."""
    
    # Unsafe HTTP methods
    UNSAFE_METHODS = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']
    
    # Safe methods to test
    SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS']
    
    @staticmethod
    def test_methods(url: str, timeout: int = 10) -> Dict:
        """
        Test various HTTP methods on a URL.
        
        Args:
            url: The URL to test
            timeout: Request timeout in seconds
            
        Returns:
            Dictionary with method test results
        """
        result = {
            'url': url,
            'allowed_methods': [],
            'forbidden_methods': [],
            'security_issues': [],
            'warnings': []
        }
        
        # Test safe methods
        for method in HTTPMethodTester.SAFE_METHODS:
            try:
                response = requests.request(method, url, timeout=timeout, allow_redirects=False)
                result['allowed_methods'].append({
                    'method': method,
                    'status_code': response.status_code
                })
            except requests.RequestException:
                result['forbidden_methods'].append(method)
        
        # Test unsafe methods
        for method in HTTPMethodTester.UNSAFE_METHODS:
            try:
                response = requests.request(method, url, timeout=timeout, allow_redirects=False)
                if response.status_code not in [405, 501]:
                    result['allowed_methods'].append({
                        'method': method,
                        'status_code': response.status_code
                    })
                    
                    # Flag unsafe methods
                    if method in ['PUT', 'DELETE', 'PATCH']:
                        result['security_issues'].append({
                            'severity': 'high',
                            'issue': f'Unsafe Method Allowed: {method}',
                            'description': f'{method} method is allowed - potential data modification risk'
                        })
                    elif method == 'TRACE':
                        result['security_issues'].append({
                            'severity': 'critical',
                            'issue': 'TRACE Method Enabled',
                            'description': 'TRACE method can lead to XST (Cross-Site Tracing) attacks'
                        })
                    elif method == 'CONNECT':
                        result['security_issues'].append({
                            'severity': 'high',
                            'issue': 'CONNECT Method Enabled',
                            'description': 'CONNECT method can be used as a proxy'
                        })
            except requests.RequestException:
                result['forbidden_methods'].append(method)
        
        # Test CORS
        HTTPMethodTester._test_cors(result, url, timeout)
        
        # Test Host header injection
        HTTPMethodTester._test_host_header(result, url, timeout)
        
        return result
    
    @staticmethod
    def _test_cors(result: Dict, url: str, timeout: int):
        """Test for CORS misconfigurations."""
        try:
            headers = {'Origin': 'http://evil.com'}
            response = requests.get(url, headers=headers, timeout=timeout)
            
            cors_header = response.headers.get('Access-Control-Allow-Origin', '')
            acah = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if cors_header == '*':
                result['warnings'].append({
                    'severity': 'medium',
                    'issue': 'Overly Permissive CORS',
                    'description': 'CORS allows any origin (*)'
                })
            elif cors_header == 'http://evil.com':
                result['security_issues'].append({
                    'severity': 'critical',
                    'issue': 'CORS Misconfiguration',
                    'description': 'CORS reflects arbitrary origin'
                })
            
            if acah == 'true' and cors_header == '*':
                result['security_issues'].append({
                    'severity': 'critical',
                    'issue': 'Dangerous CORS Configuration',
                    'description': 'CORS allows credentials with wildcard origin'
                })
        except requests.RequestException:
            pass
    
    @staticmethod
    def _test_host_header(result: Dict, url: str, timeout: int):
        """Test for Host header injection."""
        try:
            headers = {'Host': 'evil.com'}
            response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False)
            
            # Check if response reflects the injected host
            if 'evil.com' in response.text or 'evil.com' in str(response.headers):
                result['security_issues'].append({
                    'severity': 'high',
                    'issue': 'Host Header Injection',
                    'description': 'Server reflects arbitrary Host header'
                })
        except requests.RequestException:
            pass
