"""
Cookie Security Analyzer
Analyzes HTTP cookies for security issues and misconfigurations.
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urlparse


class CookieAnalyzer:
    """Analyzes cookies for security issues."""
    
    # Common cookie names that should be secure
    SECURE_COOKIE_NAMES = [
        'sessionid', 'session', 'sid', 'auth', 'token', 'jwt',
        'phpsessid', 'jsessionid', 'aspsessionid', 'user',
        'login', 'password', 'remember', 'auth_token', 'access_token'
    ]
    
    @staticmethod
    def analyze_cookies(cookie_string: str, url: str = "") -> Dict:
        """
        Analyze cookies from Set-Cookie header or document.cookie.
        
        Args:
            cookie_string: Cookie string from Set-Cookie header or document.cookie
            url: The URL the cookies are from
            
        Returns:
            Dictionary with cookie analysis results
        """
        result = {
            'cookies': [],
            'security_issues': [],
            'warnings': []
        }
        
        # Parse cookies
        cookies = CookieAnalyzer._parse_cookies(cookie_string)
        
        for cookie in cookies:
            cookie_analysis = CookieAnalyzer._analyze_single_cookie(cookie, url)
            result['cookies'].append(cookie_analysis)
            result['security_issues'].extend(cookie_analysis['security_issues'])
            result['warnings'].extend(cookie_analysis['warnings'])
        
        return result
    
    @staticmethod
    def _parse_cookies(cookie_string: str) -> List[Dict]:
        """Parse cookie string into individual cookies."""
        cookies = []
        
        # Handle Set-Cookie format (multiple cookies separated by newlines)
        if '\n' in cookie_string:
            for line in cookie_string.split('\n'):
                if line.strip():
                    cookies.extend(CookieAnalyzer._parse_cookie_line(line.strip()))
        else:
            # Handle document.cookie format (cookies separated by semicolons)
            cookies.extend(CookieAnalyzer._parse_cookie_line(cookie_string))
        
        return cookies
    
    @staticmethod
    def _parse_cookie_line(line: str) -> List[Dict]:
        """Parse a single cookie line."""
        cookies = []
        
        # Split by semicolon for multiple cookies
        parts = [p.strip() for p in line.split(';')]
        
        if not parts:
            return cookies
        
        # First part is name=value
        name_value = parts[0]
        if '=' in name_value:
            name, value = name_value.split('=', 1)
            cookie = {
                'name': name.strip(),
                'value': value.strip(),
                'attributes': {}
            }
            
            # Parse attributes
            for attr in parts[1:]:
                if '=' in attr:
                    attr_name, attr_value = attr.split('=', 1)
                    cookie['attributes'][attr_name.strip().lower()] = attr_value.strip()
                else:
                    cookie['attributes'][attr.strip().lower()] = True
            
            cookies.append(cookie)
        
        return cookies
    
    @staticmethod
    def _analyze_single_cookie(cookie: Dict, url: str) -> Dict:
        """Analyze a single cookie for security issues."""
        result = {
            'name': cookie['name'],
            'value': cookie['value'][:50] + '...' if len(cookie['value']) > 50 else cookie['value'],
            'attributes': cookie['attributes'],
            'security_issues': [],
            'warnings': []
        }
        
        attrs = cookie['attributes']
        name = cookie['name'].lower()
        
        # Check if cookie is sensitive
        is_sensitive = any(s in name for s in CookieAnalyzer.SECURE_COOKIE_NAMES)
        
        # Check for Secure flag
        if not attrs.get('secure'):
            if is_sensitive:
                result['security_issues'].append({
                    'severity': 'high',
                    'issue': 'Missing Secure Flag',
                    'description': f'Cookie "{cookie["name"]}" is sensitive but lacks Secure flag'
                })
            else:
                result['warnings'].append({
                    'severity': 'medium',
                    'issue': 'Missing Secure Flag',
                    'description': f'Cookie "{cookie["name"]}" lacks Secure flag'
                })
        
        # Check for HttpOnly flag
        if not attrs.get('httponly'):
            if is_sensitive:
                result['security_issues'].append({
                    'severity': 'high',
                    'issue': 'Missing HttpOnly Flag',
                    'description': f'Cookie "{cookie["name"]}" is sensitive but lacks HttpOnly flag (XSS risk)'
                })
            else:
                result['warnings'].append({
                    'severity': 'medium',
                    'issue': 'Missing HttpOnly Flag',
                    'description': f'Cookie "{cookie["name"]}" lacks HttpOnly flag (XSS risk)'
                })
        
        # Check for SameSite attribute
        samesite = attrs.get('samesite', '').lower()
        if not samesite:
            if is_sensitive:
                result['security_issues'].append({
                    'severity': 'high',
                    'issue': 'Missing SameSite Attribute',
                    'description': f'Cookie "{cookie["name"]}" lacks SameSite attribute (CSRF risk)'
                })
            else:
                result['warnings'].append({
                    'severity': 'medium',
                    'issue': 'Missing SameSite Attribute',
                    'description': f'Cookie "{cookie["name"]}" lacks SameSite attribute (CSRF risk)'
                })
        elif samesite == 'none' and not attrs.get('secure'):
            result['security_issues'].append({
                'severity': 'critical',
                'issue': 'SameSite=None without Secure',
                'description': f'Cookie "{cookie["name"]}" has SameSite=None but lacks Secure flag'
            })
        elif samesite == 'lax' and is_sensitive:
            result['warnings'].append({
                'severity': 'low',
                'issue': 'Weak SameSite Policy',
                'description': f'Cookie "{cookie["name"]}" uses SameSite=Lax (consider Strict for sensitive cookies)'
            })
        
        # Check for overly broad domain
        domain = attrs.get('domain', '')
        if domain and domain.startswith('.'):
            if is_sensitive:
                result['security_issues'].append({
                    'severity': 'medium',
                    'issue': 'Overly Broad Domain',
                    'description': f'Cookie "{cookie["name"]}" has wildcard domain: {domain}'
                })
        
        # Check for overly long expiration
        max_age = attrs.get('max-age', '')
        if max_age:
            try:
                max_age_int = int(max_age)
                if max_age_int > 31536000:  # More than 1 year
                    result['warnings'].append({
                        'severity': 'low',
                        'issue': 'Long Expiration Time',
                        'description': f'Cookie "{cookie["name"]}" has Max-Age > 1 year'
                    })
            except ValueError:
                pass
        
        # Check for session cookies without expiration
        if not attrs.get('expires') and not attrs.get('max-age') and is_sensitive:
            result['warnings'].append({
                'severity': 'low',
                'issue': 'Session Cookie',
                'description': f'Cookie "{cookie["name"]}" is a session cookie (clears on browser close)'
            })
        
        # Check for suspicious value patterns
        value = cookie['value']
        if len(value) > 100:
            result['warnings'].append({
                'severity': 'low',
                'issue': 'Large Cookie Value',
                'description': f'Cookie "{cookie["name"]}" has an unusually large value'
            })
        
        # Check for potential secrets in value
        if any(keyword in value.lower() for keyword in ['password', 'secret', 'token', 'key', 'auth']):
            result['security_issues'].append({
                'severity': 'critical',
                'issue': 'Sensitive Data in Cookie',
                'description': f'Cookie "{cookie["name"]}" may contain sensitive data'
            })
        
        return result
    
    @staticmethod
    def get_security_score(analysis_result: Dict) -> int:
        """
        Calculate security score based on cookie analysis.
        
        Args:
            analysis_result: Result from analyze_cookies() method
            
        Returns:
            Security score (0-100)
        """
        score = 100
        
        for issue in analysis_result.get('security_issues', []):
            severity = issue.get('severity', 'low')
            if severity == 'critical':
                score -= 25
            elif severity == 'high':
                score -= 15
            elif severity == 'medium':
                score -= 8
            elif severity == 'low':
                score -= 3
        
        for warning in analysis_result.get('warnings', []):
            severity = warning.get('severity', 'low')
            if severity == 'critical':
                score -= 12
            elif severity == 'high':
                score -= 8
            elif severity == 'medium':
                score -= 4
            elif severity == 'low':
                score -= 2
        
        return max(0, score)
