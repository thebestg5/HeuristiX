"""
Content Security Policy (CSP) Analyzer
Analyzes CSP headers for security issues and misconfigurations.
"""

import re
from typing import Dict, List, Optional


class CSPAnalyzer:
    """Analyzes Content Security Policy for security issues."""
    
    # CSP directives that should be present
    RECOMMENDED_DIRECTIVES = [
        'default-src',
        'script-src',
        'style-src',
        'img-src',
        'connect-src',
        'font-src',
        'object-src',
        'media-src',
        'frame-src',
        'base-uri',
        'form-action',
        'frame-ancestors',
        'report-uri',
        'report-to'
    ]
    
    # Dangerous CSP keywords
    DANGEROUS_KEYWORDS = [
        'unsafe-eval',
        'unsafe-inline',
        'data:',
        '*',
        'http:',
        'ftp:'
    ]
    
    @staticmethod
    def analyze_csp(csp_string: str) -> Dict:
        """
        Analyze a Content Security Policy string.
        
        Args:
            csp_string: The CSP header value
            
        Returns:
            Dictionary with CSP analysis results
        """
        result = {
            'directives': {},
            'security_issues': [],
            'warnings': [],
            'score': 0
        }
        
        if not csp_string:
            result['security_issues'].append({
                'severity': 'critical',
                'issue': 'Missing CSP Header',
                'description': 'No Content-Security-Policy header found'
            })
            result['score'] = 0
            return result
        
        # Parse CSP directives
        directives = CSPAnalyzer._parse_csp(csp_string)
        result['directives'] = directives
        
        # Check for missing recommended directives
        for directive in CSPAnalyzer.RECOMMENDED_DIRECTIVES:
            if directive not in directives:
                if directive in ['default-src', 'script-src', 'object-src']:
                    result['security_issues'].append({
                        'severity': 'high',
                        'issue': f'Missing {directive} Directive',
                        'description': f'CSP is missing the {directive} directive'
                    })
                else:
                    result['warnings'].append({
                        'severity': 'low',
                        'issue': f'Missing {directive} Directive',
                        'description': f'CSP is missing the {directive} directive'
                    })
        
        # Analyze each directive
        for directive_name, directive_values in directives.items():
            issues = CSPAnalyzer._analyze_directive(directive_name, directive_values)
            result['security_issues'].extend(issues['security_issues'])
            result['warnings'].extend(issues['warnings'])
        
        # Calculate security score
        result['score'] = CSPAnalyzer._calculate_score(result)
        
        return result
    
    @staticmethod
    def _parse_csp(csp_string: str) -> Dict[str, List[str]]:
        """Parse CSP string into directives."""
        directives = {}
        
        # Split by semicolon
        parts = [p.strip() for p in csp_string.split(';')]
        
        for part in parts:
            if not part:
                continue
            
            # Split directive name from values
            if ' ' in part:
                directive_name, values = part.split(' ', 1)
                directive_name = directive_name.strip()
                values_list = [v.strip() for v in values.split()]
                directives[directive_name] = values_list
            else:
                directives[part.strip()] = []
        
        return directives
    
    @staticmethod
    def _analyze_directive(name: str, values: List[str]) -> Dict:
        """Analyze a single CSP directive."""
        result = {
            'security_issues': [],
            'warnings': []
        }
        
        # Check for dangerous keywords
        for value in values:
            for keyword in CSPAnalyzer.DANGEROUS_KEYWORDS:
                if keyword in value:
                    severity = 'critical' if keyword in ['unsafe-eval', 'unsafe-inline'] else 'high'
                    if name in ['script-src', 'object-src']:
                        result['security_issues'].append({
                            'severity': severity,
                            'issue': f'Dangerous Keyword in {name}',
                            'description': f'{name} contains {keyword}'
                        })
                    else:
                        result['warnings'].append({
                            'severity': 'medium',
                            'issue': f'Dangerous Keyword in {name}',
                            'description': f'{name} contains {keyword}'
                        })
        
        # Check for overly permissive policies
        if '*' in values:
            if name in ['script-src', 'object-src', 'default-src']:
                result['security_issues'].append({
                    'severity': 'critical',
                    'issue': f'Overly Permissive {name}',
                    'description': f'{name} allows all sources (*)'
                })
            else:
                result['warnings'].append({
                    'severity': 'medium',
                    'issue': f'Overly Permissive {name}',
                    'description': f'{name} allows all sources (*)'
                })
        
        # Check for data: URLs
        if 'data:' in values:
            if name in ['script-src', 'object-src']:
                result['security_issues'].append({
                    'severity': 'high',
                    'issue': f'Insecure Source in {name}',
                    'description': f'{name} allows data: URLs'
                })
        
        # Check for http: (non-HTTPS)
        if 'http:' in values:
            result['warnings'].append({
                'severity': 'medium',
                'issue': f'Insecure Protocol in {name}',
                'description': f'{name} allows http: (non-HTTPS) sources'
            })
        
        # Check for missing nonce or hash in script-src
        if name == 'script-src':
            has_nonce = any('nonce-' in v for v in values)
            has_hash = any('sha256-' in v or 'sha384-' in v or 'sha512-' in v for v in values)
            has_unsafe_inline = 'unsafe-inline' in values
            
            if not has_nonce and not has_hash and not has_unsafe_inline:
                result['warnings'].append({
                    'severity': 'low',
                    'issue': 'No Script Hashes or Nonces',
                    'description': 'script-src should use hashes or nonces instead of unsafe-inline'
                })
        
        # Check for frame-src vs child-src (deprecated)
        if name == 'child-src':
            result['warnings'].append({
                'severity': 'low',
                'issue': 'Deprecated Directive',
                'description': 'child-src is deprecated, use frame-src instead'
            })
        
        return result
    
    @staticmethod
    def _calculate_score(analysis_result: Dict) -> int:
        """Calculate CSP security score."""
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
