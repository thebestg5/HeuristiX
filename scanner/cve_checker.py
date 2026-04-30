"""
CVE Vulnerability Checker
Checks for known vulnerabilities in detected libraries and technologies.
"""

import requests
import re
from typing import Dict, List, Optional
from datetime import datetime, timedelta


class CVEChecker:
    """Checks for CVE vulnerabilities in detected technologies."""
    
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Common JavaScript libraries and their typical versions
    COMMON_LIBRARIES = {
        'jquery': {'name': 'jQuery', 'type': 'javascript'},
        'react': {'name': 'React', 'type': 'javascript'},
        'angular': {'name': 'Angular', 'type': 'javascript'},
        'vue': {'name': 'Vue.js', 'type': 'javascript'},
        'lodash': {'name': 'Lodash', 'type': 'javascript'},
        'moment': {'name': 'Moment.js', 'type': 'javascript'},
        'axios': {'name': 'Axios', 'type': 'javascript'},
        'bootstrap': {'name': 'Bootstrap', 'type': 'css'},
        'tailwind': {'name': 'Tailwind CSS', 'type': 'css'},
        'express': {'name': 'Express.js', 'type': 'nodejs'},
        'react-dom': {'name': 'React DOM', 'type': 'javascript'},
        'redux': {'name': 'Redux', 'type': 'javascript'},
        'webpack': {'name': 'Webpack', 'type': 'build'},
        'babel': {'name': 'Babel', 'type': 'build'},
    }
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize CVE checker with optional NVD API key."""
        self.api_key = api_key
        self.cache = {}
        self.cache_expiry = timedelta(hours=1)
    
    def detect_libraries(self, content: str) -> List[Dict]:
        """
        Detect JavaScript libraries from content.
        
        Args:
            content: HTML or JavaScript content
            
        Returns:
            List of detected libraries with versions
        """
        detected = []
        
        # Detect from script tags
        script_pattern = r'(?:src=["\']([^"\']+)|cdnjs\.cloudflare\.com/ajax/libs/([^/]+)/([^/]+)/)'
        matches = re.findall(script_pattern, content, re.IGNORECASE)
        
        for match in matches:
            url = match[0] if match[0] else match[1]
            for lib_key, lib_info in self.COMMON_LIBRARIES.items():
                if lib_key.lower() in url.lower():
                    # Try to extract version
                    version_match = re.search(r'/(\d+\.\d+\.\d+)', url)
                    version = version_match.group(1) if version_match else 'unknown'
                    detected.append({
                        'name': lib_info['name'],
                        'key': lib_key,
                        'version': version,
                        'url': url
                    })
                    break
        
        # Detect from package references
        for lib_key, lib_info in self.COMMON_LIBRARIES.items():
            if lib_key in content.lower():
                version_match = re.search(rf'{lib_key}[@=]["\']?([^\s"\'>,)]+)', content, re.IGNORECASE)
                version = version_match.group(1) if version_match else 'unknown'
                detected.append({
                    'name': lib_info['name'],
                    'key': lib_key,
                    'version': version,
                    'url': None
                })
        
        return detected
    
    def check_library_cves(self, library_name: str, version: str) -> List[Dict]:
        """
        Check for CVEs in a specific library version.
        
        Args:
            library_name: Name of the library
            version: Version of the library
            
        Returns:
            List of CVE vulnerabilities
        """
        cache_key = f"{library_name}:{version}"
        
        # Check cache
        if cache_key in self.cache:
            cached_data, cached_time = self.cache[cache_key]
            if datetime.now() - cached_time < self.cache_expiry:
                return cached_data
        
        try:
            # Search NVD API
            params = {
                'keywordSearch': f"{library_name} {version}",
                'resultsPerPage': 20
            }
            
            if self.api_key:
                params['apiKey'] = self.api_key
            
            response = requests.get(self.NVD_API_URL, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                cves = []
                
                for item in data.get('vulnerabilities', []):
                    cve = item.get('cve', {})
                    cve_id = cve.get('id', '')
                    description = cve.get('descriptions', [{}])[0].get('value', '')
                    metrics = cve.get('metrics', {})
                    
                    # Get CVSS score
                    cvss_score = 0
                    severity = 'unknown'
                    
                    if 'cvssMetricV31' in metrics:
                        cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore', 0)
                        severity = cvss_data.get('baseSeverity', 'unknown')
                    elif 'cvssMetricV2' in metrics:
                        cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore', 0)
                        severity = 'HIGH' if cvss_score >= 7 else 'MEDIUM' if cvss_score >= 4 else 'LOW'
                    
                    cves.append({
                        'id': cve_id,
                        'description': description,
                        'cvss_score': cvss_score,
                        'severity': severity,
                        'published': cve.get('published', ''),
                        'modified': cve.get('lastModified', '')
                    })
                
                # Cache results
                self.cache[cache_key] = (cves, datetime.now())
                return cves
            
        except Exception as e:
            print(f"Error checking CVEs for {library_name}: {e}")
        
        return []
    
    def analyze_content(self, content: str) -> Dict:
        """
        Analyze content for vulnerable libraries.
        
        Args:
            content: HTML or JavaScript content
            
        Returns:
            Dictionary with detected libraries and their CVEs
        """
        result = {
            'libraries': [],
            'vulnerabilities': [],
            'total_cvss_score': 0
        }
        
        libraries = self.detect_libraries(content)
        
        for lib in libraries:
            cves = self.check_library_cves(lib['name'], lib['version'])
            
            lib_data = {
                'name': lib['name'],
                'version': lib['version'],
                'url': lib['url'],
                'cves': cves,
                'vulnerable': len(cves) > 0
            }
            
            result['libraries'].append(lib_data)
            result['vulnerabilities'].extend(cves)
            
            # Calculate total CVSS score
            for cve in cves:
                result['total_cvss_score'] += cve.get('cvss_score', 0)
        
        return result
    
    def get_security_score(self, analysis_result: Dict) -> int:
        """
        Calculate security score based on CVE analysis.
        
        Args:
            analysis_result: Result from analyze_content() method
            
        Returns:
            Security score (0-100)
        """
        score = 100
        
        total_cvss = analysis_result.get('total_cvss_score', 0)
        num_cves = len(analysis_result.get('vulnerabilities', []))
        
        # Deduct points based on CVSS score
        score -= min(total_cvss, 50)
        
        # Additional deduction for number of vulnerabilities
        score -= min(num_cves * 5, 30)
        
        return max(0, score)
    
    def get_remediation_advice(self, library_name: str, version: str) -> List[str]:
        """
        Get remediation advice for a vulnerable library.
        
        Args:
            library_name: Name of the library
            version: Current version
            
        Returns:
            List of remediation steps
        """
        cves = self.check_library_cves(library_name, version)
        
        if not cves:
            return ['No known vulnerabilities for this version']
        
        advice = [
            f'Update {library_name} to the latest version',
            'Check the library\'s official website for security advisories',
            'Review the CVE details for specific mitigation steps'
        ]
        
        # Add specific advice based on severity
        for cve in cves:
            severity = cve.get('severity', 'unknown')
            if severity in ['CRITICAL', 'HIGH']:
                advice.append(f'URGENT: {cve["id"]} is {severity} severity - update immediately')
        
        return list(set(advice))  # Remove duplicates
