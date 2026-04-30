"""
Technology Stack Detector
Identifies the technology stack used by a website.
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urlparse


class TechDetector:
    """Detects the technology stack of a website."""
    
    # CMS signatures
    CMS_SIGNATURES = {
        'WordPress': [
            r'/wp-content/',
            r'/wp-includes/',
            r'wp-json',
            r'generator.*wordpress',
            r'wp-emoji'
        ],
        'Drupal': [
            r'/sites/default/',
            r'/modules/',
            r'/themes/',
            r'Drupal.settings',
            r'generator.*drupal'
        ],
        'Joomla': [
            r'/components/',
            r'/modules/',
            r'/templates/',
            r'generator.*joomla',
            r'/media/jui/'
        ],
        'Magento': [
            r'/skin/frontend/',
            r'/js/varien/',
            r'mage/',
            r'generator.*magento'
        ],
        'Shopify': [
            r'shopify.com',
            r'Shopify.theme',
            r'Shopify.checkout'
        ],
        'Squarespace': [
            r'squarespace.com',
            r'sqs-block'
        ],
        'Wix': [
            r'wix.com',
            r'wix-static'
        ]
    }
    
    # Framework signatures
    FRAMEWORK_SIGNATURES = {
        'React': [
            r'react',
            r'react-dom',
            r'_react',
            r'React.createElement',
            r'useState',
            r'useEffect'
        ],
        'Vue.js': [
            r'vue',
            r'vue-router',
            r'v-if',
            r'v-for',
            r'Vue\.'
        ],
        'Angular': [
            r'angular',
            r'ng-app',
            r'ng-controller',
            r'\$scope',
            r'angular\.module'
        ],
        'jQuery': [
            r'jquery',
            r'\$\.ajax',
            r'\.jquery',
            r'jQuery\.fn'
        ],
        'Bootstrap': [
            r'bootstrap',
            r'btn-',
            r'navbar-',
            r'carousel-'
        ],
        'Tailwind CSS': [
            r'tailwind',
            r'tw-',
            r'flex-',
            r'grid-'
        ],
        'Laravel': [
            r'laravel',
            r'/storage/',
            r'/public/'
        ],
        'Django': [
            r'csrfmiddlewaretoken',
            r'django',
            r'/static/'
        ],
        'Ruby on Rails': [
            r'rails',
            r'turbolinks',
            r'rails-ujs'
        ],
        'Express.js': [
            r'express',
            r'connect.sid'
        ],
        'Flask': [
            r'flask',
            r'werkzeug'
        ],
        'Spring Boot': [
            r'spring',
            r'boot'
        ],
        'ASP.NET': [
            r'asp\.net',
            r'__VIEWSTATE',
            r'__EVENTVALIDATION'
        ]
    }
    
    # Server signatures
    SERVER_SIGNATURES = {
        'Apache': [
            r'apache',
            r'mod_',
            r'.htaccess'
        ],
        'Nginx': [
            r'nginx',
            r'X-Powered-By.*nginx'
        ],
        'IIS': [
            r'iis',
            r'asp\.net',
            r'Server.*Microsoft-IIS'
        ],
        'Node.js': [
            r'node',
            r'express',
            r'connect'
        ],
        'Cloudflare': [
            r'cloudflare',
            r'cf-ray',
            r'cf-cache-status'
        ]
    }
    
    @staticmethod
    def detect_from_html(html: str, url: str = "") -> Dict:
        """
        Detect technology stack from HTML content.
        
        Args:
            html: HTML content
            url: The URL of the page
            
        Returns:
            Dictionary with detected technologies
        """
        result = {
            'cms': [],
            'frameworks': [],
            'servers': [],
            'libraries': [],
            'versions': {}
        }
        
        html_lower = html.lower()
        
        # Detect CMS
        for cms, patterns in TechDetector.CMS_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, html_lower, re.IGNORECASE):
                    if cms not in result['cms']:
                        result['cms'].append(cms)
                        TechDetector._extract_version(html, cms, result)
                    break
        
        # Detect Frameworks
        for framework, patterns in TechDetector.FRAMEWORK_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, html_lower, re.IGNORECASE):
                    if framework not in result['frameworks']:
                        result['frameworks'].append(framework)
                        TechDetector._extract_version(html, framework, result)
                    break
        
        # Detect Servers (from meta tags, headers would be separate)
        for server, patterns in TechDetector.SERVER_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, html_lower, re.IGNORECASE):
                    if server not in result['servers']:
                        result['servers'].append(server)
                    break
        
        # Detect common libraries
        libraries = TechDetector._detect_libraries(html)
        result['libraries'] = libraries
        
        return result
    
    @staticmethod
    def _detect_libraries(html: str) -> List[str]:
        """Detect common JavaScript libraries."""
        libraries = []
        html_lower = html.lower()
        
        library_patterns = {
            'jQuery': r'jquery[.-]\d+\.\d+\.\d+',
            'Bootstrap': r'bootstrap[.-]\d+\.\d+\.\d+',
            'Font Awesome': r'font-awesome[.-]\d+\.\d+\.\d+',
            'Moment.js': r'moment[.-]\d+\.\d+\.\d+',
            'Lodash': r'lodash[.-]\d+\.\d+\.\d+',
            'Axios': r'axios[.-]\d+\.\d+\.\d+',
            'Three.js': r'three[.-]\d+\.\d+\.\d+',
            'D3.js': r'd3[.-]\d+\.\d+\.\d+',
            'Chart.js': r'chart\.js[.-]\d+\.\d+\.\d+',
            'Leaflet': r'leaflet[.-]\d+\.\d+\.\d+',
            'Mapbox': r'mapbox[.-]\d+\.\d+\.\d+',
            'Swiper': r'swiper[.-]\d+\.\d+\.\d+',
            'AOS': r'aos[.-]\d+\.\d+\.\d+',
            'GSAP': r'gsap[.-]\d+\.\d+\.\d+',
            'Anime.js': r'anime[.-]\d+\.\d+\.\d+',
            'Typed.js': r'typed[.-]\d+\.\d+\.\d+',
            'Particles.js': r'particles[.-]\d+\.\d+\.\d+',
            'SweetAlert2': r'sweetalert2[.-]\d+\.\d+\.\d+',
            'Toastr': r'toastr[.-]\d+\.\d+\.\d+',
            'CountUp.js': r'countup[.-]\d+\.\d+\.\d+',
            'Waypoints': r'waypoints[.-]\d+\.\d+\.\d+',
            'Owl Carousel': r'owl\.carousel[.-]\d+\.\d+\.\d+',
            'Slick': r'slick[.-]\d+\.\d+\.\d+',
            'Isotope': r'isotope[.-]\d+\.\d+\.\d+',
            'Masonry': r'masonry[.-]\d+\.\d+\.\d+',
            'Lightbox': r'lightbox[.-]\d+\.\d+\.\d+',
            'Fancybox': r'fancybox[.-]\d+\.\d+\.\d+',
            'Magnific Popup': r'magnific-popup[.-]\d+\.\d+\.\d+',
            'PhotoSwipe': r'photoswipe[.-]\d+\.\d+\.\d+',
            'LazyLoad': r'lazyload[.-]\d+\.\d+\.\d+',
            'Intersection Observer': r'intersectionobserver',
            'Mutation Observer': r'mutationobserver'
        }
        
        for lib, pattern in library_patterns.items():
            if re.search(pattern, html_lower):
                libraries.append(lib)
        
        return libraries
    
    @staticmethod
    def _extract_version(html: str, tech: str, result: Dict):
        """Extract version information for a technology."""
        version_patterns = [
            rf'{tech.lower()}[/-](\d+\.\d+\.\d+)',
            rf'{tech.lower()}[/-](\d+\.\d+)',
            rf'version["\']?\s*[:=]\s*["\']?(\d+\.\d+\.\d+)["\']?',
            rf'generator["\']?\s*[:=]\s*["\']?{tech.lower()}\s*(\d+\.\d+\.\d+)["\']?'
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, html.lower())
            if match:
                result['versions'][tech] = match.group(1)
                break
