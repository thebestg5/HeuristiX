import re
import hashlib
import base64
import functools
import json
import os
from urllib.parse import urlparse, parse_qs, urlencode
from typing import List, Dict, Any, Optional
import tldextract


@functools.lru_cache(maxsize=512)
def _cached_tldextract(url_or_domain: str):
    """Cached full tldextract result."""
    return tldextract.extract(url_or_domain)


def _cached_root_domain(url_or_domain: str) -> str:
    """Cached root domain extraction using tldextract."""
    extracted = _cached_tldextract(url_or_domain)
    if extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return extracted.domain or ""


class Threat:
    def __init__(self, threat_type: str, severity: str, file_path: str,
                 line_number: int, description: str, evidence: str = ""):
        self.threat_type = threat_type
        self.severity = severity
        self.file_path = file_path
        self.line_number = line_number
        self.description = description
        self.evidence = evidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.threat_type,
            "severity": self.severity,
            "file": self.file_path,
            "line": self.line_number,
            "description": self.description,
            "evidence": self.evidence,
        }


class MalwareDetector:
    """Detects malicious scripts, obfuscation, and known malware patterns."""

    # Security headers that should be present
    SECURITY_HEADERS = {
        'X-Frame-Options': {'critical': False, 'description': 'Missing X-Frame-Options header (clickjacking protection)'},
        'X-Content-Type-Options': {'critical': False, 'description': 'Missing X-Content-Type-Options header (MIME sniffing protection)'},
        'Content-Security-Policy': {'critical': True, 'description': 'Missing Content-Security-Policy header (XSS protection)'},
        'Strict-Transport-Security': {'critical': True, 'description': 'Missing Strict-Transport-Security header (HTTPS enforcement)'},
        'X-XSS-Protection': {'critical': False, 'description': 'Missing X-XSS-Protection header (XSS filter)'},
        'Referrer-Policy': {'critical': False, 'description': 'Missing Referrer-Policy header (privacy)'},
        'Permissions-Policy': {'critical': False, 'description': 'Missing Permissions-Policy header (feature control)'},
    }

    # Patterns run on ALL files (extremely specific, unlikely in legitimate minified bundles)
    # IMPROVED: Removed generic patterns that cause false positives (e.g., sendBeacon)
    # Focus on truly malicious patterns only
    JS_MALWARE_PATTERNS = [
        (r"new\s+ActiveXObject", "ActiveX exploitation", "critical"),
        (r"WScript\.Shell", "Windows script host exploitation", "critical"),
        (r"Shell\.Application", "Shell application exploitation", "critical"),
        (r"crypto\.[a-zA-Z]+\.(mine|hash)", "Cryptocurrency mining", "critical"),
        (r"CoinHive|coinhive|CryptoLoot|webminer", "Known crypto miner library", "critical"),
        (r"miner\.(start|stop|init)", "Crypto miner control", "critical"),
    ]

    # Patterns prone to false positives in minified/compiled libraries (skip minified)
    # IMPROVED: Removed many low-severity patterns that cause false positives on legitimate sites
    # Focus on high-risk obfuscation and injection patterns only
    JS_CONTEXT_PATTERNS = [
        (r"eval\s*\(", "Dynamic code execution (eval)", "high"),
        (r"Function\s*\(\s*['\"]\s*return\s+eval", "Obfuscated eval via Function constructor", "high"),
        (r"document\.location\s*=", "Forced redirect", "high"),
        (r"window\.location\s*=[^=]", "Forced redirect", "high"),
        (r"location\.href\s*=[^=]", "Forced redirect", "high"),
        (r"atob\s*\(", "Base64 decoding (possible obfuscation)", "medium"),
        (r"\\x[0-9a-fA-F]{2}", "Hex escaped characters", "medium"),
        (r"\\u[0-9a-fA-F]{4}", "Unicode escaped characters", "medium"),
        (r"String\.prototype\.split\s*\(\s*['\"].*['\"]\).*\.reverse", "String reversal obfuscation", "high"),
        (r"createElement\s*\(\s*['\"]script['\"]", "Dynamic script injection", "high"),
        (r"appendChild\s*\(\s*.*script", "Script DOM injection", "high"),
        (r"insertBefore\s*\(\s*.*script", "Script DOM injection", "high"),
    ]

    # REMOVED: Credential-harvesting patterns from JS detector
    # These are now handled by PhishingDetector with proper context-aware checks
    # (requires HTML form + password field + suspicious domain)
    JS_CREDENTIAL_PATTERNS = []

    # Known malicious script hashes (MD5 examples for demonstration)
    KNOWN_MALWARE_HASHES = {
        "d41d8cd98f00b204e9800998ecf8427e": "Empty file (suspicious)",
    }

    # IMPROVED: Known malicious root domains (exact match only, no substring matching)
    MALICIOUS_ROOT_DOMAINS = [
        "coinhive.com", "jsecoin.com", "cryptoloot.com", "webmine.cz",
        "ppoi.org", "kdowqlpt.com", "trackers.online",
    ]

    # CDN whitelist for external payload check (legitimate sources)
    CDN_WHITELIST = [
        "github.com", "githubusercontent.com", "gitlab.com",
        "google.com", "gstatic.com", "googlesource.com",
        "microsoft.com", "microsoftazure.com", "azureedge.net",
        "amazonaws.com", "cloudflare.com", "cloudfront.net",
        "cdnjs.cloudflare.com", "unpkg.com", "jsdelivr.net",
        "npmjs.com", "pypi.org", "rubygems.org",
    ]

    def __init__(self):
        self.patterns = [(re.compile(p, re.IGNORECASE), desc, sev)
                         for p, desc, sev in self.JS_MALWARE_PATTERNS]
        self.context_patterns = [(re.compile(p, re.IGNORECASE), desc, sev)
                                 for p, desc, sev in self.JS_CONTEXT_PATTERNS]
        self.credential_patterns = [(re.compile(p, re.IGNORECASE), desc, sev)
                                  for p, desc, sev in self.JS_CREDENTIAL_PATTERNS]
        # IMPROVED: No longer using regex patterns for domains - using exact root domain matching

    @staticmethod
    def _is_minified_bundle(content: str, file_path: str) -> bool:
        """Heuristic: minified bundles have very long lines and known names."""
        fname = file_path.lower()
        if any(k in fname for k in ["bundle", "chunk", "vendor", "min.js", "swagger-ui", "main.", "polyfill", "runtime", "commons"]):
            return True
        lines = content.splitlines()
        if not lines:
            return False
        avg = sum(len(l) for l in lines) / len(lines)
        # If average line length > 400 and total lines < 200, likely minified
        return avg > 400 and len(lines) < 200

    @staticmethod
    def _get_root_domain(url_or_domain: str) -> str:
        return _cached_root_domain(url_or_domain)

    @staticmethod
    def analyzeHeaders(headers: Dict[str, str], url: str = "") -> List[Threat]:
        """Analyze HTTP response headers for security issues."""
        threats = []
        headers_upper = {k.upper(): v for k, v in headers.items()}
        
        for header_name, config in MalwareDetector.SECURITY_HEADERS.items():
            if header_name.upper() not in headers_upper:
                severity = 'critical' if config['critical'] else 'medium'
                threats.append(Threat(
                    'Missing Security Header',
                    severity,
                    'HTTP Headers',
                    0,
                    config['description'],
                    f'URL: {url}'
                ))
        
        # Check for dangerous header values
        if 'X-Frame-Options'.upper() in headers_upper:
            value = headers_upper['X-Frame-Options'].upper()
            if value == 'ALLOWALL':
                threats.append(Threat(
                    'Insecure Header Value',
                    'high',
                    'HTTP Headers',
                    0,
                    'X-Frame-Options set to ALLOWALL (allows all framing)',
                    f'URL: {url}'
                ))
        
        if 'Content-Security-Policy'.upper() in headers_upper:
            csp = headers_upper['Content-Security-Policy'].upper()
            if 'UNSAFE-EVAL' in csp or 'UNSAFE-INLINE' in csp:
                threats.append(Threat(
                    'Weak CSP Policy',
                    'medium',
                    'HTTP Headers',
                    0,
                    'Content-Security-Policy allows unsafe-eval or unsafe-inline',
                    f'URL: {url}'
                ))
        
        # Check for server information disclosure
        if 'Server'.upper() in headers_upper:
            server = headers_upper['Server'].upper()
            if any(x in server for x in ['APACHE', 'NGINX', 'IIS', 'PHP', 'PYTHON']):
                threats.append(Threat(
                    'Information Disclosure',
                    'low',
                    'HTTP Headers',
                    0,
                    'Server header reveals technology stack',
                    f'Server: {headers_upper["Server"]}'
                ))
        
        return threats


class CustomRuleEngine:
    """Custom rule engine for user-defined detection patterns."""
    
    RULES_FILE = "custom_rules.json"
    
    def __init__(self):
        self.custom_rules = []
        self.load_rules()
    
    def load_rules(self):
        """Load custom rules from JSON file."""
        try:
            if os.path.exists(self.RULES_FILE):
                with open(self.RULES_FILE, 'r') as f:
                    data = json.load(f)
                    self.custom_rules = data.get('rules', [])
        except Exception as e:
            print(f"Error loading custom rules: {e}")
            self.custom_rules = []
    
    def save_rules(self):
        """Save custom rules to JSON file."""
        try:
            with open(self.RULES_FILE, 'w') as f:
                json.dump({'rules': self.custom_rules}, f, indent=2)
        except Exception as e:
            print(f"Error saving custom rules: {e}")
    
    def add_rule(self, pattern: str, description: str, severity: str, threat_type: str = "Custom Rule"):
        """Add a custom detection rule."""
        try:
            # Validate regex pattern
            re.compile(pattern)
            self.custom_rules.append({
                'pattern': pattern,
                'description': description,
                'severity': severity,
                'threat_type': threat_type
            })
            self.save_rules()
            return True
        except re.error as e:
            print(f"Invalid regex pattern: {e}")
            return False
    
    def remove_rule(self, index: int):
        """Remove a custom rule by index."""
        if 0 <= index < len(self.custom_rules):
            self.custom_rules.pop(index)
            self.save_rules()
            return True
        return False
    
    def analyze_content(self, content: str, file_path: str) -> List[Threat]:
        """Analyze content using custom rules."""
        threats = []
        lines = content.split('\n')
        
        for rule in self.custom_rules:
            try:
                pattern = re.compile(rule['pattern'], re.IGNORECASE)
                for line_num, line in enumerate(lines):
                    if pattern.search(line):
                        threats.append(Threat(
                            rule['threat_type'],
                            rule['severity'],
                            file_path,
                            line_num + 1,
                            rule['description'],
                            line.strip().substring(0, 200)
                        ))
            except re.error:
                continue
        
        return threats
    
    def get_rules(self) -> List[Dict]:
        """Get all custom rules."""
        return self.custom_rules


# Global custom rule engine instance
custom_rule_engine = CustomRuleEngine()


class MalwareDetector:
    """Detects malicious scripts, obfuscation, and known malware patterns."""

    # Security headers that should be present
    SECURITY_HEADERS = {
        'X-Frame-Options': {'critical': False, 'description': 'Missing X-Frame-Options header (clickjacking protection)'},
        'X-Content-Type-Options': {'critical': False, 'description': 'Missing X-Content-Type-Options header (MIME sniffing protection)'},
        'Content-Security-Policy': {'critical': True, 'description': 'Missing Content-Security-Policy header (XSS protection)'},
        'Strict-Transport-Security': {'critical': True, 'description': 'Missing Strict-Transport-Security header (HTTPS enforcement)'},
        'X-XSS-Protection': {'critical': False, 'description': 'Missing X-XSS-Protection header (XSS filter)'},
        'Referrer-Policy': {'critical': False, 'description': 'Missing Referrer-Policy header (privacy)'},
        'Permissions-Policy': {'critical': False, 'description': 'Missing Permissions-Policy header (feature control)'},
    }

    # Patterns run on ALL files (extremely specific, unlikely in legitimate minified bundles)
    # IMPROVED: Removed generic patterns that cause false positives (e.g., sendBeacon)
    # Focus on truly malicious patterns only
    JS_MALWARE_PATTERNS = [
        (r"new\s+ActiveXObject", "ActiveX exploitation", "critical"),
        (r"WScript\.Shell", "Windows script host exploitation", "critical"),
        (r"Shell\.Application", "Shell application exploitation", "critical"),
        (r"crypto\.[a-zA-Z]+\.(mine|hash)", "Cryptocurrency mining", "critical"),
        (r"CoinHive|coinhive|CryptoLoot|webminer", "Known crypto miner library", "critical"),
        (r"miner\.(start|stop|init)", "Crypto miner control", "critical"),
        (r"document\.write\s*\(\s*<iframe", "Hidden iframe injection", "high"),
        (r"<iframe[^>]*width\s*=\s*[\"']?0", "Zero-width iframe (hidden content)", "high"),
        (r"<iframe[^>]*height\s*=\s*[\"']?0", "Zero-height iframe (hidden content)", "high"),
        (r"<iframe[^>]*style\s*=\s*[\"'][^\"']*display\s*:\s*none", "Hidden iframe via CSS", "high"),
        (r"document\.cookie\s*=", "Cookie manipulation", "high"),
        (r"\.addEventListener\s*\(\s*[\"']keydown", "Keylogger detected", "critical"),
        (r"\.addEventListener\s*\(\s*[\"']keypress", "Keylogger detected", "critical"),
        (r"\.addEventListener\s*\(\s*[\"']keyup", "Keylogger detected", "critical"),
        (r"onkeydown\s*=", "Inline keylogger event", "critical"),
        (r"onkeypress\s*=", "Inline keylogger event", "critical"),
        (r"onkeyup\s*=", "Inline keylogger event", "critical"),
        (r"\.exec\s*\(", "Command execution attempt", "critical"),
        (r"\.spawn\s*\(", "Process spawn attempt", "critical"),
        (r"child_process", "Node.js child process (server-side)", "critical"),
        (r"require\s*\(\s*[\"']child_process", "Node.js child process import", "critical"),
        (r"require\s*\(\s*[\"']fs", "Node.js filesystem access", "critical"),
        (r"require\s*\(\s*[\"']net", "Node.js network access", "critical"),
        (r"require\s*\(\s*[\"']http", "Node.js HTTP module", "critical"),
        (r"require\s*\(\s*[\"']https", "Node.js HTTPS module", "critical"),
        (r"system\s*\(", "System command execution", "critical"),
        (r"exec\s*\(", "Command execution", "critical"),
        (r"passthru\s*\(", "Command execution", "critical"),
        (r"shell_exec\s*\(", "Command execution", "critical"),
        (r"backticks|`[^`]+`", "Shell command execution", "critical")
    ]

    # Secret detection patterns
    SECRET_PATTERNS = [
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "critical"),
        (r"aws_access_key_id\s*=\s*[\"']?[A-Z0-9]{20}", "AWS Access Key", "critical"),
        (r"aws_secret_access_key\s*=\s*[\"']?[A-Za-z0-9\/+=]{40}", "AWS Secret Key", "critical"),
        (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key", "critical"),
        (r"sk_live_[0-9a-zA-Z]{24}", "Stripe Live Secret Key", "critical"),
        (r"sk_test_[0-9a-zA-Z]{24}", "Stripe Test Secret Key", "high"),
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token", "critical"),
        (r"xoxb-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}", "Slack Bot Token", "critical"),
        (r"mongodb:\/\/[^\s\"']+", "MongoDB Connection String", "critical"),
        (r"mysql:\/\/[^\s\"']+", "MySQL Connection String", "critical"),
        (r"postgresql:\/\/[^\s\"']+", "PostgreSQL Connection String", "critical"),
        (r"redis:\/\/[^\s\"']+", "Redis Connection String", "critical"),
        (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "SSH Private Key", "critical"),
        (r"api[_-]?key\s*[:=]\s*[\"']?[a-zA-Z0-9]{32,}", "Generic API Key", "high"),
        (r"secret[_-]?key\s*[:=]\s*[\"']?[a-zA-Z0-9]{32,}", "Secret Key", "critical"),
        (r"password\s*[:=]\s*[\"'][^\"']{8,}", "Hardcoded password", "critical"),
    ]

    # WASM detection patterns
    WASM_PATTERNS = [
        (r"WebAssembly\.instantiate", "WebAssembly instantiation", "medium"),
        (r"WebAssembly\.instantiateStreaming", "WebAssembly streaming instantiation", "medium"),
        (r"new\s+WebAssembly", "WebAssembly object creation", "medium"),
        (r"\.wasm", "WebAssembly binary file reference", "medium"),
        (r"atob\([^)]*wasm", "Base64-encoded WASM (obfuscated)", "high"),
        (r"fetch.*\.wasm", "WASM file fetch", "medium"),
    ]

    def analyze_content(self, content: str, file_path: str, page_url: str = "") -> List[Threat]:
        is_minified = self._is_minified_bundle(content, file_path)
        seen = set()  # For duplicate removal
        
        # CRITICAL: Check if the PAGE being scanned is trusted
        # If the page is trusted (e.g., Wikipedia), skip obfuscation pattern detections
        # page_url is now passed explicitly from analyzer.py
        is_page_trusted = PhishingDetector._is_trusted_domain(page_url) if page_url else False
        
        # Extract target domain for external payload check
        target_domain = self._get_root_domain(page_url) if page_url else ""

        # Check known malware hashes (always check, even for trusted pages)
        file_hash = hashlib.md5(content.encode()).hexdigest()
        if file_hash in self.KNOWN_MALWARE_HASHES:
            key = ("Known Malware", file_path, file_hash)
            if key not in seen:
                seen.add(key)
                threats.append(Threat(
                    "Known Malware",
                    "critical",
                    file_path,
                    0,
                    f"File matches known malware signature: {self.KNOWN_MALWARE_HASHES[file_hash]}",
                    file_hash
                ))

        # Core patterns (safe even in minified code - always check)
        for line_num, line in enumerate(lines, start=1):
            for pattern, description, severity in self.patterns:
                if pattern.search(line):
                    # Skip ActiveX alerts for polyfill files (legitimate compatibility shims)
                    if description == "ActiveX exploitation" and "polyfill" in file_path.lower():
                        continue
                    key = ("Malicious Script", file_path, line_num, description)
                    if key not in seen:
                        seen.add(key)
                        threats.append(Threat(
                            "Malicious Script",
                            severity,
                            file_path,
                            line_num,
                            description,
                            line.strip()[:200]
                        ))

        # CRITICAL: Context patterns (unicode, hex escapes, etc.) - SKIP for trusted pages
        # Wikipedia uses encoded characters normally - should not flag as malicious
        if not is_minified and not is_page_trusted:
            for line_num, line in enumerate(lines, start=1):
                for pattern, description, severity in self.context_patterns:
                    if pattern.search(line):
                        key = ("Malicious Script", file_path, line_num, description)
                        if key not in seen:
                            seen.add(key)
                            threats.append(Threat(
                                "Malicious Script",
                                severity,
                                file_path,
                                line_num,
                                description,
                                line.strip()[:200]
                            ))

            # Credential keywords: also skip minified bundles and trusted pages
            for line_num, line in enumerate(lines, start=1):
                for pattern, description, severity in self.credential_patterns:
                    if pattern.search(line):
                        key = ("Malicious Script", file_path, line_num, description)
                        if key not in seen:
                            seen.add(key)
                            threats.append(Threat(
                                "Malicious Script",
                                severity,
                                file_path,
                                line_num,
                                description,
                                line.strip()[:200]
                            ))

        # IMPROVED: Check for suspicious domain references using exact root domain matching
        # Extract all URLs/domains from content and check exact root domain match
        url_pattern = re.compile(r'https?://[^\s<>"\'\)]+', re.IGNORECASE)
        for match in url_pattern.finditer(content):
            url = match.group(1) if match.groups() else match.group(0)
            root_domain = self._get_root_domain(url)
            if root_domain in self.MALICIOUS_ROOT_DOMAINS:
                line_num = content[:match.start()].count("\n") + 1
                key = ("Malicious Domain Reference", file_path, line_num, root_domain)
                if key not in seen:
                    seen.add(key)
                    threats.append(Threat(
                        "Malicious Domain Reference",
                        "critical",
                        file_path,
                        line_num,
                        f"Reference to known malicious domain: {root_domain}",
                        line.strip()[:200]
                    ))

        # Check for suspicious base64 blobs (skip in known minified bundles with long base64 sourcemaps)
        # Also skip for trusted pages
        if not is_minified and not is_page_trusted:
            for threat in self._check_base64_blobs(content, file_path):
                key = ("Obfuscated Payload", file_path, threat.line_number, threat.evidence[:50])
                if key not in seen:
                    seen.add(key)
                    threats.append(threat)

        # NEW: External Payload Check - detect links to .exe/.zip/.sh/.msi on different domains
        if target_domain:
            for threat in self._check_external_payloads(content, file_path, target_domain):
                key = ("External Payload", file_path, threat.line_number, threat.evidence[:100])
                if key not in seen:
                    seen.add(key)
                    threats.append(threat)

        # NEW: Sensitive Data Leak - check for TODO, API_KEY, PASSWORD comments
        for threat in self._check_sensitive_data_leaks(content, file_path):
            key = ("Sensitive Data Leak", file_path, threat.line_number, threat.description)
            if key not in seen:
                seen.add(key)
                threats.append(threat)

        return threats

    def _check_base64_blobs(self, content: str, file_path: str) -> List[Threat]:
        threats = []
        # Find large base64 strings (potential obfuscated payloads)
        # NEW: Also decode and re-scan for malicious content
        b64_pattern = re.compile(r"['\"]([A-Za-z0-9+/]{50,}={0,2})['\"]")
        for match in b64_pattern.finditer(content):
            snippet = match.group(1)
            line_num = content[:match.start()].count("\n") + 1
            # Try to decode the base64 with multiple fallbacks for padding errors
            decoded = None
            try:
                # First try strict validation
                padding = 4 - len(snippet) % 4
                if padding != 4:
                    snippet_padded = snippet + "=" * padding
                else:
                    snippet_padded = snippet
                decoded = base64.b64decode(snippet_padded, validate=True).decode('utf-8', errors='ignore')
            except:
                # Fallback: try lenient decode without validation (handles intentional padding corruption)
                try:
                    decoded = base64.b64decode(snippet, validate=False).decode('utf-8', errors='ignore')
                except:
                    decoded = None
            
            evidence = snippet[:100]
            description = "Obfuscated Base64 payload"
            
            # If decoded successfully, check for malicious content
            if decoded and len(decoded) > 20:
                # Check for URLs in decoded content
                url_match = re.search(r'https?://[^\s<>"\'\)]+', decoded)
                if url_match:
                    description += f" with decoded URL: {url_match.group(0)[:50]}"
                    evidence = decoded[:100]
                # Check for common malicious keywords
                elif any(kw in decoded.lower() for kw in ['eval', 'script', 'shell', 'exec', 'http']):
                    description += " with decoded suspicious content"
                    evidence = decoded[:100]
            
            threats.append(Threat(
                "Obfuscated Payload",
                "high",
                file_path,
                line_num,
                description,
                evidence
            ))
        return threats

    def _check_external_payloads(self, content: str, file_path: str, target_domain: str) -> List[Threat]:
        """Check for links to .exe, .zip, .sh, .msi, .iso, .img files on different domains."""
        threats = []
        # Pattern to match URLs ending in executable extensions (added .iso, .img per review)
        payload_pattern = re.compile(r'https?://[^\s<>"\'\)]+\.(exe|zip|sh|msi|dmg|pkg|apk|iso|img)', re.IGNORECASE)
        for match in payload_pattern.finditer(content):
            url = match.group(0)
            link_domain = self._get_root_domain(url)
            if link_domain and link_domain != target_domain:
                line_num = content[:match.start()].count("\n") + 1
                
                # Check if the link is to a whitelisted CDN (downgrade to LOW)
                is_cdn = any(whitelist in link_domain for whitelist in self.CDN_WHITELIST)
                severity = "low" if is_cdn else "critical"
                cdn_note = " (whitelisted CDN)" if is_cdn else ""
                
                threats.append(Threat(
                    "External Payload",
                    severity,
                    file_path,
                    line_num,
                    f"Link to executable file on external domain{cdn_note}: {link_domain}",
                    url[:150]
                ))
        return threats

    def _check_sensitive_data_leaks(self, content: str, file_path: str) -> List[Threat]:
        """Check for TODO, API_KEY, PASSWORD, and other sensitive developer comments."""
        threats = []
        sensitive_patterns = [
            (r'//\s*(TODO|FIXME|HACK|BUG)[:\s]', "Developer TODO/FIXME comment", "low"),
            (r'/\*\s*(TODO|FIXME|HACK|BUG)[:\s]', "Developer TODO/FIXME comment", "low"),
            (r'(API_KEY|APIKEY|API-KEY|SECRET_KEY|SECRET)[:\s=]', "Hardcoded API key or secret", "critical"),
            (r'(PASSWORD|PASSWD|PASSWORD)[:\s=]', "Hardcoded password reference", "critical"),
            (r'(PRIVATE_KEY|PRIVATE-KEY|RSA_PRIVATE)[:\s=]', "Hardcoded private key reference", "critical"),
            (r'(TOKEN|AUTH_TOKEN|JWT)[:\s=]', "Hardcoded authentication token", "high"),
            (r'(DATABASE_URL|DB_HOST|DB_PASSWORD)[:\s=]', "Hardcoded database credentials", "high"),
        ]
        
        # Placeholder patterns for passwords (downgrade to LOW if matched)
        password_placeholders = [
            'replaceme', 'replace_me', 'placeholder', 'example', 'test', 'demo',
            'changeme', 'change_me', 'your_password', 'yourpassword', 'secret',
            '123456', 'password', 'admin', 'root', 'pass', 'qwerty',
        ]
        
        lines = content.splitlines()
        for line_num, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped in ['}', ']', ')', '};']:
                continue
            # Skip lines that are just CSS or common non-sensitive patterns
            if line_stripped.startswith(('.', '#', '*')):
                continue
                
            for pattern, description, severity in sensitive_patterns:
                match = re.search(pattern, line_stripped, re.IGNORECASE)
                if match:
                    # Special handling for PASSWORD: check if it's a placeholder
                    actual_severity = severity
                    if 'PASSWORD' in match.group(0).upper():
                        # Extract the password value
                        value_match = re.search(r'[:\s=]\s*[\'"]?([^\'"\s,;]+)', line_stripped[match.end():])
                        if value_match:
                            password_value = value_match.group(1).lower()
                            if any(placeholder in password_value for placeholder in password_placeholders):
                                actual_severity = "low"
                                description += " (placeholder detected)"
                    
                    threats.append(Threat(
                        "Sensitive Data Leak",
                        actual_severity,
                        file_path,
                        line_num,
                        description,
                        line_stripped[:150]
                    ))
                    break  # Only flag once per line
        return threats


class PhishingDetector:
    """Detects phishing indicators, fake login forms, and brand impersonation."""
    
    # IMPROVED: Expanded trusted domains list to ~100 domains
    # Uses root domain matching (e.g., "wikipedia.org" matches "en.wikipedia.org")
    TRUSTED_DOMAINS = [
        # Core
        "wikipedia.org", "wikimedia.org", "wiktionary.org",
        "google.com", "youtube.com", "gmail.com", "googleapis.com",
        "github.com", "githubusercontent.com",
        "microsoft.com", "live.com", "office.com", "windows.com",
        "apple.com", "icloud.com",
        "amazon.com", "aws.amazon.com",
        "facebook.com", "instagram.com", "whatsapp.com",
        "twitter.com", "x.com",
        "netflix.com", "spotify.com",
        "linkedin.com",
        "paypal.com",

        # Dev / docs
        "mozilla.org", "developer.mozilla.org", "stackoverflow.com",
        "python.org", "pypi.org",
        "nodejs.org", "npmjs.com",
        "openai.com",
        "ruby-lang.org", "golang.org",
        "rust-lang.org", "crates.io",
        "php.net", "composer.io",
        "java.com", "maven.org",
        "npmjs.org", "bower.io",
        "jquery.com", "reactjs.org",
        "vuejs.org", "angular.io",
        "svelte.dev", "nextjs.org",
        "nuxt.com", "gatsbyjs.com",
        "electronjs.org", "deno.land",
        "bun.sh", "vitejs.dev",
        "tailwindcss.com", "bootstrap.com",
        "sass-lang.com", "lesscss.org",
        "typescriptlang.org", "babeljs.io",
        "webpack.js.org", "rollupjs.org",
        "parceljs.org", "esbuild.github.io",
        "jestjs.io", "cypress.io",
        "playwright.dev", "selenium.dev",
        "puppeteer.dev", "testing-library.com",
        "mdn.dev", "caniuse.com",
        "w3.org", "whatwg.org",
        "ecma-international.org",

        # Infrastructure / CDN
        "cloudflare.com", "cdnjs.com",
        "akamai.com", "fastly.com",
        "cloudfront.net", "azureedge.net",
        "edgekey.net", "llnwd.net",
        "incapdns.net", "akadns.net",
        "edgesuite.net", "footprint.net",
        "rackspace.com", "digitalocean.com",
        "linode.com", "vultr.com",
        "hetzner.com", "ovh.com",
        "scaleway.com", "upcloud.com",

        # News
        "bbc.com", "cnn.com", "nytimes.com",
        "reuters.com", "apnews.com",
        "theguardian.com", "washingtonpost.com",
        "wsj.com", "bloomberg.com",
        "ft.com", "economist.com",
        "npr.org", "pbs.org",

        # General safe
        "example.com", "example.org", "iana.org",
        "gnu.org", "mit.edu", "harvard.edu",
        "stanford.edu", "berkeley.edu",
        "cmu.edu", "caltech.edu",
        "ox.ac.uk", "cam.ac.uk",
        "ethz.ch", "epfl.ch",
        "uva.nl", "tue.nl",
        "kth.se", "dtu.dk",
        "aalto.fi", "tuni.fi",
        "ntnu.no", "uio.no",
        "ku.dk", "dtu.dk",
        "tum.de", "tu-darmstadt.de",
        "ust.hk", "cuhk.edu.hk",
        "nus.edu.sg", "ntu.edu.sg",
        "anu.edu.au", "unsw.edu.au",
        "utoronto.ca", "ubc.ca",
        "mcgill.ca", "uwaterloo.ca",
    ]
    
    # Official domains for brands (to avoid false positives)
    BRAND_OFFICIAL_DOMAINS = {
        "paypal": ["paypal.com", "paypalobjects.com"],
        "apple": ["apple.com", "icloud.com"],
        "microsoft": ["microsoft.com", "azure.com", "office.com", "live.com"],
        "google": ["google.com", "gmail.com", "youtube.com", "android.com"],
        "facebook": ["facebook.com", "instagram.com", "whatsapp.com"],
        "amazon": ["amazon.com", "aws.amazon.com"],
        "netflix": ["netflix.com"],
        "chase": ["chase.com"],
        "wells fargo": ["wellsfargo.com"],
        "citi": ["citi.com", "citibank.com"],
        "hsbc": ["hsbc.com"],
        "barclays": ["barclays.com"],
        "santander": ["santander.com"],
        "bbva": ["bbva.com"],
        "deutsche bank": ["deutschebank.com"],
        "ing": ["ing.com"],
        "bank of america": ["bankofamerica.com"],
        "jpmorgan": ["jpmorgan.com", "chase.com"],
        "capital one": ["capitalone.com"],
        "gmail": ["gmail.com", "google.com"],
        "yahoo": ["yahoo.com"],
        "outlook": ["outlook.com", "live.com", "microsoft.com"],
        "icloud": ["icloud.com", "apple.com"],
        "protonmail": ["protonmail.com", "proton.me"],
        "zoho mail": ["zoho.com"],
        "instagram": ["instagram.com", "facebook.com"],
        "x.com": ["x.com", "twitter.com"],
        "linkedin": ["linkedin.com"],
        "tiktok": ["tiktok.com"],
        "snapchat": ["snapchat.com"],
        "whatsapp": ["whatsapp.com", "facebook.com"],
        "telegram": ["telegram.org"],
        "signal": ["signal.org"],
        "discord": ["discord.com"],
        "reddit": ["reddit.com"],
        "pinterest": ["pinterest.com"],
        "wechat": ["wechat.com"],
        "vk": ["vk.com"],
        "yandex": ["yandex.com", "yandex.ru"],
        "baidu": ["baidu.com"],
        "alibaba": ["alibaba.com"],
        "aliexpress": ["aliexpress.com"],
        "taobao": ["taobao.com"],
        "protonmail": ["protonmail.com"],
        "onedrive": ["onedrive.com", "live.com"],
        "google drive": ["drive.google.com", "google.com"],
        "mega": ["mega.nz"],
        "nordvpn": ["nordvpn.com"],
        "expressvpn": ["expressvpn.com"],
        "mcafee": ["mcafee.com"],
        "norton": ["norton.com"],
        "kaspersky": ["kaspersky.com"],
        "avast": ["avast.com"],
        "avg": ["avg.com"],
        "bitdefender": ["bitdefender.com"],
        "malwarebytes": ["malwarebytes.com"],
        "lastpass": ["lastpass.com"],
        "1password": ["1password.com"],
        "dashlane": ["dashlane.com"],
        "bitwarden": ["bitwarden.com"],
        "roblox": ["roblox.com"],
        "minecraft": ["minecraft.net"],
        "fortnite": ["fortnite.com", "epicgames.com"],
        "valorant": ["valorant.com", "riotgames.com"],
        "league of legends": ["leagueoflegends.com", "riotgames.com"],
        "call of duty": ["callofduty.com", "activision.com"],
        "apex legends": ["apexlegends.com", "ea.com"],
        "overwatch": ["overwatch.com", "blizzard.com"],
        "battle.net": ["battle.net", "blizzard.com"],
        "ea.com": ["ea.com"],
        "ubisoft": ["ubisoft.com"],
        "playstation": ["playstation.com", "sony.com"],
        "xbox": ["xbox.com", "microsoft.com"],
        "nintendo": ["nintendo.com"],
        "tinder": ["tinder.com"],
        "bumble": ["bumble.com"],
        "hinge": ["hinge.co"],
        "match": ["match.com"],
        "eharmony": ["eharmony.com"],
        "okcupid": ["okcupid.com"],
        "indeed": ["indeed.com"],
        "glassdoor": ["glassdoor.com"],
        "monster": ["monster.com"],
        "coursera": ["coursera.org"],
        "udemy": ["udemy.com"],
        "edx": ["edx.org"],
        "khan academy": ["khanacademy.org"],
        "codecademy": ["codecademy.com"],
        "duolingo": ["duolingo.com"],
        "wix": ["wix.com"],
        "wordpress": ["wordpress.com"],
        "godaddy": ["godaddy.com"],
        "namecheap": ["namecheap.com"],
        "cloudflare": ["cloudflare.com"],
        "aws": ["aws.amazon.com", "amazonaws.com"],
        "azure": ["azure.com", "microsoft.com"],
        "gcp": ["cloud.google.com", "google.com"],
        "digitalocean": ["digitalocean.com"],
        "heroku": ["heroku.com"],
        "vercel": ["vercel.com"],
        "netlify": ["netlify.com"],
        "firebase": ["firebase.com", "google.com"],
        "mongodb": ["mongodb.com"],
        "salesforce": ["salesforce.com"],
        "hubspot": ["hubspot.com"],
        "zendesk": ["zendesk.com"],
        "zoho": ["zoho.com"],
        "stripe": ["stripe.com"],
        "square": ["squareup.com"],
        "wise": ["wise.com"],
        "revolut": ["revolut.com"],
        "n26": ["n26.com"],
        "monzo": ["monzo.com"],
        "cash app": ["cash.app", "squareup.com"],
        "venmo": ["venmo.com"],
        "zelle": ["zellepay.com"],
        "shopify": ["shopify.com"],
        "walmart": ["walmart.com"],
        "target": ["target.com"],
        "best buy": ["bestbuy.com"],
        "costco": ["costco.com"],
        "home depot": ["homedepot.com"],
        "lowes": ["lowes.com"],
        "uber": ["uber.com"],
        "lyft": ["lyft.com"],
        "airbnb": ["airbnb.com"],
        "booking": ["booking.com"],
        "expedia": ["expedia.com"],
        "american airlines": ["aa.com", "americanairlines.com"],
        "delta": ["delta.com"],
        "united airlines": ["united.com"],
        "fedex": ["fedex.com"],
        "ups": ["ups.com"],
        "dhl": ["dhl.com"],
        "usps": ["usps.com"],
        "disney": ["disney.com"],
        "disney plus": ["disneyplus.com"],
        "hulu": ["hulu.com"],
        "hbo": ["hbo.com"],
        "peacock": ["peacocktv.com"],
        "paramount": ["paramountplus.com"],
        "twitch": ["twitch.tv", "amazon.com"],
        "steam": ["steampowered.com"],
        "epic games": ["epicgames.com"],
        "riot games": ["riotgames.com"],
        "coinbase": ["coinbase.com"],
        "binance": ["binance.com"],
        "kraken": ["kraken.com"],
        "gemini": ["gemini.com"],
        "metamask": ["metamask.io"],
        "ledger": ["ledger.com"],
        "trezor": ["trezor.io"],
        "blockchain": ["blockchain.com"],
        "robinhood": ["robinhood.com"],
        "fidelity": ["fidelity.com"],
        "schwab": ["schwab.com"],
        "vanguard": ["vanguard.com"],
        "etrade": ["etrade.com"],
        "western union": ["westernunion.com"],
        "moneygram": ["moneygram.com"],
        "github": ["github.com"],
        "gitlab": ["gitlab.com"],
        "bitbucket": ["bitbucket.org"],
        "supabase": ["supabase.com"],
        "auth0": ["auth0.com"],
        "okta": ["okta.com"],
        "render": ["render.com"],
        "fly.io": ["fly.io"],
        "railway": ["railway.app"],
    }
    
    # Simplified brand keywords for domain-based detection only
    BRAND_KEYWORDS = list(BRAND_OFFICIAL_DOMAINS.keys())

    # Short brand tokens that commonly appear inside benign words; if the
    # domain contains any of these words the short-brand match is suppressed.
    EXCLUDED_WORDS = ['king', 'gaming', 'spring', 'ring', 'betting', 'playing']

    SUSPICIOUS_TLDS = [
        ".tk", ".ml", ".ga", ".cf", ".xyz", ".top",
        ".work", ".date", ".party", ".click", ".download",
        ".win", ".bid", ".loan", ".country", ".stream",
        ".gdn", ".trade", ".science", ".review", ".ninja",
        ".rocks", ".site", ".space", ".fun", ".life",
        ".today", ".press", ".host", ".ooo", ".buzz",
        ".cafe", ".chat", ".cheap", ".club"
    ]

    # IMPROVED: Removed keyword-based patterns that cause false positives
    # Focus on structural patterns and suspicious domains only
    PHISHING_PATTERNS = [
        (r"<form[^>]*action\s*=\s*['\"]https?://[^/'\"]*\.(tk|ml|ga|cf|top|xyz|work|date|party|link|click|download|racing|win|bid|loan|men|wang|country|stream|gdn|trade|science|review|ninja|rocks|site|online|space|website|tech|club|fun|store|shop|live|life|news|today|press|host|cloud|agency|digital|social|media|video|photography|gallery|graphics|design|zone|center|city|company|directory|domains|enterprises|holdings|industries|international|limited|management|network|partners|photos|productions|properties|recipes|rentals|repair|report|schule|services|shoes|singles|systems|tienda|tips|tools|town|toys|training|university|vacations|ventures|viajes|villas|vin|vip|vision|vodka|vote|voting|voyage|watch|webcam|website|wed|wedding|whoswho|wien|wiki|wine|works|wtf|ooo|bar|buzz|cab|cafe|camp|care|cash|catering|chat|cheap|church|claims|cleaning|clinic|clothing|coach|codes|coffee|community|computer|condos|construction|contractors|cool|coupons|credit|creditcard|cruises|dating|deals|delivery|democrat|dental|dentist|diamonds|direct|discount|doctor|dog|engineer|equipment|estate|events|exchange|expert|exposed|fail|farm|finance|financial|fish|fitness|flights|florist|football|forsale|foundation|fund|furniture|fyi|games|gifts|gives|glass|gmbh|gold|golf|gratis|green|gripe|group|guide|guitars|guru|haus|healthcare|help|hiphop|hockey|holiday|horse|hospital|house|immobilien|immo|ink|institute|insure|investments|jewelry|juegos|kaufen|kitchen|kiwi|land|lease|legal|lgbt|lighting|limo|link|loans|ltd|maison|marketing|mba|memorial|moda|mortgage|moscow|navy|nyc|one|organic|parts|photo|pics|pictures|place|plumbing|plus|poker|porn|promo|pub|qpon|rehab|reisen|rent|rentals|repair|republican|rest|restaurant|reviews|rich|rip|run|sale|salon|sarl|school|scot|sexy|shiksha|show|skin|soccer|software|soy|studio|style|supplies|supply|support|surf|surgery|tattoo|tax|taxi|team|technology|tennis|theater|theatre|tickets|tires|tours|town|toys|trade|trading|tube|vet|viajes|video|villas|vin|vip|vision|vodka|vote|voting|voyage|watch|webcam|website|wed|wedding|whoswho|wien|wiki|wine|works|wtf|xxx|yoga|yokohama|zone)['\"]", "Form submits to suspicious TLD", "high"),
        (r"<form[^>]*action\s*=\s*['\"]https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}['\"]", "Form submits to IP address", "high"),
    ]

    def __init__(self):
        self.patterns = [(re.compile(p, re.IGNORECASE), desc, sev)
                         for p, desc, sev in self.PHISHING_PATTERNS]
        # Pre-compute cleaned brand tokens to avoid repeated string ops per page
        self._brand_checks = [
            (brand, brand.lower().replace(" ", "").replace(".", ""))
            for brand in self.BRAND_KEYWORDS
        ]
        # Pre-compute excluded words for fast lookup
        self._excluded_set = set(self.EXCLUDED_WORDS)

    @staticmethod
    def _get_root_domain(url_or_domain: str) -> str:
        return _cached_root_domain(url_or_domain)

    @staticmethod
    def _is_trusted_domain(url_or_domain: str) -> bool:
        """Check if domain or any parent domain is in trusted list."""
        extracted = _cached_tldextract(url_or_domain)
        if extracted.suffix:
            # Check domain.suffix (e.g., mozilla.org) - the root domain
            root_domain = f"{extracted.domain}.{extracted.suffix}"
            if root_domain in PhishingDetector.TRUSTED_DOMAINS:
                return True
            # Check full domain (e.g., developer.mozilla.org)
            if extracted.subdomain:
                full_domain = f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}"
                if full_domain in PhishingDetector.TRUSTED_DOMAINS:
                    return True
        return False
    
    @staticmethod
    def _is_official_brand_domain(domain: str, brand: str) -> bool:
        """Check if domain is the official domain for a brand."""
        official_domains = PhishingDetector.BRAND_OFFICIAL_DOMAINS.get(brand.lower(), [])
        for official in official_domains:
            if official in domain:
                return True
        return False

    def analyze_page(self, content: str, url: str, file_path: str) -> List[Threat]:
        """
        IMPROVED: Context-aware phishing detection with trusted domain enforcement.
        - Domain-based brand impersonation (not content-based)
        - Context-aware credential harvesting (requires form + password + suspicious domain)
        - Enforces trusted domain logic at start: skips all detections for trusted domains
        - Uses root domain matching for trusted domain checks
        - Implements duplicate removal
        - Severity: CRITICAL for confirmed malicious, HIGH for clear phishing, MEDIUM for suspicious patterns, LOW for weak signals
        """
        # CRITICAL: Check trusted domain FIRST using root domain matching
        root_domain = self._get_root_domain(url)
        is_trusted = root_domain in self.TRUSTED_DOMAINS
        
        # For trusted domains, return empty list (skip all detections)
        if is_trusted:
            return []
        
        threats = []
        lines = content.splitlines()
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        extracted = _cached_tldextract(url)
        seen = set()  # For duplicate removal

        # Split domain into tokens (e.g. "paypal-login-secure.xyz" → ["paypal","login","secure","xyz"])
        # so short brands like "ing" don't match inside "king" or "gaming".
        domain_tokens = set(re.split(r"[^a-z0-9]", domain))

        # IMPROVED: Domain-based brand impersonation detection
        # Only flag if brand keyword appears as a distinct token in the domain
        # and the domain is NOT an official domain for that brand.
        for brand, brand_clean in self._brand_checks:
            if brand_clean not in domain_tokens:
                continue
            # For "ing", suppress if the domain also contains an excluded word
            # (king, gaming, spring, ring, betting, playing …)
            if brand_clean == "ing" and any(
                w in domain_tokens for w in self._excluded_set
            ):
                continue
            if not self._is_official_brand_domain(domain, brand):
                key = ("Brand Impersonation", file_path, brand)
                if key not in seen:
                    seen.add(key)
                    threats.append(Threat(
                        "Brand Impersonation",
                        "high",
                        file_path,
                        0,
                        f"Domain '{domain}' contains brand '{brand}' but is not an official domain. Possible phishing.",
                        domain
                    ))
                break  # Only flag once per domain

        # Check for suspicious TLD (MEDIUM: suspicious pattern with context)
        tld = f".{extracted.suffix.split('.')[-1]}" if extracted.suffix else ""
        if tld in self.SUSPICIOUS_TLDS:
            key = ("Suspicious TLD", file_path, tld)
            if key not in seen:
                seen.add(key)
                threats.append(Threat(
                    "Suspicious TLD",
                    "medium",  # MEDIUM: suspicious pattern with context
                    file_path,
                    0,
                    f"Domain uses suspicious TLD '{tld}' commonly used for phishing/scams.",
                    domain
                ))

        # Brand + TLD mismatch: HIGH if domain contains gov/bank/secure words
        # but the TLD is not .com, .org, or a local country-code suffix (e.g. .gob.ar)
        brand_tld_keywords = ["gob", "gov", "bank", "secure"]
        if any(kw in domain for kw in brand_tld_keywords):
            suffix = extracted.suffix.lower()
            suffix_last = suffix.split(".")[-1] if suffix else ""
            is_country_code = len(suffix_last) == 2
            if suffix not in ("com", "org") and not is_country_code:
                key = ("Brand + TLD Mismatch", file_path, domain)
                if key not in seen:
                    seen.add(key)
                    threats.append(Threat(
                        "Suspicious TLD",
                        "high",
                        file_path,
                        0,
                        f"Domain '{domain}' contains trusted brand term but uses non-standard TLD '{suffix}'.",
                        domain
                    ))

        # IMPROVED: Context-aware credential harvesting detection
        # Only flag if: HTML has <form> AND password field AND (suspicious domain OR HTTP)
        has_form = re.search(r"<form", content, re.IGNORECASE) is not None
        has_password = re.search(r"<input[^>]*type\s*=\s*['\"]password['\"]", content, re.IGNORECASE) is not None
        
        if has_form and has_password:
            # Check if domain is suspicious or using HTTP
            is_suspicious_domain = not is_trusted or tld in self.SUSPICIOUS_TLDS
            is_http = parsed.scheme == "http"
            
            if is_suspicious_domain or is_http:
                # HIGH: clear phishing context (password form on suspicious domain)
                severity = "high" if (is_suspicious_domain and is_http) else "medium"
                reason = []
                if is_http:
                    reason.append("HTTP (non-encrypted)")
                if is_suspicious_domain:
                    reason.append("suspicious/untrusted domain")
                key = ("Credential Harvesting Form", file_path, domain)
                if key not in seen:
                    seen.add(key)
                    threats.append(Threat(
                        "Credential Harvesting Form",
                        severity,
                        file_path,
                        0,
                        f"Password form on {' and '.join(reason)}. Possible credential harvesting.",
                        domain
                    ))

        # Check patterns line by line (MEDIUM/LOW: suspicious patterns)
        for line_num, line in enumerate(lines, start=1):
            for pattern, description, severity in self.patterns:
                if pattern.search(line):
                    key = ("Phishing Indicator", file_path, line_num, description)
                    if key not in seen:
                        seen.add(key)
                        threats.append(Threat(
                            "Phishing Indicator",
                            severity,  # MEDIUM: suspicious pattern with context
                            file_path,
                            line_num,
                            description,
                            line.strip()[:200]
                        ))

        # Check for password fields with external form actions (HIGH: clear phishing)
        form_action_pattern = re.compile(r"<form[^>]*action\s*=\s*['\"](.*?)['\"]", re.IGNORECASE)
        for match in form_action_pattern.finditer(content):
            action = match.group(1)
            action_parsed = urlparse(action)
            if action_parsed.netloc and action_parsed.netloc.lower() != domain:
                # Only flag if external domain is not trusted
                if not self._is_trusted_domain(action_parsed.netloc.lower()):
                    line_num = content[:match.start()].count("\n") + 1
                    key = ("Cross-Domain Form Action", file_path, line_num, action_parsed.netloc)
                    if key not in seen:
                        seen.add(key)
                        threats.append(Threat(
                            "Cross-Domain Form Action",
                            "high",  # HIGH: clear phishing (form data to external domain)
                            file_path,
                            line_num,
                            f"Form submits data to external domain: {action_parsed.netloc}",
                            action
                        ))

        return threats


class SuspiciousLinkDetector:
    """Detects suspicious, scam, or malicious links."""

    # IMPROVED: Keywords only flagged when combined with suspicious domain
    SUSPICIOUS_KEYWORDS = [
        "free", "winner", "prize", "lottery", "million", "click here",
        "limited time", "act now", "congratulations", "you won",
        "claim now", "urgent", "verify now", "account suspended",
        "download now", "install", "update required", "virus detected",
        "call now", "support", "refund", "gift", "bonus", "cash",
        "investment", "crypto", "bitcoin", "double your", "guaranteed",
        "risk free", "no obligation", "act immediately", "expires today"
    ]

    # IMPROVED: Strict URL shortener list for exact root domain matching
    URL_SHORTENERS = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
        "buff.ly", "is.gd", "short.link", "rebrand.ly", "bit.do"
    ]

    # Known malicious root domains (exact match only)
    MALICIOUS_ROOT_DOMAINS = [
        "coinhive.com", "jsecoin.com", "cryptoloot.com", "webmine.cz",
        "ppoi.org", "kdowqlpt.com", "trackers.online",
    ]

    URL_OBFUSCATION_PATTERNS = [
        # Only match @ in netloc (domain part), not in path/query (CSS @-rules, email addresses in paths)
        (r"https?://[^/@]*@[^/@]*", "URL contains @ in domain (credential trick)", "high"),
        (r"0x[0-9a-fA-F]+", "Hex encoded URL segment", "medium"),
        (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "IP address URL", "medium"),
        (r"https?://[^/]*\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}", "Dashed IP URL", "medium"),
        (r"https?://[^/]{100,}", "Excessively long subdomain (possible obfuscation)", "medium"),
    ]

    def __init__(self):
        self.url_patterns = [(re.compile(p, re.IGNORECASE), desc, sev)
                             for p, desc, sev in self.URL_OBFUSCATION_PATTERNS]

    @staticmethod
    def _get_root_domain(url_or_domain: str) -> str:
        return _cached_root_domain(url_or_domain)

    @staticmethod
    def _link_line_map(content: str, links: List[str]) -> Dict[str, int]:
        """Build a fast mapping from link to its first line number in content."""
        mapping: Dict[str, int] = {}
        for link in links:
            pos = content.find(link)
            if pos != -1:
                mapping[link] = content[:pos].count('\n') + 1
        return mapping

    def analyze_links(self, links: List[str], page_content: str, file_path: str, page_url: str = "") -> List[Threat]:
        """
        IMPROVED: Context-aware link analysis with strict trusted domain enforcement.
        - Keywords only flagged if PAGE is untrusted AND link domain is suspicious
        - URL obfuscation patterns skipped if PAGE is trusted
        - URL shorteners use exact root domain matching
        - Malicious domains use exact root domain matching
        - Duplicate removal with normalized URL keys
        """
        threats = []
        seen = set()  # For duplicate removal

        # Pre-compute line numbers for all links in one pass (much faster than
        # scanning lines repeatedly inside the per-link loop).
        link_lines = self._link_line_map(page_content, links)

        # CRITICAL: Check if the PAGE being scanned is trusted
        # If the page is trusted (e.g., Wikipedia), skip ALL keyword/obfuscation detections
        # Extract URL from file_path if page_url not provided
        if not page_url and file_path.startswith("http"):
            page_url = file_path
        is_page_trusted = PhishingDetector._is_trusted_domain(page_url) if page_url else False

        # Deferred keyword hits: only emit if >=2 distinct keywords appear on the page
        keyword_hits = []

        for link in links:
            parsed = urlparse(link)
            link_lower = link.lower()
            scheme = parsed.scheme.lower()
            root_domain = self._get_root_domain(link)

            # Normalize URL for duplicate detection (remove fragments, sort params)
            normalized_url = self._normalize_url(link)

            # Skip benign utility schemes from obfuscation checks
            is_utility_scheme = scheme in ("mailto", "tel", "sms", "javascript", "data")

            # CRITICAL: If PAGE is trusted, skip ALL keyword and obfuscation detections
            # Wikipedia = trusted domain -> ALL keyword detections must be ignored
            if is_page_trusted:
                # Only check for actual malicious domains (not keywords or obfuscation)
                if root_domain in self.MALICIOUS_ROOT_DOMAINS:
                    line_num = link_lines.get(link, 0)
                    key = ("Malicious Domain", normalized_url, root_domain)
                    if key not in seen:
                        seen.add(key)
                        threats.append(Threat(
                            "Malicious Domain",
                            "critical",
                            file_path,
                            line_num,
                            f"Link to known malicious domain: {root_domain}",
                            link
                        ))
                continue  # Skip all other checks for trusted pages

            # For untrusted pages, check suspicious keywords ONLY if link domain is suspicious
            is_suspicious_domain = (
                root_domain in self.MALICIOUS_ROOT_DOMAINS or
                root_domain in self.URL_SHORTENERS or
                not PhishingDetector._is_trusted_domain(link)
            )

            if is_suspicious_domain:
                for keyword in self.SUSPICIOUS_KEYWORDS:
                    if keyword in link_lower:
                        line_num = link_lines.get(link, 0)
                        keyword_hits.append((normalized_url, keyword, line_num, link))

            # IMPROVED: Check URL shorteners using exact root domain match
            if root_domain in self.URL_SHORTENERS:
                line_num = link_lines.get(link, 0)
                key = ("URL Shortener", normalized_url, root_domain)
                if key not in seen:
                    seen.add(key)
                    threats.append(Threat(
                        "URL Shortener",
                        "medium",
                        file_path,
                        line_num,
                        f"URL uses known shortener: {root_domain}",
                        link
                    ))

            # IMPROVED: Check malicious domains using exact root domain match
            if root_domain in self.MALICIOUS_ROOT_DOMAINS:
                line_num = link_lines.get(link, 0)
                key = ("Malicious Domain", normalized_url, root_domain)
                if key not in seen:
                    seen.add(key)
                    threats.append(Threat(
                        "Malicious Domain",
                        "critical",
                        file_path,
                        line_num,
                        f"Link to known malicious domain: {root_domain}",
                        link
                    ))

            # Check URL obfuscation patterns (skip utility schemes AND skip for trusted pages)
            # CRITICAL: @ in URL and other obfuscation patterns should NOT trigger on trusted pages
            if not is_utility_scheme and not is_page_trusted:
                for pattern, description, severity in self.url_patterns:
                    if pattern.search(link):
                        # Additional check for @: only flag if @ is in netloc (domain), not path
                        # This prevents false positives from CSS @-rules like @media, @keyframes
                        if "@" in description:
                            parsed_link = urlparse(link)
                            if "@" not in parsed_link.netloc:
                                continue  # @ is not in domain, skip this detection

                        line_num = link_lines.get(link, 0)
                        key = ("URL Obfuscation", normalized_url, description)
                        if key not in seen:
                            seen.add(key)
                            threats.append(Threat(
                                "URL Obfuscation",
                                severity,
                                file_path,
                                line_num,
                                description,
                                link
                            ))

            # Check mismatched href/display text (skip for trusted pages)
            if not is_page_trusted:
                for threat in self._check_mismatched_links(link, page_content, file_path):
                    key = ("Link Mismatch", normalized_url, threat.description)
                    if key not in seen:
                        seen.add(key)
                        threats.append(threat)

        # Only emit Suspicious Link Keyword alerts if >=2 distinct keywords found on page
        distinct_keywords = set(k for _, k, _, _ in keyword_hits)
        if len(distinct_keywords) >= 2:
            for normalized_url, keyword, line_num, link in keyword_hits:
                key = ("Suspicious Link Keyword", normalized_url, keyword)
                if key not in seen:
                    seen.add(key)
                    threats.append(Threat(
                        "Suspicious Link Keyword",
                        "medium",
                        file_path,
                        line_num,
                        f"URL contains suspicious keyword: '{keyword}'",
                        link
                    ))

        return threats

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Normalize URL for duplicate detection (remove fragments, sort params)."""
        parsed = urlparse(url)
        # Remove fragment
        normalized = parsed._replace(fragment="").geturl()
        # Sort query parameters
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            sorted_params = urlencode(sorted(params.items()), doseq=True)
            normalized = parsed._replace(query=sorted_params, fragment="").geturl()
        return normalized

    def _check_mismatched_links(self, link: str, content: str, file_path: str) -> List[Threat]:
        threats = []
        # Find <a> tags where href != visible text (common phishing technique)
        pattern = re.compile(r'<a[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>([^<]+)</a>', re.IGNORECASE)
        for match in pattern.finditer(content):
            href = match.group(1)
            text = match.group(2).strip()
            if href == link and text.lower().startswith(("http://", "https://")):
                href_domain = urlparse(href).netloc.lower()
                text_domain = urlparse(text).netloc.lower()
                if href_domain and text_domain and href_domain != text_domain:
                    line_num = content[:match.start()].count("\n") + 1
                    threats.append(Threat(
                        "Link Mismatch / Phishing",
                        "high",
                        file_path,
                        line_num,
                        f"Link displays '{text}' but points to '{href}'. Clickjacking/phishing technique.",
                        f"href={href}, text={text}"
                    ))
        return threats
