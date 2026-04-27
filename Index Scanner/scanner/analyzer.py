from typing import List, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from .crawler import WebCrawler, CrawlResult
from .detectors import MalwareDetector, PhishingDetector, SuspiciousLinkDetector, Threat
from .display import log_info, log_warning, log_error, log_threat


class FileInfo:
    def __init__(self, url: str, content_type: str, content: str, source: str):
        self.url = url
        self.content_type = content_type
        self.content = content
        self.source = source  # e.g., "page", "external_script", "inline"


class RiskScorer:
    """Calculates a 0-100 safety score from scan threats. Higher = safer."""

    # Per-threat deduction by severity level
    SEVERITY_PENALTY = {
        "critical": 15,
        "high": 10,
        "medium": 5,
        "low": 2,
    }

    # Category multiplier — more dangerous categories deduct extra
    CATEGORY_MULTIPLIER = {
        "known_malware": 1.5,
        "credential_harvesting": 1.5,
        "malicious_domain": 1.4,
        "brand_impersonation": 1.3,
        "phishing": 1.3,
        "obfuscated_js": 1.2,
        "forced_redirect": 1.2,
        "suspicious_tld": 1.1,
        "suspicious_link": 1.0,
        "url_obfuscation": 1.0,
        "other": 1.0,
    }

    # Threat type → category mapping (covers ALL threat types)
    _CATEGORY_MAP = {
        "Known Malware": "known_malware",
        "Malicious Script": "known_malware",
        "Malicious Domain Reference": "malicious_domain",
        "Malicious Domain": "malicious_domain",
        "Brand Impersonation": "brand_impersonation",
        "Credential Harvesting Form": "credential_harvesting",
        "Cross-Domain Form Action": "phishing",
        "Phishing Indicator": "phishing",
        "Link Mismatch / Phishing": "phishing",
        "Suspicious TLD": "suspicious_tld",
        "Suspicious Link Keyword": "suspicious_link",
        "URL Shortener": "suspicious_link",
        "URL Obfuscation": "url_obfuscation",
    }

    # Descriptions that map to specific categories
    _DESCRIPTION_MAP = {
        "Forced redirect": "forced_redirect",
        "Obfuscated Payload": "obfuscated_js",
        "Base64 decoding (possible obfuscation)": "obfuscated_js",
        "Hex escaped characters": "obfuscated_js",
        "Unicode escaped characters": "obfuscated_js",
        "Obfuscated eval via Function constructor": "obfuscated_js",
        "String reversal obfuscation": "obfuscated_js",
        "ActiveX exploitation": "known_malware",
    }

    @classmethod
    def score(cls, threats: List[Threat]) -> Dict[str, Any]:
        """Return safety score (0-100), breakdown, verdict, and confidence. Higher = safer."""
        # Group threats by category and severity
        category_data: Dict[str, Dict[str, int]] = {}  # cat → {severity: count}
        unmapped = 0
        for t in threats:
            cat = cls._CATEGORY_MAP.get(t.threat_type)
            if not cat:
                cat = cls._DESCRIPTION_MAP.get(t.description)
            if not cat:
                cat = "other"
                unmapped += 1
            if cat not in category_data:
                category_data[cat] = {}
            sev = t.severity if t.severity in cls.SEVERITY_PENALTY else "low"
            category_data[cat][sev] = category_data[cat].get(sev, 0) + 1

        # Calculate total deduction
        score = 100
        breakdown = {}
        for cat, sev_counts in category_data.items():
            multiplier = cls.CATEGORY_MULTIPLIER.get(cat, 1.0)
            cat_penalty = 0
            for sev, count in sev_counts.items():
                base = cls.SEVERITY_PENALTY.get(sev, 2)
                cat_penalty += round(base * count * multiplier)
            if cat_penalty > 0:
                breakdown[cat] = {"counts": sev_counts, "multiplier": multiplier, "points": -cat_penalty}
                score -= cat_penalty

        score = max(score, 0)
        verdict = ""
        if score > 70:
            verdict = "Safe"
        elif score > 50:
            verdict = "Moderate Risk"
        elif score > 25:
            verdict = "High Risk"
        elif score > 0:
            verdict = "Very Dangerous"
        else:
            verdict = "Dangerous Phishing Site"

        # Calculate HeuristiX Confidence Score based on behavioral flags
        # Behavioral flags are distinct threat categories that indicate malicious intent
        behavioral_categories = {
            "forced_redirect", "obfuscated_js", "credential_harvesting", 
            "brand_impersonation", "phishing", "malicious_domain", "known_malware"
        }
        triggered_behavioral = len([cat for cat in category_data.keys() if cat in behavioral_categories])
        
        # Confidence calculation:
        # 0-1 flags: Low confidence (30-50%)
        # 2 flags: Medium confidence (60-75%)
        # 3+ flags: High confidence (85-99%)
        if triggered_behavioral == 0:
            confidence = 0
            confidence_label = "No behavioral flags detected"
        elif triggered_behavioral == 1:
            confidence = 40
            confidence_label = "Low Probability of Malice"
        elif triggered_behavioral == 2:
            confidence = 70
            confidence_label = "Moderate Probability of Malice"
        else:
            confidence = 95 + min(triggered_behavioral - 3, 4)  # 95-99%
            confidence_label = "High Probability of Malice"

        return {
            "score": score,
            "verdict": verdict,
            "breakdown": breakdown,
            "max_score": 100,
            "confidence": {
                "score": confidence,
                "label": confidence_label,
                "behavioral_flags_triggered": triggered_behavioral,
            },
        }


class FileAnalyzer:
    """Orchestrates crawling and runs all detectors on discovered files."""

    def __init__(self, base_url: str, max_pages: int = 50, max_depth: int = 3, stealth_mode: bool = False):
        self.crawler = WebCrawler(base_url, max_pages=max_pages, max_depth=max_depth, stealth_mode=stealth_mode)
        self.malware_detector = MalwareDetector()
        self.phishing_detector = PhishingDetector()
        self.link_detector = SuspiciousLinkDetector()
        self.all_threats: List[Threat] = []
        self.files: Dict[str, FileInfo] = {}
        self.stats = {
            "pages_scanned": 0,
            "files_scanned": 0,
            "scripts_scanned": 0,
            "links_checked": 0,
            "threats_found": 0,
        }

    def scan(self) -> Dict[str, Any]:
        results = self.crawler.crawl()
        self.stats["pages_scanned"] = len(results)

        # Analyze each page
        for url, result in results.items():
            self._analyze_page(url, result)

        # Build summary
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        threat_types: Dict[str, int] = {}
        for t in self.all_threats:
            severity_counts[t.severity] = severity_counts.get(t.severity, 0) + 1
            threat_types[t.threat_type] = threat_types.get(t.threat_type, 0) + 1

        self.stats["threats_found"] = len(self.all_threats)

        # Compute risk score (0-100) with capped category weights to avoid false-positive inflation
        risk = RiskScorer.score(self.all_threats)

        # Collect all discovered links (deduplicated, sorted)
        all_links: Set[str] = set()
        for result in results.values():
            all_links.update(result.links)

        return {
            "base_url": self.crawler.base_url,
            "pages_scanned": self.stats["pages_scanned"],
            "files_scanned": self.stats["files_scanned"],
            "scripts_scanned": self.stats["scripts_scanned"],
            "links_checked": self.stats["links_checked"],
            "threats_found": len(self.all_threats),
            "severity_counts": severity_counts,
            "threat_types": threat_types,
            "threats": [t.to_dict() for t in self.all_threats],
            "crawl_errors": self.crawler.errors,
            "files": [{"url": k, "type": v.content_type, "source": v.source}
                      for k, v in self.files.items()],
            "all_links": sorted(all_links),
            "risk_score": risk,
        }

    def _analyze_page(self, url: str, result: CrawlResult):
        # Register page
        self.files[url] = FileInfo(url, result.content_type, result.content, "page")
        self.stats["files_scanned"] += 1
        self.stats["links_checked"] += len(result.links)
        log_info(f"Analyzing page: {url}")

        # 1. Malware detection on page content (pass page_url for trusted domain check)
        threats = self.malware_detector.analyze_content(result.content, url, page_url=url)
        for t in threats:
            log_threat(t.severity, f"[{t.threat_type}] {t.description} in {url}")
        self.all_threats.extend(threats)

        # 2. Phishing detection on page content
        threats = self.phishing_detector.analyze_page(result.content, url, url)
        for t in threats:
            log_threat(t.severity, f"[{t.threat_type}] {t.description} in {url}")
        self.all_threats.extend(threats)

        # 3. Suspicious link detection (pass page_url for trusted domain check)
        threats = self.link_detector.analyze_links(result.links, result.content, url, page_url=url)
        for t in threats:
            log_threat(t.severity, f"[{t.threat_type}] {t.description} in {url}")
        self.all_threats.extend(threats)

        # 4. Fetch external scripts concurrently (pass original page URL for trusted domain check)
        self._fetch_external_scripts(result.scripts, url)

        # 5. Analyze inline scripts directly from CrawlResult (avoids re-parsing HTML)
        for idx, script_text in enumerate(result.inline_scripts, start=1):
            inline_id = f"{url}#inline-script-{idx}"
            self.files[inline_id] = FileInfo(inline_id, "text/javascript", script_text, "inline")
            self.stats["scripts_scanned"] += 1
            self.stats["files_scanned"] += 1
            threats = self.malware_detector.analyze_content(script_text, inline_id, page_url=url)
            for t in threats:
                log_threat(t.severity, f"[{t.threat_type}] {t.description} in {inline_id}")
            self.all_threats.extend(threats)

    def _fetch_external_scripts(self, script_urls: List[str], page_url: str):
        """Fetch and analyze external scripts concurrently."""
        pending = [u for u in script_urls if u not in self.files]
        if not pending:
            return

        log_info(f"Fetching {len(pending)} external scripts from {page_url}")

        def fetch_one(script_url: str) -> Tuple[str, int, str, str]:
            status, content, ct = self.crawler.fetch_external(script_url)
            return script_url, status, content, ct

        with ThreadPoolExecutor(max_workers=min(8, len(pending))) as executor:
            future_to_url = {executor.submit(fetch_one, u): u for u in pending}
            for future in as_completed(future_to_url):
                script_url, status, content, ct = future.result()
                if status == 200:
                    self.files[script_url] = FileInfo(script_url, ct, content, "external_script")
                    self.stats["scripts_scanned"] += 1
                    self.stats["files_scanned"] += 1
                    threats = self.malware_detector.analyze_content(content, script_url, page_url=page_url)
                    for t in threats:
                        log_threat(t.severity, f"[{t.threat_type}] {t.description} in {script_url}")
                    self.all_threats.extend(threats)
                else:
                    log_warning(f"Failed to fetch external script: {script_url} (status: {status})")
