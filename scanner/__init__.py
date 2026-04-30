"""
Index Scanner - Web Security Scanner
Detects malware, malicious scripts, phishing, and scam links in websites.
"""

from .crawler import WebCrawler
from .analyzer import FileAnalyzer
from .detectors import MalwareDetector, PhishingDetector, SuspiciousLinkDetector
from .reporter import ScanReporter

__all__ = [
    'WebCrawler',
    'FileAnalyzer',
    'MalwareDetector',
    'PhishingDetector',
    'SuspiciousLinkDetector',
    'ScanReporter',
]
