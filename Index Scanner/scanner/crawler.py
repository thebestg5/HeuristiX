import requests
import time
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, urldefrag
from typing import Set, Dict, List, Tuple
from bs4 import BeautifulSoup
from .display import log_info, log_warning, log_error

# Disable noisy SSL warning when verify=False is used
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CrawlResult:
    def __init__(self, url: str, status_code: int, content_type: str,
                 content: str, links: List[str], scripts: List[str], forms: List[Dict],
                 inline_scripts: List[str] = None):
        self.url = url
        self.status_code = status_code
        self.content_type = content_type
        self.content = content
        self.links = links
        self.scripts = scripts
        self.forms = forms
        self.inline_scripts = inline_scripts or []
        self.files = []  # Populated by analyzer


class WebCrawler:
    def __init__(self, base_url: str, max_pages: int = 50, delay: float = 0.5,
                 timeout: int = 15, user_agent: str = None, max_depth: int = 3, 
                 stealth_mode: bool = False):
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc.lower()
        self.max_pages = max_pages
        self.delay = delay
        self.timeout = timeout
        self.max_depth = max_depth
        self.stealth_mode = stealth_mode
        
        # Stealth mode: minimal headers to avoid detection
        # Normal mode: Pretend to be Googlebot so malicious sites serve their SEO/bot-optimized payload
        if stealth_mode:
            self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        else:
            self.user_agent = user_agent or (
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
            )
        
        self.visited: Set[str] = set()
        self.results: Dict[str, CrawlResult] = {}
        self.errors: List[Dict] = []

    def crawl(self) -> Dict[str, CrawlResult]:
        queue: List[Tuple[str, int]] = [(self.base_url, 0)]

        while queue and len(self.visited) < self.max_pages:
            # Build a batch of URLs to fetch concurrently at this frontier
            batch: List[Tuple[str, int]] = []
            while queue and len(batch) < (self.max_pages - len(self.visited)):
                url, depth = queue.pop(0)
                if depth > self.max_depth:
                    continue
                url = self._normalize_url(url)
                if url in self.visited:
                    continue
                self.visited.add(url)
                batch.append((url, depth))

            if not batch:
                break

            # Fetch batch concurrently
            with ThreadPoolExecutor(max_workers=min(8, len(batch))) as executor:
                future_to_item = {
                    executor.submit(self._fetch, url): (url, depth)
                    for url, depth in batch
                }
                for future in as_completed(future_to_item):
                    url, depth = future_to_item[future]
                    result = future.result()
                    if result is None:
                        continue
                    self.results[url] = result
                    for link in result.links:
                        normalized = self._normalize_url(link)
                        if self._is_internal(normalized) and normalized not in self.visited:
                            queue.append((normalized, depth + 1))

            time.sleep(self.delay)

        return self.results

    def _fetch(self, url: str) -> CrawlResult | None:
        try:
            headers = {"User-Agent": self.user_agent}
            # verify=False = accept self-signed, expired, mismatched, untrusted certs
            resp = requests.get(url, headers=headers, timeout=self.timeout, allow_redirects=True, verify=False)
            content_type = resp.headers.get("Content-Type", "unknown").lower()

            # Only parse text-based content
            if not ("text/" in content_type or "application/javascript" in content_type
                    or "application/json" in content_type or "xml" in content_type):
                return CrawlResult(url, resp.status_code, content_type, "", [], [], [])

            text = resp.text
            soup = BeautifulSoup(text, "html.parser")

            links = []
            scripts = []
            forms = []

            # Extract links
            for a in soup.find_all("a", href=True):
                absolute = urljoin(url, a["href"])
                links.append(absolute)

            # Extract script sources and inline scripts
            inline_scripts = []
            for script in soup.find_all("script"):
                if script.get("src"):
                    scripts.append(urljoin(url, script["src"]))
                elif script.string:
                    inline_scripts.append(script.string)

            # Extract forms
            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action", ""))
                inputs = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    inputs.append({
                        "type": inp.get("type", "text"),
                        "name": inp.get("name", ""),
                        "id": inp.get("id", ""),
                    })
                forms.append({"action": action, "inputs": inputs})

            return CrawlResult(url, resp.status_code, content_type, text, links, scripts, forms, inline_scripts)

        except requests.exceptions.Timeout:
            self.errors.append({"url": url, "error": "Timeout"})
            log_warning(f"Timeout fetching {url}")
        except requests.exceptions.SSLError as e:
            err_msg = str(e)
            # Self-signed, expired, untrusted, hostname-mismatch certificates
            if any(k in err_msg for k in ("certificate", "CERTIFICATE_VERIFY", "SSL", "TLS")):
                self.errors.append({"url": url, "error": "SSL certificate error (self-signed, expired, or untrusted) – continuing scan"})
                log_info(f"SSL certificate bypassed for {url}")
            else:
                self.errors.append({"url": url, "error": f"SSL error: {err_msg[:200]}"})
                log_error(f"SSL error for {url}: {err_msg[:100]}")
        except requests.exceptions.ConnectionError as e:
            err_msg = str(e)
            # Gracefully handle DNS/name resolution failures
            if any(k in err_msg for k in ("NameResolutionError", "getaddrinfo", "Failed to resolve", "Name or service not known")):
                host = urlparse(url).netloc
                self.errors.append({"url": url, "error": f"DNS resolution failed for {host}"})
                log_error(f"DNS resolution failed for {host}")
            else:
                self.errors.append({"url": url, "error": f"Connection error: {err_msg[:200]}"})
                log_error(f"Connection error for {url}: {err_msg[:100]}")
        except requests.exceptions.RequestException as e:
            self.errors.append({"url": url, "error": f"Request error: {str(e)}"})
            log_error(f"Request error for {url}: {str(e)[:100]}")
        except Exception as e:
            self.errors.append({"url": url, "error": f"Unexpected error: {str(e)}"})
            log_error(f"Unexpected error for {url}: {str(e)[:100]}")

        return None

    def fetch_external(self, url: str) -> Tuple[int, str, str]:
        """Fetch an external resource (script, css)."""
        try:
            headers = {"User-Agent": self.user_agent}
            # verify=False = accept self-signed, expired, mismatched, untrusted certs
            resp = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
            return resp.status_code, resp.text, resp.headers.get("Content-Type", "unknown")
        except requests.exceptions.SSLError as e:
            err_msg = str(e)
            if any(k in err_msg for k in ("certificate", "CERTIFICATE_VERIFY", "SSL", "TLS")):
                self.errors.append({"url": url, "error": "SSL certificate error (self-signed, expired, or untrusted) – continuing scan"})
            else:
                self.errors.append({"url": url, "error": f"SSL error: {err_msg[:200]}"})
            return 0, "", "error"
        except requests.exceptions.ConnectionError as e:
            err_msg = str(e)
            if any(k in err_msg for k in ("NameResolutionError", "getaddrinfo", "Failed to resolve", "Name or service not known")):
                host = urlparse(url).netloc
                self.errors.append({"url": url, "error": f"DNS resolution failed for {host}"})
            else:
                self.errors.append({"url": url, "error": f"External fetch error: {err_msg[:200]}"})
            return 0, "", "error"
        except Exception as e:
            self.errors.append({"url": url, "error": f"External fetch error: {str(e)}"})
            return 0, "", "error"

    def _normalize_url(self, url: str) -> str:
        url = url.strip()
        url, _ = urldefrag(url)
        return url

    def _is_internal(self, url: str) -> bool:
        parsed = urlparse(url)
        if not parsed.netloc:
            return True
        return parsed.netloc.lower() == self.base_domain
