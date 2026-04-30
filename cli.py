import argparse
import sys
import os
from datetime import datetime
from scanner import FileAnalyzer, ScanReporter
from scanner.display import print_startup_sequence, log_scan_start, log_scan_complete, log_info, log_warning, log_error


def main():
    parser = argparse.ArgumentParser(
        description="HeuristiX - Detect malware, malicious scripts, phishing, and scam links."
    )
    parser.add_argument("url", help="Target website URL to scan")
    parser.add_argument("--pages", type=int, default=30, help="Maximum pages to crawl (default: 30)")
    parser.add_argument("--depth", type=int, default=2, help="Maximum crawl depth (default: 2)")
    parser.add_argument("--format", choices=["json", "html", "both"], default="both",
                        help="Report format (default: both)")
    parser.add_argument("--output", "-o", default="reports", help="Output directory for reports")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode (hide from site detection)")
    args = parser.parse_args()

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print_startup_sequence()
    log_scan_start(url, args.pages, args.depth, args.stealth)

    analyzer = FileAnalyzer(url, max_pages=args.pages, max_depth=args.depth, stealth_mode=args.stealth)
    result = analyzer.scan()

    sev = result.get("severity_counts", {})
    threats = result.get("threats_found", 0)
    score = result.get("risk_score", {}).get("score", 0)
    verdict = result.get("risk_score", {}).get("verdict", "")
    confidence = result.get("risk_score", {}).get("confidence", {}).get("score", 0)

    log_scan_complete(score, verdict, confidence)

    if threats:
        log_warning(f"Threats found: {threats}")
    else:
        log_info("No threats detected")

    os.makedirs(args.output, exist_ok=True)

    if args.format in ("json", "both"):
        import json
        fname = os.path.join(args.output, f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(fname, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"📄 JSON report saved: {fname}")

    if args.format in ("html", "both"):
        fname = os.path.join(args.output, f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        with open(fname, "w", encoding="utf-8") as f:
            f.write(ScanReporter.to_html(result))
        print(f"🌐 HTML report saved: {fname}")

    print("\nDone.\n")
    return 0 if threats == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
