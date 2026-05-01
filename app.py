import os
import json
import hashlib
import threading
import uuid
import logging
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, Response
from scanner import FileAnalyzer, ScanReporter
from scanner.display import print_startup_sequence, log_scan_start, log_scan_complete, log_info, log_error

# Suppress Flask's default startup message
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)

# In-memory store for active and completed scans for HeuristiX
scans = {}
SCAN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
os.makedirs(SCAN_DIR, exist_ok=True)
SCANS_FILE = os.path.join(SCAN_DIR, "scans.json")
COMMUNITY_THREATS_FILE = os.path.join(SCAN_DIR, "community_threats.json")

# Community threats store
community_threats = []


def load_scans():
    """Load HeuristiX scan history from disk on startup."""
    global scans
    if os.path.exists(SCANS_FILE):
        try:
            with open(SCANS_FILE, "r", encoding="utf-8") as f:
                scans = json.load(f)
        except:
            scans = {}


def load_community_threats():
    """Load community threats from disk on startup."""
    global community_threats
    if os.path.exists(COMMUNITY_THREATS_FILE):
        try:
            with open(COMMUNITY_THREATS_FILE, "r", encoding="utf-8") as f:
                community_threats = json.load(f)
        except:
            community_threats = []


def save_community_threats():
    """Save community threats to disk."""
    try:
        with open(COMMUNITY_THREATS_FILE, "w", encoding="utf-8") as f:
            json.dump(community_threats, f, indent=2, ensure_ascii=False)
    except:
        pass


def save_scans():
    """Save HeuristiX scan history to disk (without analyzer objects)."""
    try:
        # Create a serializable copy of scans (exclude _analyzer)
        serializable = {}
        for scan_id, data in scans.items():
            serializable[scan_id] = {k: v for k, v in data.items() if k != "_analyzer"}
        with open(SCANS_FILE, "w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2, ensure_ascii=False)
    except:
        pass


# Load scans on startup
load_scans()
load_community_threats()


def run_scan(scan_id: str, url: str, max_pages: int, max_depth: int, stealth_mode: bool = False):
    scans[scan_id]["status"] = "running"
    log_scan_start(url, max_pages, max_depth, stealth_mode)
    try:
        analyzer = FileAnalyzer(url, max_pages=max_pages, max_depth=max_depth, stealth_mode=stealth_mode)
        result = analyzer.scan()
        scans[scan_id]["status"] = "completed"
        scans[scan_id]["result"] = result
        scans[scan_id]["_analyzer"] = analyzer  # Keep reference for file downloads (not saved to disk)
        scans[scan_id]["completed_at"] = datetime.now().isoformat()

        # Generate HX-Report filename: HX_Scan_[URL]_[Date].json
        # Sanitize URL for filename
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        url_clean = parsed_url.netloc.replace("www.", "").replace(".", "_")
        date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_filename = f"HX_Scan_{url_clean}_{date_str}.json"
        json_path = os.path.join(SCAN_DIR, json_filename)
        
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        # Save HTML report with same naming convention
        html_filename = f"HX_Scan_{url_clean}_{date_str}.html"
        html_path = os.path.join(SCAN_DIR, html_filename)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(ScanReporter.to_html(result))

        scans[scan_id]["json_report"] = json_path
        scans[scan_id]["html_report"] = html_path

        # Log scan completion with confidence
        score = result.get("risk_score", {}).get("score", 0)
        verdict = result.get("risk_score", {}).get("verdict", "")
        confidence = result.get("risk_score", {}).get("confidence", {}).get("score", 0)
        log_scan_complete(score, verdict, confidence)

        # Save scan metadata to disk (without the analyzer object)
        save_scans()

        # If scan found dangerous site, add to community threats
        if score <= 50 and verdict in ["DANGEROUS", "MALICIOUS"]:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Check if already reported
            existing = next((t for t in community_threats if t["domain"] == domain), None)
            if not existing:
                threat_entry = {
                    "id": str(uuid.uuid4()),
                    "domain": domain,
                    "url": url,
                    "risk_score": score,
                    "verdict": verdict,
                    "threats_count": len(result.get("threats_found", [])),
                    "reported_at": datetime.now().isoformat(),
                    "reporter": "Anonymous",
                    "top_threats": result.get("threats_found", [])[:3]
                }
                community_threats.insert(0, threat_entry)
                # Keep only last 100 threats
                if len(community_threats) > 100:
                    community_threats = community_threats[:100]
                save_community_threats()

    except Exception as e:
        scans[scan_id]["status"] = "failed"
        scans[scan_id]["error"] = str(e)
        log_error(f"Scan failed: {e}")
        save_scans()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(force=True)
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    max_pages = min(max(int(data.get("max_pages", 20)), 1), 200)
    max_depth = min(max(int(data.get("max_depth", 2)), 1), 5)
    stealth_mode = data.get("stealth_mode", False)

    scan_id = str(uuid.uuid4())
    scans[scan_id] = {
        "id": scan_id,
        "url": url,
        "max_pages": max_pages,
        "max_depth": max_depth,
        "stealth_mode": stealth_mode,
        "status": "queued",
        "started_at": datetime.now().isoformat(),
    }

    thread = threading.Thread(target=run_scan, args=(scan_id, url, max_pages, max_depth, stealth_mode), daemon=True)
    thread.start()

    return jsonify({"scan_id": scan_id, "status": "queued"})


@app.route("/api/scan/<scan_id>/status")
def api_scan_status(scan_id):
    info = scans.get(scan_id)
    if not info:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify({
        "scan_id": scan_id,
        "status": info.get("status"),
        "url": info.get("url"),
        "started_at": info.get("started_at"),
        "completed_at": info.get("completed_at"),
        "error": info.get("error"),
    })


@app.route("/api/scan/<scan_id>/result")
def api_scan_result(scan_id):
    info = scans.get(scan_id)
    if not info:
        return jsonify({"error": "Scan not found"}), 404
    if info.get("status") != "completed":
        return jsonify({"error": "Scan not completed"}), 400
    return jsonify(info.get("result", {}))


@app.route("/api/scans")
def api_scans():
    items = []
    for sid, info in scans.items():
        items.append({
            "scan_id": sid,
            "url": info.get("url"),
            "status": info.get("status"),
            "started_at": info.get("started_at"),
            "completed_at": info.get("completed_at"),
        })
    items.sort(key=lambda x: x.get("started_at", ""), reverse=True)
    return jsonify({"scans": items[:50]})


@app.route("/api/community-threats")
def api_community_threats():
    """Get community-reported dangerous sites."""
    return jsonify({"threats": community_threats[:20]})


@app.route("/api/community-threats", methods=["POST"])
def api_report_threat():
    """Manually report a threat to the community."""
    data = request.get_json(force=True)
    domain = data.get("domain", "").strip()
    url = data.get("url", "").strip()
    reporter = data.get("reporter", "Anonymous").strip()
    
    if not domain or not url:
        return jsonify({"error": "Domain and URL are required"}), 400
    
    # Check if already reported
    existing = next((t for t in community_threats if t["domain"] == domain), None)
    if existing:
        return jsonify({"error": "Domain already reported"}), 400
    
    threat_entry = {
        "id": str(uuid.uuid4()),
        "domain": domain,
        "url": url,
        "risk_score": data.get("risk_score", 0),
        "verdict": data.get("verdict", "DANGEROUS"),
        "threats_count": data.get("threats_count", 0),
        "reported_at": datetime.now().isoformat(),
        "reporter": reporter,
        "top_threats": data.get("top_threats", [])
    }
    
    community_threats.insert(0, threat_entry)
    if len(community_threats) > 100:
        community_threats = community_threats[:100]
    save_community_threats()
    
    return jsonify({"success": True, "threat": threat_entry})


@app.route("/api/scan/<scan_id>/report/<format>")
def api_report(scan_id, format):
    info = scans.get(scan_id)
    if not info:
        return jsonify({"error": "Scan not found"}), 404

    if format == "html":
        path = info.get("html_report")
    elif format == "json":
        path = info.get("json_report")
    elif format == "pdf":
        path = info.get("html_report")
        if path and os.path.exists(path):
            try:
                from weasyprint import HTML
                pdf_path = path.replace('.html', '.pdf')
                HTML(filename=path).write_pdf(pdf_path)
                return send_file(pdf_path, as_attachment=True, download_name=os.path.basename(pdf_path))
            except ImportError:
                return jsonify({"error": "PDF export requires weasyprint. Run: pip install weasyprint"}), 500
        return jsonify({"error": "HTML report not ready"}), 400
    else:
        return jsonify({"error": "Invalid format"}), 400

    if path and os.path.exists(path):
        return send_file(path, as_attachment=False)
    return jsonify({"error": "Report not ready"}), 400


@app.route("/api/scan/<scan_id>/file/<path:file_url>")
def api_file_content(scan_id, file_url):
    """Download the raw content of a scanned file as text only (safe, no AV triggers)."""
    info = scans.get(scan_id)
    if not info:
        return jsonify({"error": "Scan not found"}), 404
    result = info.get("result", {})
    if not result:
        return jsonify({"error": "Scan not completed"}), 400

    # Try to get content from in-memory analyzer first
    analyzer = info.get("_analyzer")
    fi = None
    if analyzer:
        fi = analyzer.files.get(file_url)
        if not fi:
            # Try matching by suffix (file_url might be a partial path)
            for k, v in analyzer.files.items():
                if k.endswith(file_url) or file_url.endswith(k):
                    fi = v
                    file_url = k
                    break
    
    # If analyzer not available (old scan loaded from disk), try to extract from result
    if not fi and result.get("files"):
        for f in result["files"]:
            if f["url"] == file_url or f["url"].endswith(file_url) or file_url.endswith(f["url"]):
                # File content is not in the result, we need to reload from JSON report
                json_path = info.get("json_report")
                if json_path and os.path.exists(json_path):
                    try:
                        with open(json_path, "r", encoding="utf-8") as f:
                            full_result = json.load(f)
                        # Check if full result has file content (it won't by default)
                        # For now, return error for old scans
                        return jsonify({"error": "File content not available for old scans. Please re-scan to download files."}), 400
                    except:
                        pass
                break
    
    if not fi:
        return jsonify({"error": "File not found"}), 404

    # Generate a safe filename for download (always .txt to prevent AV triggers)
    safe_name = hashlib.md5(file_url.encode()).hexdigest()[:12]
    parsed = __import__("urllib.parse").parse.urlparse(file_url)
    path_name = parsed.path.strip("/").replace("/", "_")[-40:] or "index"
    filename = f"{path_name}.txt"  # Always .txt for safety

    # Force text/plain content type to prevent any execution or AV false positives
    # Add security headers to prevent content sniffing and ensure text treatment
    return Response(
        fi.content,
        mimetype="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; script-src 'none';",
            "X-Frame-Options": "DENY",
        }
    )


@app.route("/api/scan/<scan_id>/links")
def api_scan_links(scan_id):
    """Return all discovered links for a scan."""
    info = scans.get(scan_id)
    if not info:
        return jsonify({"error": "Scan not found"}), 404
    result = info.get("result", {})
    if not result:
        return jsonify({"error": "Scan not completed"}), 400
    return jsonify({"links": result.get("all_links", []), "total": len(result.get("all_links", []))})


@app.route("/api/live-logs/<scan_id>")
def api_live_logs(scan_id):
    info = scans.get(scan_id)
    if not info:
        return jsonify({"logs": [], "status": "not_found"})
    # Simple status-as-log for now
    logs = [{"time": datetime.now().isoformat(), "message": f"Status: {info.get('status', 'unknown')}"}]
    return jsonify({"logs": logs, "status": info.get("status", "unknown")})


@app.route("/api/scan-file", methods=["POST"])
def api_scan_file():
    """Scan an uploaded file for malware."""
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    try:
        # Read file content
        content = file.read().decode('utf-8', errors='ignore')
        filename = file.filename
        
        # Use MalwareDetector to scan the file
        from scanner.detectors import MalwareDetector
        from scanner.analyzer import RiskScorer
        
        detector = MalwareDetector()
        threats = detector.analyze_content(content, filename)
        risk_score = RiskScorer.score(threats)
        
        # Count severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for t in threats:
            severity_counts[t.severity] = severity_counts.get(t.severity, 0) + 1
        
        return jsonify({
            "filename": filename,
            "file_size": len(content),
            "threats_found": len(threats),
            "threats": [t.to_dict() for t in threats],
            "severity_counts": severity_counts,
            "risk_score": risk_score
        })
    
    except Exception as e:
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500


if __name__ == "__main__":
    print_startup_sequence()
    log_info("HeuristiX Web Server starting on http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)
