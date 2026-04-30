import json
from typing import Dict, Any, List
from datetime import datetime


class ScanReporter:
    """Generates scan reports in JSON and HTML formats."""

    @staticmethod
    def to_json(data: Dict[str, Any], indent: int = 2) -> str:
        return json.dumps(data, indent=indent, ensure_ascii=False)

    @staticmethod
    def to_html(data: Dict[str, Any]) -> str:
        title = f"Scan Report: {data.get('base_url', 'Unknown')}"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        severity = data.get("severity_counts", {})
        threats: List[Dict[str, Any]] = data.get("threats", [])
        errors = data.get("crawl_errors", [])
        files = data.get("files", [])
        risk = data.get("risk_score", {})
        score = risk.get("score", 0)
        verdict = risk.get("verdict", "")
        score_color = "#22c55e" if score > 70 else "#eab308" if score > 50 else "#ef4444"

        rows = ""
        for t in threats:
            badge_class = ScanReporter._severity_class(t.get("severity", "low"))
            rows += f"""
                <tr>
                    <td><span class="badge {badge_class}">{t.get('severity', 'low').upper()}</span></td>
                    <td>{t.get('type', '')}</td>
                    <td class="mono">{t.get('file', '')}</td>
                    <td>{t.get('line', 0)}</td>
                    <td>{t.get('description', '')}</td>
                    <td class="mono small">{ScanReporter._escape(t.get('evidence', ''))}</td>
                </tr>
            """

        error_rows = ""
        for e in errors:
            error_rows += f"""
                <tr>
                    <td class="mono">{e.get('url', '')}</td>
                    <td>{e.get('error', '')}</td>
                </tr>
            """

        file_rows = ""
        for f in files[:200]:  # Limit displayed files
            file_rows += f"""
                <tr>
                    <td class="mono">{f.get('url', '')}</td>
                    <td>{f.get('type', '')}</td>
                    <td>{f.get('source', '')}</td>
                </tr>
            """

        if not threats:
            rows = '<tr><td colspan="6" class="text-center">No threats detected.</td></tr>'
        if not errors:
            error_rows = '<tr><td colspan="2" class="text-center">No crawl errors.</td></tr>'
        if not files:
            file_rows = '<tr><td colspan="3" class="text-center">No files scanned.</td></tr>'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{title}}</title>
    <style>
        :root {{
            --bg: #0f1117;
            --card: #161922;
            --text: #e2e8f0;
            --muted: #94a3b8;
            --accent: #38bdf8;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #22c55e;
            --border: #1f2937;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 2rem;
        }}
        h1, h2, h3 {{ margin-top: 0; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ margin-bottom: 2rem; }}
        .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 0.75rem;
            padding: 1.25rem;
            text-align: center;
        }}
        .card .number {{ font-size: 2rem; font-weight: 700; margin-bottom: 0.25rem; }}
        .card .label {{ color: var(--muted); font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .number.critical {{ color: var(--critical); }}
        .number.high {{ color: var(--high); }}
        .number.medium {{ color: var(--medium); }}
        .number.low {{ color: var(--low); }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 0.75rem;
            overflow: hidden;
            margin-bottom: 2rem;
        }}
        th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }}
        th {{ background: rgba(255,255,255,0.03); color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        tr:hover {{ background: rgba(255,255,255,0.02); }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 0.375rem;
            font-size: 0.75rem;
            font-weight: 600;
            color: white;
        }}
        .badge.critical {{ background: var(--critical); }}
        .badge.high {{ background: var(--high); }}
        .badge.medium {{ background: var(--medium); color: #000; }}
        .badge.low {{ background: var(--low); }}
        .mono {{ font-family: 'Fira Code', Consolas, Monaco, monospace; font-size: 0.8rem; word-break: break-all; }}
        .small {{ max-width: 300px; }}
        .text-center {{ text-align: center; color: var(--muted); }}
        .section {{ margin-bottom: 2.5rem; }}
        .muted {{ color: var(--muted); }}
        .timestamp {{ font-size: 0.875rem; color: var(--muted); }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🛡️ Index Scanner Report</h1>
        <p class="muted">Target: <strong>{data.get('base_url', 'Unknown')}</strong></p>
        <p class="timestamp">Generated: {timestamp}</p>
    </div>

    {f"""<div style="background:{score_color}15;border:1px solid {score_color};border-radius:.75rem;padding:1rem 1.25rem;margin-bottom:1.5rem;display:flex;align-items:center;gap:1.25rem;">
        <div style="font-size:2.5rem;font-weight:800;color:{score_color};">{score}</div>
        <div>
            <div style="font-size:1.1rem;font-weight:700;color:{score_color};">{verdict}</div>
            <div style="font-size:.85rem;color:var(--muted);">Risk Score (0-100)</div>
        </div>
    </div>""" if risk else ""}

    <div class="cards">
        <div class="card">
            <div class="number critical">{severity.get('critical', 0)}</div>
            <div class="label">Critical</div>
        </div>
        <div class="card">
            <div class="number high">{severity.get('high', 0)}</div>
            <div class="label">High</div>
        </div>
        <div class="card">
            <div class="number medium">{severity.get('medium', 0)}</div>
            <div class="label">Medium</div>
        </div>
        <div class="card">
            <div class="number low">{severity.get('low', 0)}</div>
            <div class="label">Low</div>
        </div>
        <div class="card">
            <div class="number">{data.get('pages_scanned', 0)}</div>
            <div class="label">Pages</div>
        </div>
        <div class="card">
            <div class="number">{data.get('files_scanned', 0)}</div>
            <div class="label">Files</div>
        </div>
        <div class="card">
            <div class="number">{data.get('links_checked', 0)}</div>
            <div class="label">Links</div>
        </div>
    </div>

    <div class="section">
        <h2>Threats</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>File / URL</th>
                    <th>Line</th>
                    <th>Description</th>
                    <th>Evidence</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>Crawl Errors</h2>
        <table>
            <thead>
                <tr>
                    <th>URL</th>
                    <th>Error</th>
                </tr>
            </thead>
            <tbody>
                {error_rows}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>Scanned Files</h2>
        <table>
            <thead>
                <tr>
                    <th>URL</th>
                    <th>Content Type</th>
                    <th>Source</th>
                </tr>
            </thead>
            <tbody>
                {file_rows}
            </tbody>
        </table>
    </div>
</div>
</body>
</html>
"""
        return html

    @staticmethod
    def _severity_class(severity: str) -> str:
        s = severity.lower()
        if s == "critical":
            return "critical"
        if s == "high":
            return "high"
        if s == "medium":
            return "medium"
        return "low"

    @staticmethod
    def _escape(text: str) -> str:
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))
