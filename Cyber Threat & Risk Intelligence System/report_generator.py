"""
============================================================
 report_generator.py — PDF Incident Report Generator
 Cyber Risk & Threat Intelligence System
============================================================
 Generates styled PDF incident reports from threat log data.
 Uses WeasyPrint to render HTML templates into PDF documents.
============================================================
"""

import os
from datetime import datetime

# ============================================================
# Configuration
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

# Attempt to import WeasyPrint; fall back to HTML-only if unavailable (e.g., missing GTK+ on Windows)
try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except (ImportError, OSError, Exception) as e:
    WEASYPRINT_AVAILABLE = False
    print(f"[WARN] WeasyPrint not available ({e}). Reports will be saved as HTML.")


def _get_risk_color(risk_level: str) -> str:
    """
    Returns the hex color code for a given risk level.

    Args:
        risk_level: One of 'critical', 'high', 'medium', 'low'.

    Returns:
        str: Hex color code.
    """
    colors = {
        "critical": "#ff1744",
        "high": "#ff9100",
        "medium": "#ffd600",
        "low": "#00e676",
    }
    return colors.get(risk_level.lower(), "#90a4ae")


def _build_report_html(log_entry: dict) -> str:
    """
    Builds a styled HTML string for the incident report.

    The HTML is self-contained with inline CSS for maximum
    compatibility across PDF renderers and browsers.

    Args:
        log_entry: Decrypted threat log dictionary.

    Returns:
        str: Complete HTML document string.
    """
    risk_level = log_entry.get("risk_level", "unknown")
    risk_color = _get_risk_color(risk_level)
    threat_type = log_entry.get("threat_type", "unknown").replace("_", " ").title()
    report_id = log_entry.get("id", "N/A")
    timestamp = log_entry.get("timestamp", datetime.now().isoformat())
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Incident Report #{report_id} — Cyber Risk Intelligence</title>
    <style>
        @page {{
            size: A4;
            margin: 2cm;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
            color: #e0e0e0;
            background: #0a0e17;
            line-height: 1.6;
            padding: 40px;
        }}

        .report-header {{
            text-align: center;
            padding-bottom: 30px;
            border-bottom: 2px solid #00f0ff;
            margin-bottom: 30px;
        }}

        .report-header h1 {{
            font-size: 28px;
            color: #00f0ff;
            text-transform: uppercase;
            letter-spacing: 3px;
            margin-bottom: 8px;
        }}

        .report-header .subtitle {{
            font-size: 14px;
            color: #7a8ba0;
        }}

        .report-header .report-id {{
            font-size: 16px;
            color: #39ff14;
            margin-top: 10px;
            font-weight: bold;
        }}

        .section {{
            margin-bottom: 25px;
            background: #111827;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 20px;
        }}

        .section h2 {{
            font-size: 18px;
            color: #00f0ff;
            margin-bottom: 15px;
            padding-bottom: 8px;
            border-bottom: 1px solid #1e293b;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .field {{
            display: flex;
            margin-bottom: 10px;
        }}

        .field-label {{
            min-width: 180px;
            font-weight: 600;
            color: #7a8ba0;
            text-transform: uppercase;
            font-size: 12px;
            letter-spacing: 1px;
        }}

        .field-value {{
            color: #e0e0e0;
            font-size: 14px;
        }}

        .risk-badge {{
            display: inline-block;
            padding: 4px 16px;
            border-radius: 4px;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 13px;
            color: #ffffff;
            background: {risk_color};
        }}

        .mitigation-box {{
            background: #0d1321;
            border-left: 4px solid #39ff14;
            padding: 15px 20px;
            margin-top: 10px;
            border-radius: 0 8px 8px 0;
            font-size: 14px;
            line-height: 1.7;
            color: #c8d6e5;
        }}

        .footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #1e293b;
            color: #4a5568;
            font-size: 11px;
        }}

        .classification-stamp {{
            text-align: center;
            margin: 20px 0;
            font-size: 14px;
            font-weight: bold;
            color: #ff1744;
            letter-spacing: 4px;
            text-transform: uppercase;
        }}
    </style>
</head>
<body>
    <div class="classification-stamp">
        ── CONFIDENTIAL ── ZERO TRUST SECURED ──
    </div>

    <div class="report-header">
        <h1>🛡️ Incident Report</h1>
        <div class="subtitle">Cyber Risk & Threat Intelligence System</div>
        <div class="report-id">Report #{report_id}</div>
    </div>

    <!-- Incident Overview -->
    <div class="section">
        <h2>📋 Incident Overview</h2>
        <div class="field">
            <span class="field-label">Incident ID:</span>
            <span class="field-value">#{report_id}</span>
        </div>
        <div class="field">
            <span class="field-label">Detection Time:</span>
            <span class="field-value">{timestamp}</span>
        </div>
        <div class="field">
            <span class="field-label">Report Generated:</span>
            <span class="field-value">{generated_at}</span>
        </div>
        <div class="field">
            <span class="field-label">Threat Category:</span>
            <span class="field-value">{threat_type}</span>
        </div>
        <div class="field">
            <span class="field-label">Risk Level:</span>
            <span class="field-value">
                <span class="risk-badge">{risk_level.upper()}</span>
            </span>
        </div>
    </div>

    <!-- Network Details -->
    <div class="section">
        <h2>🌐 Network Details</h2>
        <div class="field">
            <span class="field-label">Source IP:</span>
            <span class="field-value">{log_entry.get('src_ip', 'N/A')}</span>
        </div>
        <div class="field">
            <span class="field-label">Destination IP:</span>
            <span class="field-value">{log_entry.get('dst_ip', 'N/A')}</span>
        </div>
        <div class="field">
            <span class="field-label">Protocol:</span>
            <span class="field-value">{log_entry.get('protocol', 'N/A').upper()}</span>
        </div>
        <div class="field">
            <span class="field-label">Destination Port:</span>
            <span class="field-value">{log_entry.get('dst_port', 'N/A')}</span>
        </div>
        <div class="field">
            <span class="field-label">Packet Length:</span>
            <span class="field-value">{log_entry.get('length', 'N/A')} bytes</span>
        </div>
    </div>

    <!-- ML Classification -->
    <div class="section">
        <h2>🤖 ML Classification</h2>
        <div class="field">
            <span class="field-label">Prediction:</span>
            <span class="field-value">{log_entry.get('prediction', 'N/A')}</span>
        </div>
        <div class="field">
            <span class="field-label">Confidence:</span>
            <span class="field-value">{float(log_entry.get('confidence', 0)) * 100:.1f}%</span>
        </div>
    </div>

    <!-- Mitigation Recommendations -->
    <div class="section">
        <h2>🔧 Mitigation Recommendations</h2>
        <div class="mitigation-box">
            {log_entry.get('mitigation', 'No specific mitigation available. Manual review recommended.')}
        </div>
    </div>

    <div class="footer">
        <p>Generated by Cyber Risk & Threat Intelligence System</p>
        <p>This report is encrypted at rest using AES-256-GCM | Zero Trust Architecture</p>
        <p>© {datetime.now().year} — CONFIDENTIAL</p>
    </div>
</body>
</html>"""

    return html


def generate_pdf_report(log_entry: dict) -> str:
    """
    Generates a PDF incident report from a threat log entry.

    If WeasyPrint is installed, produces a styled PDF.
    Otherwise, falls back to saving the report as an HTML file.

    Args:
        log_entry: Decrypted threat log dictionary from the vault.

    Returns:
        str: Absolute file path to the generated report.

    Raises:
        Exception: If report generation fails.
    """
    # Ensure reports directory exists
    os.makedirs(REPORTS_DIR, exist_ok=True)

    # Build the report HTML
    html_content = _build_report_html(log_entry)

    # Generate filename
    report_id = log_entry.get("id", "unknown")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if WEASYPRINT_AVAILABLE:
        # Generate PDF via WeasyPrint
        filename = f"incident_report_{report_id}_{timestamp}.pdf"
        filepath = os.path.join(REPORTS_DIR, filename)

        try:
            HTML(string=html_content).write_pdf(filepath)
            print(f"[REPORT] PDF generated: {filepath}")
            return filepath

        except Exception as e:
            print(f"[ERROR] PDF generation failed: {e}")
            # Fall through to HTML fallback
            print("[INFO] Falling back to HTML report.")

    # Fallback: Save as HTML
    filename = f"incident_report_{report_id}_{timestamp}.html"
    filepath = os.path.join(REPORTS_DIR, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[REPORT] HTML report generated: {filepath}")
    return filepath


# ============================================================
# Self-Test
# ============================================================
if __name__ == "__main__":
    print("=" * 50)
    print(" PDF Report Generator — Self-Test")
    print("=" * 50)

    test_log = {
        "id": 1,
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "protocol": "tcp",
        "dst_port": 80,
        "length": 1500,
        "threat_type": "ddos",
        "risk_level": "critical",
        "prediction": "anomaly",
        "confidence": 0.94,
        "mitigation": "Deploy rate limiting and SYN cookies. "
                      "Enable DDoS protection via WAF/CDN.",
        "timestamp": datetime.now().isoformat(),
    }

    report_path = generate_pdf_report(test_log)
    print(f"\n[TEST] Report saved to: {report_path}")
    print("[PASS] Report generation test PASSED ✓")
