import datetime
import json

def generate_html_report(url, vulnerabilities, elapsed):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    high   = [v for v in vulnerabilities if v["severity"] == "HIGH"]
    medium = [v for v in vulnerabilities if v["severity"] == "MEDIUM"]
    low    = [v for v in vulnerabilities if v["severity"] == "LOW"]
    info   = [v for v in vulnerabilities if v["severity"] == "INFO"]

    def severity_badge(severity):
        colors = {
            "HIGH":   ("#c0392b", "#fadbd8"),
            "MEDIUM": ("#d68910", "#fef9e7"),
            "LOW":    ("#1a5276", "#d6eaf8"),
            "INFO":   ("#117a65", "#d1f2eb"),
        }
        fg, bg = colors.get(severity, ("#333", "#eee"))
        return (
            f'<span style="background:{bg};color:{fg};padding:3px 10px;'
            f'border-radius:4px;font-size:12px;font-weight:600;">{severity}</span>'
        )

    def build_rows(vulns):
        if not vulns:
            return '<tr><td colspan="4" style="text-align:center;color:#999;">None found</td></tr>'
        rows = ""
        for v in vulns:
            rows += f"""
            <tr>
                <td>{severity_badge(v['severity'])}</td>
                <td><strong>{v['type']}</strong></td>
                <td>{v['detail']}</td>
                <td style="font-size:12px;color:#666;word-break:break-all;">{v['url']}</td>
            </tr>"""
        return rows

    all_rows = build_rows(vulnerabilities)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnScan Report — {url}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #f4f6f9;
    color: #2c3e50;
    padding: 40px 20px;
  }}
  .container {{ max-width: 1000px; margin: 0 auto; }}

  /* Header */
  .header {{
    background: #1a1a2e;
    color: white;
    padding: 32px 40px;
    border-radius: 12px;
    margin-bottom: 24px;
  }}
  .header h1 {{
    font-size: 24px;
    font-weight: 600;
    margin-bottom: 8px;
    color: #e74c3c;
    letter-spacing: 2px;
  }}
  .header .meta {{ font-size: 13px; color: #aaa; line-height: 1.8; }}
  .header .meta span {{ color: #ecf0f1; font-weight: 500; }}

  /* Summary cards */
  .cards {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 24px;
  }}
  .card {{
    background: white;
    border-radius: 10px;
    padding: 20px;
    text-align: center;
    border-top: 4px solid;
  }}
  .card.high   {{ border-color: #e74c3c; }}
  .card.medium {{ border-color: #f39c12; }}
  .card.low    {{ border-color: #2980b9; }}
  .card.info   {{ border-color: #27ae60; }}
  .card .number {{
    font-size: 36px;
    font-weight: 700;
    line-height: 1;
    margin-bottom: 6px;
  }}
  .card.high   .number {{ color: #e74c3c; }}
  .card.medium .number {{ color: #f39c12; }}
  .card.low    .number {{ color: #2980b9; }}
  .card.info   .number {{ color: #27ae60; }}
  .card .label {{ font-size: 12px; color: #999; font-weight: 600; letter-spacing: 1px; }}

  /* Table */
  .section {{
    background: white;
    border-radius: 10px;
    padding: 28px 32px;
    margin-bottom: 24px;
  }}
  .section h2 {{
    font-size: 16px;
    font-weight: 600;
    margin-bottom: 20px;
    padding-bottom: 12px;
    border-bottom: 1px solid #eee;
    color: #2c3e50;
  }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{
    text-align: left;
    font-size: 11px;
    font-weight: 600;
    color: #999;
    letter-spacing: 1px;
    padding: 0 12px 12px 0;
    text-transform: uppercase;
  }}
  td {{
    padding: 12px 12px 12px 0;
    font-size: 14px;
    border-top: 1px solid #f0f0f0;
    vertical-align: top;
  }}
  tr:hover td {{ background: #fafafa; }}

  /* Footer */
  .footer {{
    text-align: center;
    font-size: 12px;
    color: #bbb;
    padding-top: 8px;
  }}
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <h1>&#x1F6E1; VULNSCAN</h1>
    <div class="meta">
      Target &nbsp;&nbsp;: <span>{url}</span><br>
      Scanned : <span>{now}</span><br>
      Duration: <span>{elapsed}s</span><br>
      Total &nbsp;&nbsp;: <span>{len(vulnerabilities)} issue(s) found</span>
    </div>
  </div>

  <div class="cards">
    <div class="card high">
      <div class="number">{len(high)}</div>
      <div class="label">HIGH</div>
    </div>
    <div class="card medium">
      <div class="number">{len(medium)}</div>
      <div class="label">MEDIUM</div>
    </div>
    <div class="card low">
      <div class="number">{len(low)}</div>
      <div class="label">LOW</div>
    </div>
    <div class="card info">
      <div class="number">{len(info)}</div>
      <div class="label">INFO</div>
    </div>
  </div>

  <div class="section">
    <h2>All Findings</h2>
    <table>
      <thead>
        <tr>
          <th style="width:90px;">Severity</th>
          <th style="width:220px;">Type</th>
          <th>Detail</th>
          <th style="width:200px;">URL</th>
        </tr>
      </thead>
      <tbody>
        {all_rows}
      </tbody>
    </table>
  </div>

  <div class="footer">
    Generated by VulnScan v1.0 &nbsp;·&nbsp; For authorized testing only
  </div>

</div>
</body>
</html>"""

    return html


def generate_json_report(url, vulnerabilities, elapsed):
    return {
        "target": url,
        "scanned_at": datetime.datetime.now().isoformat(),
        "duration_seconds": elapsed,
        "summary": {
            "total": len(vulnerabilities),
            "high":   len([v for v in vulnerabilities if v["severity"] == "HIGH"]),
            "medium": len([v for v in vulnerabilities if v["severity"] == "MEDIUM"]),
            "low":    len([v for v in vulnerabilities if v["severity"] == "LOW"]),
            "info":   len([v for v in vulnerabilities if v["severity"] == "INFO"]),
        },
        "vulnerabilities": vulnerabilities
    }