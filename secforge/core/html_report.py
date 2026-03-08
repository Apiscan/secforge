"""
HTML report generator — self-contained, single-file output.

Uses inline CSS/JS with no external dependencies.
Opens directly in a browser without a web server.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from secforge.models.enums import Severity, FindingStatus
from secforge.core.reporter import ScanResult

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#2563eb",
    "INFO":     "#6b7280",
}

STATUS_COLORS = {
    "CONFIRMED":   "#16a34a",
    "PROBABLE":    "#d97706",
    "SPECULATIVE": "#6b7280",
}

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def to_html(result: ScanResult, path: Optional[str] = None) -> str:
    """Render a full scan result as a self-contained HTML file."""
    from rich.console import Console
    console = Console()

    counts = result.counts
    total = sum(counts.values())
    ts = result.timestamp[:10]

    findings_html = "\n".join(_finding_html(f) for f in result.findings)

    summary_rows = "\n".join(
        f'<tr><td>{sev.emoji} <strong>{sev.value}</strong></td>'
        f'<td style="color:{SEVERITY_COLORS[sev.value]};font-weight:bold">{counts[sev.value]}</td></tr>'
        for sev in SEVERITY_ORDER
        if counts[sev.value] > 0
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ApiScan Report — {result.target.url}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
  .container {{ max-width: 960px; margin: 0 auto; padding: 2rem 1rem; }}
  header {{ border-bottom: 1px solid #1e293b; padding-bottom: 1.5rem; margin-bottom: 2rem; }}
  .logo {{ font-size: 1.8rem; font-weight: 800; color: #f8fafc; }}
  .logo span {{ color: #6366f1; }}
  .meta {{ color: #94a3b8; margin-top: 0.5rem; font-size: 0.9rem; }}
  .meta strong {{ color: #e2e8f0; }}
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
               gap: 1rem; margin-bottom: 2rem; }}
  .stat-card {{ background: #1e293b; border-radius: 8px; padding: 1rem; text-align: center;
                border: 1px solid #334155; }}
  .stat-num {{ font-size: 2rem; font-weight: 800; }}
  .stat-label {{ font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }}
  .section-title {{ font-size: 1.1rem; font-weight: 700; color: #94a3b8; text-transform: uppercase;
                    letter-spacing: 0.1em; margin: 2rem 0 1rem; }}
  table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px;
           overflow: hidden; margin-bottom: 2rem; }}
  th {{ background: #0f172a; padding: 0.75rem 1rem; text-align: left; font-size: 0.8rem;
        text-transform: uppercase; color: #64748b; letter-spacing: 0.05em; }}
  td {{ padding: 0.75rem 1rem; border-top: 1px solid #334155; vertical-align: top; }}
  .finding {{ background: #1e293b; border-radius: 8px; border: 1px solid #334155;
              margin-bottom: 1rem; overflow: hidden; }}
  .finding-header {{ padding: 1rem 1.25rem; cursor: pointer; display: flex;
                     align-items: center; gap: 1rem; user-select: none; }}
  .finding-header:hover {{ background: #263248; }}
  .sev-badge {{ padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem;
                font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }}
  .status-badge {{ padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.7rem;
                   font-weight: 600; text-transform: uppercase; }}
  .finding-title {{ font-weight: 600; flex: 1; }}
  .finding-body {{ padding: 1.25rem; border-top: 1px solid #334155; display: none; }}
  .finding-body.open {{ display: block; }}
  .label {{ font-size: 0.75rem; text-transform: uppercase; color: #64748b; letter-spacing: 0.05em;
            margin-bottom: 0.25rem; margin-top: 1rem; }}
  .label:first-child {{ margin-top: 0; }}
  .code {{ background: #0f172a; border-radius: 4px; padding: 0.75rem 1rem; font-family: monospace;
           font-size: 0.85rem; white-space: pre-wrap; word-break: break-all; color: #a5f3fc;
           margin-top: 0.25rem; }}
  .remediation {{ background: #052e16; border-left: 3px solid #16a34a; padding: 0.75rem 1rem;
                  border-radius: 0 4px 4px 0; color: #bbf7d0; font-size: 0.9rem; margin-top: 0.25rem; }}
  .ref-list {{ list-style: none; margin-top: 0.25rem; }}
  .ref-list li a {{ color: #818cf8; font-size: 0.85rem; }}
  .no-findings {{ text-align: center; padding: 3rem; color: #4ade80; font-size: 1.1rem; }}
  footer {{ text-align: center; color: #475569; font-size: 0.8rem; margin-top: 3rem;
            padding-top: 1.5rem; border-top: 1px solid #1e293b; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="logo">🔐 Sec<span>Forge</span></div>
    <div class="meta">
      <strong>Target:</strong> {result.target.url} &nbsp;|&nbsp;
      <strong>Date:</strong> {ts} &nbsp;|&nbsp;
      <strong>Duration:</strong> {result.duration_s:.1f}s &nbsp;|&nbsp;
      <strong>Scanner:</strong> ApiScan v{result.scanner_version}
    </div>
  </header>

  <div class="summary">
    <div class="stat-card">
      <div class="stat-num" style="color:#f8fafc">{total}</div>
      <div class="stat-label">Total</div>
    </div>
    <div class="stat-card">
      <div class="stat-num" style="color:#16a34a">{result.confirmed_count}</div>
      <div class="stat-label">Confirmed</div>
    </div>
    {"".join(
      f'<div class="stat-card"><div class="stat-num" style="color:{SEVERITY_COLORS[sev.value]}">'
      f'{counts[sev.value]}</div><div class="stat-label">{sev.value}</div></div>'
      for sev in SEVERITY_ORDER if counts[sev.value] > 0
    )}
  </div>

  <div class="section-title">Summary</div>
  <table>
    <tr><th>Severity</th><th>Count</th></tr>
    {summary_rows}
    <tr><td><strong>Total</strong></td><td><strong>{total}</strong></td></tr>
  </table>

  <div class="section-title">Findings</div>
  {"".join([findings_html]) if result.findings else '<div class="no-findings">✅ No findings detected.</div>'}

  <footer>
    Generated by <strong>ApiScan v{result.scanner_version}</strong> &mdash;
    CLI-native API security scanner &mdash; {result.timestamp[:19].replace("T", " ")} UTC
  </footer>
</div>

<script>
document.querySelectorAll('.finding-header').forEach(h => {{
  h.addEventListener('click', () => {{
    const body = h.nextElementSibling;
    body.classList.toggle('open');
  }});
}});
</script>
</body>
</html>"""

    if path:
        out = path if path.endswith(".html") else path + ".html"
        Path(out).write_text(html)
        console.print(f"[green]✅ HTML report saved:[/green] {out}")
    return html


def _finding_html(f) -> str:
    sev_color = SEVERITY_COLORS.get(f.severity.value, "#6b7280")
    stat_color = STATUS_COLORS.get(f.status.value, "#6b7280")

    evidence_html = ""
    for i, ev in enumerate(f.evidence, 1):
        evidence_html += f"""
        <div class="label">Evidence {i}</div>
        <div class="code">{_escape(ev.note)}"""
        if ev.request_url:
            evidence_html += f"\n{_escape(ev.request_method)} {_escape(ev.request_url)}"
        if ev.response_status:
            evidence_html += f"\nHTTP {ev.response_status}"
        if ev.response_body_snippet:
            evidence_html += f"\n{_escape(ev.response_body_snippet[:300])}"
        evidence_html += "</div>"

    refs_html = ""
    if f.references:
        refs_html = '<div class="label">References</div><ul class="ref-list">' + \
            "".join(f'<li><a href="{r}" target="_blank">{_escape(r)}</a></li>' for r in f.references) + \
            "</ul>"

    owasp = f"&nbsp;|&nbsp; OWASP: {f.owasp_id}" if f.owasp_id else ""
    endpoint = f"&nbsp;|&nbsp; Endpoint: <code>{_escape(f.endpoint)}</code>" if f.endpoint else ""

    return f"""
<div class="finding">
  <div class="finding-header">
    <span class="sev-badge" style="background:{sev_color}22;color:{sev_color}">{f.severity.value}</span>
    <span class="finding-title">{_escape(f.title)}</span>
    <span class="status-badge" style="background:{stat_color}22;color:{stat_color}">{f.status.value}</span>
  </div>
  <div class="finding-body">
    <div class="label">Description</div>
    <p style="color:#cbd5e1;font-size:0.9rem">{_escape(f.description).replace(chr(10), '<br>')}</p>
    <div style="font-size:0.8rem;color:#64748b;margin-top:0.5rem">
      Plugin: {_escape(f.plugin)}{owasp}{endpoint}
    </div>
    {evidence_html}
    {"<div class='label'>Remediation</div><div class='remediation'>" + _escape(f.remediation) + "</div>" if f.remediation else ""}
    {refs_html}
  </div>
</div>"""


def _escape(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
