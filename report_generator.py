"""HTML report generator for Cloud Misconfiguration Hunter."""
import os
from dataclasses import asdict
from html import escape


def generate_html(summary, findings, output_path):
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    sev_colors = {
        "CRITICAL": "#ff3b30",
        "HIGH": "#ff9500",
        "MEDIUM": "#ffcc00",
        "LOW": "#34c759",
    }
    svc_icons = {
        "S3": "📦", "EC2": "🖥️", "IAM": "🔑", "RDS": "🗄️",
        "CloudTrail": "📜", "VPC": "🌐", "KMS": "🔐",
    }

    cards = []
    for i, f in enumerate(sorted(findings, key=lambda x: -x.risk_score)):
        color = sev_colors.get(f.severity, "#888")
        icon = svc_icons.get(f.service, "☁️")
        cards.append(f"""
        <div class="finding" data-sev="{f.severity}">
          <div class="fhead" onclick="toggle({i})">
            <span class="icon">{icon}</span>
            <span class="sev" style="background:{color}">{f.severity}</span>
            <span class="fname">{escape(f.name)}</span>
            <span class="cis">{f.cis}</span>
            <span class="score">risk {f.risk_score}</span>
            <span class="chev">▶</span>
          </div>
          <div class="fbody" id="fb-{i}">
            <div class="row"><b>File:</b> <code>{escape(f.file)}:{f.line}</code></div>
            <div class="row"><b>Service:</b> {f.service}
              &nbsp; <b>CIS:</b> {f.cis}
              &nbsp; <b>Fingerprint:</b> <code>{f.fingerprint}</code></div>
            <pre class="evidence">{escape(f.evidence)}</pre>
            <div class="row"><b>Remediation:</b> {escape(f.remediation)}</div>
          </div>
        </div>
        """)

    svc_chips = "".join(
        f'<span class="chip">{svc_icons.get(s,"☁️")} {s}: <b>{n}</b></span>'
        for s, n in summary["by_service"].items()
    )

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Cloud Misconfiguration Report</title>
<style>
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',monospace;background:#0a0f1a;color:#cbd5e1;margin:0;padding:24px}}
  h1{{color:#60a5fa;margin:0 0 6px;font-size:26px}}
  .subtitle{{color:#64748b;margin-bottom:24px;font-size:13px}}
  .stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px}}
  .stat{{background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:16px}}
  .stat .n{{font-size:28px;font-weight:800;color:#f1f5f9}}
  .stat .l{{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.5px}}
  .chips{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:24px}}
  .chip{{background:#0f172a;border:1px solid #1e293b;border-radius:20px;padding:6px 14px;font-size:12px;color:#cbd5e1}}
  .finding{{background:#0f172a;border:1px solid #1e293b;border-radius:10px;margin-bottom:10px;overflow:hidden}}
  .fhead{{display:flex;align-items:center;gap:12px;padding:14px 18px;cursor:pointer}}
  .fhead:hover{{background:#131e35}}
  .icon{{font-size:18px}}
  .sev{{color:#000;font-weight:800;font-size:10px;padding:3px 10px;border-radius:20px}}
  .fname{{flex:1;color:#e2e8f0;font-weight:600;font-size:14px}}
  .cis{{color:#94a3b8;font-size:11px;background:#1e293b;padding:3px 8px;border-radius:4px}}
  .score{{color:#94a3b8;font-size:12px}}
  .chev{{color:#475569}}
  .fbody{{display:none;padding:0 18px 18px;border-top:1px solid #1e293b}}
  .fbody.open{{display:block}}
  .row{{margin:10px 0;font-size:13px}}
  code{{background:#020617;padding:2px 6px;border-radius:4px;color:#fbbf24;font-size:12px}}
  pre.evidence{{background:#020617;padding:12px;border-radius:6px;border-left:3px solid #ff3b30;overflow-x:auto;color:#f87171;font-size:12px;font-family:monospace}}
  .footer{{margin-top:30px;color:#334155;font-size:11px;text-align:center}}
</style>
</head>
<body>
  <h1>☁️ Cloud Misconfiguration Hunter</h1>
  <div class="subtitle">Scanned {summary['scanned_at']} · {summary['files_scanned']} IaC files · CIS AWS Benchmark mapped</div>

  <div class="stats">
    <div class="stat"><div class="n">{summary['total_findings']}</div><div class="l">Total Findings</div></div>
    <div class="stat"><div class="n" style="color:#ff3b30">{summary['by_severity']['CRITICAL']}</div><div class="l">Critical</div></div>
    <div class="stat"><div class="n" style="color:#ff9500">{summary['by_severity']['HIGH']}</div><div class="l">High</div></div>
    <div class="stat"><div class="n" style="color:#ffcc00">{summary['by_severity']['MEDIUM']}</div><div class="l">Medium</div></div>
    <div class="stat"><div class="n" style="color:#34c759">{summary['by_severity']['LOW']}</div><div class="l">Low</div></div>
  </div>

  <div class="chips">{svc_chips}</div>

  {''.join(cards)}

  <div class="footer">Cloud Misconfiguration Hunter · github.com/CyberEnthusiastic</div>

<script>
function toggle(i){{document.getElementById('fb-'+i).classList.toggle('open');}}
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fp:
        fp.write(html)
