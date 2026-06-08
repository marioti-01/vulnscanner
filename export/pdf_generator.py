"""
PDF Export — VulnScanner v6
Gera relatório PDF profissional usando WeasyPrint.
Fallback para HTML se WeasyPrint não estiver disponível.
"""

import datetime
import io
from typing import Dict


def _build_html(report: Dict) -> str:
    """Constrói HTML otimizado para conversão PDF."""
    url     = report.get("url", "")
    scan_id = report.get("scan_id", "")
    score   = report.get("score", 0)
    elapsed = report.get("elapsed", 0)
    counts  = report.get("counts", {})
    ts      = report.get("timestamp", "")[:10]
    ex      = report.get("executive", {}).get("executive", {})
    modules = report.get("modules", [])

    # Score color
    if score >= 70:
        score_color = "#2ED573"
        risk_label = "BOM"
    elif score >= 40:
        score_color = "#FFA502"
        risk_label = "ATENÇÃO"
    else:
        score_color = "#FF4757"
        risk_label = "CRÍTICO"

    sev_colors = {
        "critical": "#FF4757",
        "high":     "#FFA502",
        "medium":   "#3742FA",
        "low":      "#2ED573",
        "info":     "#888",
    }

    def sev_badge(sev):
        c = sev_colors.get(sev, "#888")
        return f'<span style="background:{c}22;color:{c};border:1px solid {c}44;border-radius:4px;padding:1px 6px;font-size:10px;font-weight:700">{sev.upper()}</span>'

    # Findings rows
    findings_rows = ""
    for mod in modules:
        for f in mod.get("findings", []):
            if f.get("severity") == "info":
                continue
            sev = f.get("severity", "info")
            c = sev_colors.get(sev, "#888")
            findings_rows += f"""
            <tr>
                <td style="color:#666;font-size:11px">{mod.get('module','')}</td>
                <td>{sev_badge(sev)}</td>
                <td style="font-size:12px">{f.get('title','')[:80]}</td>
                <td style="font-size:11px;color:#666">{f.get('cvss','') or '—'}</td>
            </tr>"""

    # Attack chains
    chains_section = ""
    for mod in modules:
        if mod.get("module") == "Attack Chain Engine" and mod.get("chains"):
            chains_section = '<div class="page-break"></div><h2>⛓ Attack Chains</h2>'
            for chain in mod["chains"]:
                sev = chain.get("severity", "high")
                c = sev_colors.get(sev, "#888")
                involved = " → ".join(chain.get("findings_involved", []))
                poc = chain.get("poc_conceptual", "")
                poc_block = f'<div class="code-block">{poc}</div>' if poc and "API key" not in poc else ""
                chains_section += f"""
                <div style="border:1px solid {c}44;border-radius:8px;padding:14px;margin-bottom:14px;background:{c}08">
                    <div style="font-size:14px;font-weight:700;color:{c};margin-bottom:6px">{chain.get('title','')}</div>
                    <div style="font-size:11px;color:#666;margin-bottom:8px">Findings: {involved}</div>
                    <p style="font-size:12px;margin-bottom:8px">{chain.get('attack_narrative','')}</p>
                    {poc_block}
                    <div style="font-size:11px;background:#f0fdf4;border-left:3px solid #2ED573;padding:8px;border-radius:0 4px 4px 0;margin-top:8px">
                        <strong style="color:#2ED573">Remediação:</strong> {chain.get('unified_fix','')}
                    </div>
                </div>"""
            break

    # Roadmap
    roadmap_rows = ""
    roadmap = report.get("executive", {}).get("roadmap", [])
    for i, item in enumerate(roadmap[:15], 1):
        sev = item.get("severity", "low")
        sla = item.get("sla_days")
        sla_str = f"{sla}d" if sla else "—"
        roadmap_rows += f"""
        <tr>
            <td style="text-align:center;color:#888;font-size:11px">{i}</td>
            <td>{sev_badge(sev)}</td>
            <td style="font-size:12px">{item.get('title','')[:70]}</td>
            <td style="font-size:11px;color:#666">{item.get('module','')}</td>
            <td style="text-align:center;font-weight:700;font-size:11px">{sla_str}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Helvetica Neue', Arial, sans-serif; color: #1a1a2e; font-size: 13px; line-height: 1.5; }}
  .page-break {{ page-break-before: always; margin-top: 30px; }}

  /* Cover */
  .cover {{ background: linear-gradient(135deg, #0a0e1a 0%, #1a1d2e 100%); color: white; padding: 60px 50px; min-height: 100vh; display: flex; flex-direction: column; justify-content: space-between; }}
  .cover-logo {{ font-size: 32px; font-weight: 800; letter-spacing: -1px; }}
  .cover-logo span {{ color: #FF4757; }}
  .cover-title {{ font-size: 28px; font-weight: 700; margin-top: 40px; }}
  .cover-url {{ font-size: 16px; color: #94A3B8; margin-top: 8px; word-break: break-all; }}
  .cover-score {{ display: inline-block; width: 120px; height: 120px; border-radius: 50%; border: 6px solid {score_color}; text-align: center; padding-top: 25px; margin-top: 40px; }}
  .cover-score-num {{ font-size: 36px; font-weight: 800; color: {score_color}; line-height: 1; }}
  .cover-score-lbl {{ font-size: 11px; font-weight: 700; color: {score_color}; text-transform: uppercase; letter-spacing: .1em; }}
  .cover-meta {{ color: #64748B; font-size: 12px; }}
  .cover-pills {{ display: flex; gap: 10px; flex-wrap: wrap; margin-top: 20px; }}
  .cover-pill {{ padding: 4px 12px; border-radius: 99px; font-size: 11px; font-weight: 700; border: 1px solid; }}

  /* Content */
  .content {{ padding: 40px 50px; }}
  h2 {{ font-size: 18px; font-weight: 700; margin: 30px 0 14px; border-bottom: 2px solid #f0f0f0; padding-bottom: 6px; color: #0a0e1a; }}
  h3 {{ font-size: 14px; font-weight: 600; margin: 20px 0 8px; color: #334155; }}
  p {{ margin-bottom: 10px; color: #475569; }}

  /* Summary box */
  .summary-box {{ background: #fff8f8; border-left: 4px solid #FF4757; border-radius: 0 8px 8px 0; padding: 14px 16px; margin-bottom: 20px; font-size: 13px; color: #475569; line-height: 1.7; }}

  /* Counts grid */
  .counts-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-bottom: 24px; }}
  .count-card {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px; text-align: center; }}
  .count-num {{ font-size: 24px; font-weight: 800; }}
  .count-lbl {{ font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: .06em; color: #888; }}

  /* Tables */
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 16px; }}
  th {{ background: #f8fafc; padding: 8px 10px; font-size: 11px; font-weight: 600; color: #64748B; text-transform: uppercase; letter-spacing: .06em; text-align: left; border-bottom: 2px solid #e2e8f0; }}
  td {{ padding: 8px 10px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }}
  tr:hover td {{ background: #fafafa; }}

  .code-block {{ background: #0a0e1a; color: #7dd3fc; font-family: monospace; font-size: 11px; padding: 10px; border-radius: 6px; white-space: pre-wrap; word-break: break-all; margin: 8px 0; }}

  /* Footer */
  .footer {{ position: fixed; bottom: 20px; left: 0; right: 0; text-align: center; font-size: 10px; color: #94A3B8; }}
  .footer::before {{ content: "VulnScanner v6 — Confidencial — Use apenas em sistemas autorizados"; }}
  @page {{ margin: 0 0 40px 0; }}
</style>
</head>
<body>

<!-- CAPA -->
<div class="cover">
  <div>
    <div class="cover-logo">Vuln<span>Scanner</span></div>
    <div class="cover-title">Relatório de Segurança</div>
    <div class="cover-url">{url}</div>
  </div>
  <div>
    <div class="cover-score">
      <div class="cover-score-num">{score}</div>
      <div class="cover-score-lbl">{risk_label}</div>
    </div>
    <div class="cover-pills" style="margin-top:20px">
      <span class="cover-pill" style="color:#FF4757;border-color:#FF4757">{counts.get('critical',0)} Critical</span>
      <span class="cover-pill" style="color:#FFA502;border-color:#FFA502">{counts.get('high',0)} High</span>
      <span class="cover-pill" style="color:#3742FA;border-color:#3742FA">{counts.get('medium',0)} Medium</span>
      <span class="cover-pill" style="color:#2ED573;border-color:#2ED573">{counts.get('low',0)} Low</span>
    </div>
  </div>
  <div class="cover-meta">
    Data: {ts} &nbsp;·&nbsp; Scan ID: {scan_id} &nbsp;·&nbsp; Duração: {elapsed}s
  </div>
</div>

<!-- CONTEÚDO -->
<div class="content">

  <h2>Sumário Executivo</h2>
  <div class="summary-box">{ex.get('summary', 'N/A')}</div>

  <div class="counts-grid">
    <div class="count-card"><div class="count-num" style="color:#FF4757">{counts.get('critical',0)}</div><div class="count-lbl">Critical</div></div>
    <div class="count-card"><div class="count-num" style="color:#FFA502">{counts.get('high',0)}</div><div class="count-lbl">High</div></div>
    <div class="count-card"><div class="count-num" style="color:#3742FA">{counts.get('medium',0)}</div><div class="count-lbl">Medium</div></div>
    <div class="count-card"><div class="count-num" style="color:#2ED573">{counts.get('low',0)}</div><div class="count-lbl">Low</div></div>
    <div class="count-card"><div class="count-num" style="color:#FF4757">{ex.get('max_cvss','0')}</div><div class="count-lbl">CVSS Max</div></div>
  </div>

  <div class="page-break"></div>
  <h2>Vulnerabilidades Encontradas</h2>
  <table>
    <tr><th>Módulo</th><th>Severidade</th><th>Vulnerabilidade</th><th>CVSS</th></tr>
    {findings_rows if findings_rows else '<tr><td colspan="4" style="text-align:center;color:#888;padding:20px">Nenhuma vulnerabilidade crítica/alta/média/baixa encontrada.</td></tr>'}
  </table>

  {chains_section}

  <div class="page-break"></div>
  <h2>Roadmap de Remediação</h2>
  <table>
    <tr><th>#</th><th>Sev</th><th>Ação</th><th>Módulo</th><th>SLA</th></tr>
    {roadmap_rows if roadmap_rows else '<tr><td colspan="5" style="text-align:center;color:#888;padding:20px">Nenhuma ação de remediação identificada.</td></tr>'}
  </table>

</div>

<div class="footer"></div>
</body>
</html>"""

    return html


def export_pdf(report: Dict) -> bytes:
    """
    Exporta relatório como PDF.
    Usa WeasyPrint se disponível, caso contrário retorna HTML.
    """
    html = _build_html(report)

    try:
        from weasyprint import HTML, CSS
        pdf_bytes = HTML(string=html, base_url=None).write_pdf()
        return pdf_bytes, "application/pdf", ".pdf"
    except ImportError:
        # Fallback para HTML se WeasyPrint não estiver instalado
        return html.encode("utf-8"), "text/html", ".html"
    except Exception as e:
        # Fallback para HTML em caso de erro
        return html.encode("utf-8"), "text/html", ".html"


def export_html(report: Dict) -> bytes:
    """Exporta o HTML do relatório (sempre disponível)."""
    return _build_html(report).encode("utf-8")
