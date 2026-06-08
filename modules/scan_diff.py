"""
Scan Diff — VulnScanner v6
Compara dois relatórios de scan e gera delta de segurança:
- Vulnerabilidades novas (regressão)
- Vulnerabilidades corrigidas (melhoria)
- Vulnerabilidades persistentes
- Variação de score e CVSS
"""

from typing import Dict, List, Tuple


SEVERITY_SCORE = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _normalize_title(title: str) -> str:
    """Normaliza título para comparação (remove prefixos como [FP?], [CHAIN])."""
    import re
    title = re.sub(r"\[.*?\]\s*", "", title)
    return title.strip().lower()


def _extract_findings(report: Dict) -> List[Dict]:
    """Extrai todos os findings relevantes de um relatório."""
    findings = []
    for mod in report.get("modules", []):
        for f in mod.get("findings", []):
            if f.get("severity") == "info":
                continue
            findings.append({
                "module": mod.get("module", ""),
                "severity": f.get("severity", "info"),
                "title": f.get("title", ""),
                "title_norm": _normalize_title(f.get("title", "")),
                "fix": f.get("fix", ""),
                "cvss": float(f.get("cvss", 0) or 0),
            })
    return findings


def _match_findings(old_findings: List[Dict], new_findings: List[Dict]) -> Tuple[List, List, List]:
    """
    Faz matching de findings entre dois scans.
    Retorna: (novos, corrigidos, persistentes)
    """
    old_keys = {f["title_norm"]: f for f in old_findings}
    new_keys = {f["title_norm"]: f for f in new_findings}

    new_vulns = [f for k, f in new_keys.items() if k not in old_keys]
    fixed_vulns = [f for k, f in old_keys.items() if k not in new_keys]
    persistent = [f for k, f in new_keys.items() if k in old_keys]

    return new_vulns, fixed_vulns, persistent


def _severity_delta(old_counts: Dict, new_counts: Dict) -> Dict:
    """Calcula variação de contagem por severidade."""
    delta = {}
    for sev in ("critical", "high", "medium", "low", "info"):
        old_val = old_counts.get(sev, 0)
        new_val = new_counts.get(sev, 0)
        delta[sev] = {
            "old": old_val,
            "new": new_val,
            "diff": new_val - old_val,
            "trend": "up" if new_val > old_val else "down" if new_val < old_val else "same",
        }
    return delta


def _risk_assessment(new_vulns: List, fixed_vulns: List, score_old: int, score_new: int) -> str:
    """Gera avaliação textual do delta de segurança."""
    if not new_vulns and not fixed_vulns:
        return "Nenhuma mudança detectada entre os dois scans."

    critical_new = [v for v in new_vulns if v["severity"] == "critical"]
    high_new = [v for v in new_vulns if v["severity"] == "high"]
    critical_fixed = [v for v in fixed_vulns if v["severity"] == "critical"]

    parts = []

    if critical_new:
        parts.append(
            f"⚠️ REGRESSÃO CRÍTICA: {len(critical_new)} nova(s) vulnerabilidade(s) crítica(s) "
            f"foram introduzidas desde o último scan. Revisão imediata necessária."
        )
    elif high_new:
        parts.append(
            f"⚡ {len(high_new)} nova(s) vulnerabilidade(s) alta(s) detectada(s). "
            f"Priorize a remediação antes do próximo deploy."
        )

    if critical_fixed:
        parts.append(
            f"✅ {len(critical_fixed)} vulnerabilidade(s) crítica(s) corrigida(s) desde o último scan."
        )

    score_diff = score_new - score_old
    if score_diff > 0:
        parts.append(f"📈 Score de segurança melhorou {score_diff} pontos ({score_old} → {score_new}).")
    elif score_diff < 0:
        parts.append(f"📉 Score de segurança piorou {abs(score_diff)} pontos ({score_old} → {score_new}).")
    else:
        parts.append(f"Score estável em {score_new}/100.")

    if fixed_vulns and not new_vulns:
        parts.append(f"🎉 {len(fixed_vulns)} problema(s) corrigido(s), nenhum novo introduzido.")

    return " ".join(parts)


def compare_scans(report_old: Dict, report_new: Dict) -> Dict:
    """
    Compara dois relatórios de scan completos.

    Args:
        report_old: Relatório do scan anterior (base)
        report_new: Relatório do scan atual (comparação)

    Returns:
        Dict com delta completo: novos, corrigidos, persistentes, scores, tendências.
    """
    old_findings = _extract_findings(report_old)
    new_findings = _extract_findings(report_new)

    new_vulns, fixed_vulns, persistent = _match_findings(old_findings, new_findings)

    score_old = report_old.get("score", 0)
    score_new = report_new.get("score", 0)

    counts_old = report_old.get("counts", {})
    counts_new = report_new.get("counts", {})
    severity_delta = _severity_delta(counts_old, counts_new)

    # CVSS médio
    def avg_cvss(findings):
        scores = [f["cvss"] for f in findings if f["cvss"] > 0]
        return round(sum(scores) / len(scores), 1) if scores else 0.0

    # Determina status geral do diff
    critical_new = any(f["severity"] == "critical" for f in new_vulns)
    high_new = any(f["severity"] == "high" for f in new_vulns)

    if critical_new:
        diff_status = "regression_critical"
    elif high_new:
        diff_status = "regression_high"
    elif fixed_vulns and not new_vulns:
        diff_status = "improved"
    elif not new_vulns and not fixed_vulns:
        diff_status = "unchanged"
    else:
        diff_status = "mixed"

    return {
        "scan_old": {
            "scan_id": report_old.get("scan_id"),
            "url": report_old.get("url"),
            "date": report_old.get("timestamp", ""),
            "score": score_old,
        },
        "scan_new": {
            "scan_id": report_new.get("scan_id"),
            "url": report_new.get("url"),
            "date": report_new.get("timestamp", ""),
            "score": score_new,
        },
        "score_delta": score_new - score_old,
        "diff_status": diff_status,
        "risk_assessment": _risk_assessment(new_vulns, fixed_vulns, score_old, score_new),
        "summary": {
            "new_count": len(new_vulns),
            "fixed_count": len(fixed_vulns),
            "persistent_count": len(persistent),
            "total_old": len(old_findings),
            "total_new": len(new_findings),
        },
        "severity_delta": severity_delta,
        "new_vulnerabilities": sorted(
            new_vulns, key=lambda x: SEVERITY_SCORE.get(x["severity"], 0), reverse=True
        ),
        "fixed_vulnerabilities": sorted(
            fixed_vulns, key=lambda x: SEVERITY_SCORE.get(x["severity"], 0), reverse=True
        ),
        "persistent_vulnerabilities": sorted(
            persistent, key=lambda x: SEVERITY_SCORE.get(x["severity"], 0), reverse=True
        ),
        "cvss_avg_old": avg_cvss(old_findings),
        "cvss_avg_new": avg_cvss(new_findings),
    }
