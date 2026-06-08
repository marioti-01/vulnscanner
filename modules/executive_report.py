"""
Executive Report Generator
Gera seção executiva com CVSS formal, risco por categoria,
sumário para gestão e recomendações priorizadas.
"""

import datetime
from typing import List, Dict


# CVSS v3.1 Base Score lookup simplificado
# (Para cálculo completo precisaria de todos os vetores)
CVSS_SEVERITY_MAP = {
    "critical": {"range": (9.0, 10.0), "label": "Critical", "color": "#FF4757"},
    "high":     {"range": (7.0, 8.9),  "label": "High",     "color": "#FFA502"},
    "medium":   {"range": (4.0, 6.9),  "label": "Medium",   "color": "#3742FA"},
    "low":      {"range": (0.1, 3.9),  "label": "Low",      "color": "#2ED573"},
    "info":     {"range": (0.0, 0.0),  "label": "Info",     "color": "#747D8C"},
}

# Categorias de risco por módulo
RISK_CATEGORIES = {
    "SSL/TLS":             "Criptografia e Transporte",
    "Headers HTTP":        "Configuração de Segurança",
    "Port Scanner":        "Exposição de Superfície",
    "OWASP Web":           "Vulnerabilidades de Aplicação",
    "DNS / Subdomains":    "Infraestrutura DNS",
    "CORS Policy":         "Controle de Acesso entre Origens",
    "Tecnologias / WAF":   "Fingerprinting e Proteção",
    "Redirects":           "Lógica de Navegação",
    "CVE Lookup":          "Vulnerabilidades Conhecidas (CVE)",
    "Crawler / Spider":    "Reconhecimento de Superfície",
    "Blind SQL Injection":  "Injeção de Dados",
    "IDOR":                "Controle de Acesso a Objetos",
    "SSRF":                "Requisições Forjadas pelo Servidor",
    "XXE":                 "Processamento XML",
    "Auth Flow":           "Autenticação",
}

# Score de risco negócio por severidade
BUSINESS_RISK = {
    "critical": "Risco imediato — exploração trivial pode comprometer dados/sistemas",
    "high":     "Risco alto — exploração requer esforço moderado mas impacto severo",
    "medium":   "Risco médio — exploração complexa ou impacto limitado",
    "low":      "Risco baixo — melhoria de postura de segurança recomendada",
    "info":     "Informativo — sem risco direto",
}

# Prioridade de remediação em dias
REMEDIATION_SLA = {
    "critical": 1,
    "high":     7,
    "medium":   30,
    "low":      90,
    "info":     None,
}


def _get_cvss_score(finding: dict) -> float:
    """Extrai ou estima score CVSS de um finding."""
    # Se o finding já tem CVSS calculado
    if "cvss" in finding:
        try:
            return float(finding["cvss"])
        except (ValueError, TypeError):
            pass

    # Estima pela severidade
    sev = finding.get("severity", "info")
    ranges = {
        "critical": 9.5,
        "high": 8.0,
        "medium": 5.5,
        "low": 2.5,
        "info": 0.0,
    }
    return ranges.get(sev, 0.0)


def _categorize_findings(modules_results: list) -> dict:
    """Agrupa findings por categoria de risco."""
    categories = {}

    for mod in modules_results:
        mod_name = mod.get("module", "Outros")
        category = RISK_CATEGORIES.get(mod_name, "Outros")

        if category not in categories:
            categories[category] = {
                "modules": [],
                "findings": [],
                "max_severity": "info",
                "cvss_scores": [],
            }

        categories[category]["modules"].append(mod_name)

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        current_max = categories[category]["max_severity"]

        for f in mod.get("findings", []):
            sev = f.get("severity", "info")
            categories[category]["findings"].append(f)
            categories[category]["cvss_scores"].append(_get_cvss_score(f))

            if sev_order.get(sev, 99) < sev_order.get(current_max, 99):
                categories[category]["max_severity"] = sev

    return categories


def _top_findings(modules_results: list, limit: int = 10) -> list:
    """Retorna os findings mais críticos ordenados por CVSS."""
    all_findings = []
    for mod in modules_results:
        for f in mod.get("findings", []):
            if f.get("severity") not in ("critical", "high"):
                continue
            all_findings.append({
                "module": mod.get("module", ""),
                "finding": f,
                "cvss": _get_cvss_score(f),
            })

    return sorted(all_findings, key=lambda x: x["cvss"], reverse=True)[:limit]


def _remediation_roadmap(modules_results: list) -> list:
    """Gera roadmap de remediação priorizado."""
    roadmap = []
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    all_actionable = []
    for mod in modules_results:
        for f in mod.get("findings", []):
            if f.get("severity") == "info" or not f.get("fix"):
                continue
            all_actionable.append({
                "severity": f.get("severity"),
                "title": f.get("title", ""),
                "fix": f.get("fix", ""),
                "module": mod.get("module", ""),
                "sla_days": REMEDIATION_SLA.get(f.get("severity"), 90),
                "cvss": _get_cvss_score(f),
            })

    all_actionable.sort(key=lambda x: (sev_order.get(x["severity"], 99), -x["cvss"]))

    # Deduplica por fix similar
    seen_fixes = set()
    for item in all_actionable:
        fix_key = item["fix"][:50]
        if fix_key not in seen_fixes:
            roadmap.append(item)
            seen_fixes.add(fix_key)

    return roadmap[:20]


def generate_executive_report(
    url: str,
    scan_id: str,
    elapsed: float,
    score: int,
    counts: dict,
    modules_results: list,
    recheck_log: list = None,
    fp_count: int = 0,
    confirmed_count: int = 0,
) -> dict:
    """
    Gera dados para o relatório executivo completo.
    """
    now = datetime.datetime.now(datetime.timezone.utc)

    # Calcula CVSS máximo
    max_cvss = 0.0
    all_cvss = []
    for mod in modules_results:
        for f in mod.get("findings", []):
            score_cvss = _get_cvss_score(f)
            all_cvss.append(score_cvss)
            if score_cvss > max_cvss:
                max_cvss = score_cvss

    avg_cvss = sum(all_cvss) / len(all_cvss) if all_cvss else 0.0

    # Nível de risco geral
    if counts.get("critical", 0) > 0 or max_cvss >= 9.0:
        overall_risk = "CRÍTICO"
        overall_color = "#FF4757"
    elif counts.get("high", 0) > 0 or max_cvss >= 7.0:
        overall_risk = "ALTO"
        overall_color = "#FFA502"
    elif counts.get("medium", 0) > 0:
        overall_risk = "MÉDIO"
        overall_color = "#3742FA"
    elif counts.get("low", 0) > 0:
        overall_risk = "BAIXO"
        overall_color = "#2ED573"
    else:
        overall_risk = "MÍNIMO"
        overall_color = "#2ED573"

    categories = _categorize_findings(modules_results)
    top_findings = _top_findings(modules_results)
    roadmap = _remediation_roadmap(modules_results)

    # Sumário executivo em texto
    total_issues = sum(v for k, v in counts.items() if k != "info")
    critical_count = counts.get("critical", 0)
    high_count = counts.get("high", 0)

    if critical_count > 0:
        exec_headline = (
            f"A varredura identificou {critical_count} vulnerabilidade(s) CRÍTICA(s) "
            f"que requerem atenção imediata. "
        )
    elif high_count > 0:
        exec_headline = (
            f"A varredura identificou {high_count} vulnerabilidade(s) de severidade ALTA. "
        )
    else:
        exec_headline = "Nenhuma vulnerabilidade crítica ou alta identificada. "

    exec_summary = (
        f"{exec_headline}"
        f"Foram analisados {len(modules_results)} módulos de segurança em {elapsed}s, "
        f"resultando em {total_issues} problema(s) acionável(is) "
        f"({critical_count} críticos, {high_count} altos, "
        f"{counts.get('medium', 0)} médios, {counts.get('low', 0)} baixos). "
        f"Score de segurança: {score}/100. "
        f"CVSS máximo detectado: {max_cvss:.1f}."
    )

    return {
        "executive": {
            "headline": exec_headline,
            "summary": exec_summary,
            "overall_risk": overall_risk,
            "overall_color": overall_color,
            "score": score,
            "max_cvss": round(max_cvss, 1),
            "avg_cvss": round(avg_cvss, 1),
            "total_issues": total_issues,
            "timestamp": now.isoformat(),
            "scan_date": now.strftime("%d/%m/%Y %H:%M UTC"),
            "target": url,
            "scan_id": scan_id,
            "elapsed": elapsed,
            "modules_run": len(modules_results),
        },
        "counts": counts,
        "categories": {
            name: {
                "max_severity": data["max_severity"],
                "finding_count": len(data["findings"]),
                "modules": data["modules"],
                "avg_cvss": round(
                    sum(data["cvss_scores"]) / len(data["cvss_scores"])
                    if data["cvss_scores"] else 0.0, 1
                ),
            }
            for name, data in categories.items()
        },
        "top_findings": [
            {
                "module": tf["module"],
                "title": tf["finding"]["title"],
                "severity": tf["finding"]["severity"],
                "cvss": tf["cvss"],
                "fix": tf["finding"].get("fix", ""),
                "sla_days": REMEDIATION_SLA.get(tf["finding"]["severity"]),
            }
            for tf in top_findings
        ],
        "roadmap": roadmap,
        "verification": {
            "confirmed": confirmed_count,
            "false_positives": fp_count,
            "log": recheck_log or [],
        },
    }
