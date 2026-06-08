"""
Compliance Report — VulnScanner v8
Mapeia findings automaticamente para frameworks de compliance:
- OWASP Top 10 2021
- PCI DSS 4.0
- NIST SP 800-53

Gera relatório de conformidade com status por controle.
"""

from typing import Dict, List


# ── OWASP Top 10 2021 ─────────────────────────────────────────────────────────

OWASP_TOP10_2021 = {
    "A01:2021": {
        "name": "Broken Access Control",
        "keywords": ["idor", "acesso", "autorização", "permission", "privilege",
                     "unauthorized", "object reference", "path traversal"],
        "description": "Restrições de controle de acesso não são aplicadas corretamente.",
    },
    "A02:2021": {
        "name": "Cryptographic Failures",
        "keywords": ["ssl", "tls", "https", "cipher", "certificado", "criptografia",
                     "hsts", "http não", "sem https", "weak cipher", "expirado"],
        "description": "Falhas relacionadas à criptografia que expõem dados sensíveis.",
    },
    "A03:2021": {
        "name": "Injection",
        "keywords": ["sql", "injection", "xss", "sqli", "xxe", "ldap", "command",
                     "template injection", "blind sql", "xpath"],
        "description": "Dados não confiáveis enviados como parte de comando ou query.",
    },
    "A04:2021": {
        "name": "Insecure Design",
        "keywords": ["csrf", "race condition", "logic", "workflow", "business",
                     "open redirect", "ssrf"],
        "description": "Riscos relacionados a falhas de design e arquitetura.",
    },
    "A05:2021": {
        "name": "Security Misconfiguration",
        "keywords": ["header", "csp", "x-frame", "cors", "default", "debug",
                     "misconfiguration", "directory listing", "arquivo sensível",
                     "exposto", "server version", "versão exposta", "permissions-policy"],
        "description": "Configurações de segurança ausentes, incorretas ou padrão.",
    },
    "A06:2021": {
        "name": "Vulnerable and Outdated Components",
        "keywords": ["cve", "vulnerabilidade conhecida", "outdated", "versão",
                     "componente", "library", "dependência", "desatualizado"],
        "description": "Uso de componentes com vulnerabilidades conhecidas.",
    },
    "A07:2021": {
        "name": "Identification and Authentication Failures",
        "keywords": ["login", "auth", "senha", "password", "session", "cookie",
                     "token", "httponly", "secure", "samesite", "csrf token"],
        "description": "Falhas relacionadas à identidade, autenticação e gestão de sessão.",
    },
    "A08:2021": {
        "name": "Software and Data Integrity Failures",
        "keywords": ["deserialization", "integrity", "update", "cdn", "subresource",
                     "supply chain", "pipeline"],
        "description": "Código e infraestrutura sem proteção contra violações de integridade.",
    },
    "A09:2021": {
        "name": "Security Logging and Monitoring Failures",
        "keywords": ["log", "monitoring", "audit", "detection", "alert"],
        "description": "Falta de logging e monitoramento adequados.",
    },
    "A10:2021": {
        "name": "Server-Side Request Forgery",
        "keywords": ["ssrf", "server-side request", "internal", "metadata",
                     "169.254", "localhost"],
        "description": "Servidor faz requisições para URLs controladas pelo atacante.",
    },
}


# ── PCI DSS 4.0 ───────────────────────────────────────────────────────────────

PCI_DSS_4 = {
    "Req 2.2": {
        "name": "System Components Configuration",
        "keywords": ["versão exposta", "server header", "default config",
                     "misconfiguration", "debug", "desnecessário"],
        "description": "Configurações seguras estabelecidas para todos os componentes.",
    },
    "Req 4.2": {
        "name": "Strong Cryptography in Transmission",
        "keywords": ["ssl", "tls", "https", "cipher", "certificado", "hsts",
                     "http não criptografado", "weak cipher", "tls 1.0", "tls 1.1"],
        "description": "Dados de titulares de cartão protegidos com criptografia forte.",
    },
    "Req 6.2": {
        "name": "Bespoke and Custom Software Security",
        "keywords": ["xss", "sql injection", "sqli", "xxe", "ssrf", "idor",
                     "input validation", "csrf", "injection"],
        "description": "Software desenvolvido de forma segura.",
    },
    "Req 6.4": {
        "name": "Public-Facing Web Applications Protection",
        "keywords": ["waf", "web application firewall", "owasp", "vulnerability scan"],
        "description": "Aplicações web voltadas ao público protegidas contra ataques.",
    },
    "Req 7.2": {
        "name": "Access Control Systems",
        "keywords": ["idor", "access control", "autorização", "privilege",
                     "unauthorized"],
        "description": "Acesso a recursos restrito a indivíduos autorizados.",
    },
    "Req 8.3": {
        "name": "Authentication for Users and Administrators",
        "keywords": ["login", "auth", "password", "mfa", "session", "cookie",
                     "httponly", "session fixation"],
        "description": "Autenticação forte para todos os usuários.",
    },
    "Req 9.5": {
        "name": "Point-of-Interaction Devices Security",
        "keywords": ["physical", "device", "terminal"],
        "description": "Dispositivos de interação física protegidos.",
    },
    "Req 11.3": {
        "name": "External and Internal Vulnerabilities",
        "keywords": ["vulnerability", "scan", "penetration test", "cve",
                     "vulnerabilidade conhecida", "port", "exposed service"],
        "description": "Vulnerabilidades externas e internas identificadas e gerenciadas.",
    },
}


# ── NIST SP 800-53 ────────────────────────────────────────────────────────────

NIST_800_53 = {
    "AC-3": {
        "name": "Access Enforcement",
        "keywords": ["idor", "access control", "unauthorized", "privilege",
                     "permission", "authorization"],
        "description": "Controles de acesso aplicados conforme política.",
    },
    "AU-2": {
        "name": "Event Logging",
        "keywords": ["log", "audit", "event", "monitoring"],
        "description": "Eventos auditáveis identificados e registrados.",
    },
    "IA-5": {
        "name": "Authenticator Management",
        "keywords": ["password", "credential", "token", "session", "cookie",
                     "httponly", "auth"],
        "description": "Autenticadores gerenciados de forma segura.",
    },
    "SC-5": {
        "name": "Denial-of-Service Protection",
        "keywords": ["ddos", "rate limit", "flood"],
        "description": "Proteção contra ataques de negação de serviço.",
    },
    "SC-8": {
        "name": "Transmission Confidentiality and Integrity",
        "keywords": ["ssl", "tls", "https", "cipher", "hsts", "criptografia",
                     "http sem criptografia"],
        "description": "Informações protegidas durante transmissão.",
    },
    "SC-18": {
        "name": "Mobile Code",
        "keywords": ["xss", "javascript", "csp", "content security policy",
                     "script injection", "unsafe-inline"],
        "description": "Código móvel (JavaScript) autorizado e controlado.",
    },
    "SI-2": {
        "name": "Flaw Remediation",
        "keywords": ["cve", "patch", "vulnerability", "vulnerabilidade conhecida",
                     "outdated", "desatualizado"],
        "description": "Falhas identificadas, relatadas e corrigidas.",
    },
    "SI-3": {
        "name": "Malware Protection",
        "keywords": ["malware", "backdoor", "webshell", "upload"],
        "description": "Proteção contra código malicioso.",
    },
    "SI-10": {
        "name": "Information Input Validation",
        "keywords": ["sql injection", "xss", "xxe", "input validation",
                     "injection", "sqli", "blind sql"],
        "description": "Validação de entradas de informação.",
    },
    "RA-5": {
        "name": "Vulnerability Monitoring and Scanning",
        "keywords": ["vulnerability scan", "port", "exposed", "open port",
                     "service", "cve"],
        "description": "Sistemas monitorados e scaneados para vulnerabilidades.",
    },
}


def _match_finding_to_controls(
    finding: Dict,
    controls: Dict,
) -> List[str]:
    """Mapeia um finding para os controles relevantes."""
    text = (
        finding.get("title", "") + " " +
        finding.get("detail", "")
    ).lower()

    matched = []
    for control_id, control in controls.items():
        if any(kw in text for kw in control["keywords"]):
            matched.append(control_id)
    return matched


def _build_framework_report(
    framework_name: str,
    controls: Dict,
    findings: List[Dict],
) -> Dict:
    """Constrói relatório de compliance para um framework."""
    control_status = {}

    for control_id, control in controls.items():
        matched_findings = []
        for f in findings:
            if f.get("severity") == "info":
                continue
            if any(kw in (f.get("title","") + f.get("detail","")).lower()
                   for kw in control["keywords"]):
                matched_findings.append({
                    "severity": f.get("severity"),
                    "title":    f.get("title", "")[:100],
                    "module":   f.get("module", ""),
                })

        if not matched_findings:
            status = "pass"
        else:
            sevs = [f["severity"] for f in matched_findings]
            if "critical" in sevs:
                status = "fail_critical"
            elif "high" in sevs:
                status = "fail_high"
            else:
                status = "fail_medium"

        control_status[control_id] = {
            "name":     control["name"],
            "desc":     control["description"],
            "status":   status,
            "findings": matched_findings,
        }

    # Calcular score de compliance
    total     = len(controls)
    passing   = sum(1 for c in control_status.values() if c["status"] == "pass")
    pct       = round((passing / total) * 100) if total > 0 else 100

    fail_crit = sum(1 for c in control_status.values() if c["status"] == "fail_critical")
    fail_high = sum(1 for c in control_status.values() if c["status"] == "fail_high")
    fail_med  = sum(1 for c in control_status.values() if c["status"] == "fail_medium")

    if pct >= 90 and fail_crit == 0:
        compliance_level = "Conforme"
        level_color      = "#2ED573"
    elif pct >= 70 and fail_crit == 0:
        compliance_level = "Parcialmente Conforme"
        level_color      = "#FFA502"
    else:
        compliance_level = "Não Conforme"
        level_color      = "#FF4757"

    return {
        "framework":       framework_name,
        "score_pct":       pct,
        "compliance_level": compliance_level,
        "level_color":     level_color,
        "total_controls":  total,
        "passing":         passing,
        "fail_critical":   fail_crit,
        "fail_high":       fail_high,
        "fail_medium":     fail_med,
        "controls":        control_status,
    }


def generate_compliance_report(modules_results: List[Dict]) -> Dict:
    """
    Gera relatório de compliance completo para todos os frameworks.

    Args:
        modules_results: Lista de resultados dos módulos de scan

    Returns:
        Dict com relatórios OWASP, PCI DSS e NIST
    """
    # Flatten findings com módulo de origem
    all_findings = []
    for mod in modules_results:
        for f in mod.get("findings", []):
            all_findings.append({
                **f,
                "module": mod.get("module", ""),
            })

    owasp  = _build_framework_report("OWASP Top 10 2021", OWASP_TOP10_2021, all_findings)
    pci    = _build_framework_report("PCI DSS 4.0",       PCI_DSS_4,        all_findings)
    nist   = _build_framework_report("NIST SP 800-53",    NIST_800_53,      all_findings)

    # Score geral de compliance (média ponderada)
    overall_score = round((owasp["score_pct"] * 0.4 + pci["score_pct"] * 0.35 +
                           nist["score_pct"] * 0.25))

    # Controles críticos falhando (união dos frameworks)
    critical_gaps = []
    for framework_data in [owasp, pci, nist]:
        for ctrl_id, ctrl in framework_data["controls"].items():
            if ctrl["status"] in ("fail_critical", "fail_high"):
                critical_gaps.append({
                    "framework": framework_data["framework"],
                    "control":   ctrl_id,
                    "name":      ctrl["name"],
                    "status":    ctrl["status"],
                    "findings":  ctrl["findings"][:2],
                })

    return {
        "overall_score":   overall_score,
        "overall_level":   "Conforme" if overall_score >= 90 else
                           "Parcialmente Conforme" if overall_score >= 70 else
                           "Não Conforme",
        "frameworks": {
            "owasp_top10": owasp,
            "pci_dss_4":   pci,
            "nist_800_53": nist,
        },
        "critical_gaps": sorted(
            critical_gaps,
            key=lambda x: 0 if x["status"] == "fail_critical" else 1
        )[:15],
    }
