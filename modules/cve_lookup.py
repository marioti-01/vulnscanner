import requests
import urllib3
import re
import time
from urllib.parse import urlparse

urllib3.disable_warnings()

HEADERS = {"User-Agent": "Mozilla/5.0 VulnScanner/2.0"}

# ── Base de CVEs conhecidos ──────────────────────────────────────────────────
# Cada entrada: tech, cve_id, description, affected_range, fixed_version,
#               version_check (callable que recebe tupla de versão e retorna True se vulnerável),
#               cvss, severity
CVE_DATABASE = [
    {
        "tech": "apache",
        "cve": "CVE-2021-41773",
        "description": "Path Traversal e execução de código no Apache HTTP Server",
        "affected": "2.4.49 a 2.4.50",
        "check": lambda v: (2, 4, 49) <= v <= (2, 4, 50),
        "cvss": "9.8",
        "severity": "critical",
        "fix": "Atualize o Apache para a versão 2.4.51 ou superior.",
    },
    {
        "tech": "apache",
        "cve": "CVE-2021-44228",
        "description": "Log4Shell — Execução remota de código via Log4j (pode afetar configurações Apache com Java)",
        "affected": "Configurações Apache com módulos Java usando Log4j 2.0 a 2.14.1",
        "check": lambda v: (2, 4, 0) <= v,  # Verificação genérica — depende de configuração
        "cvss": "10.0",
        "severity": "critical",
        "fix": "Verifique se há módulos Java/Log4j no servidor. Atualize Log4j para 2.17.1+ ou remova a classe JndiLookup.",
    },
    {
        "tech": "nginx",
        "cve": "CVE-2021-23017",
        "description": "Vulnerabilidade no DNS resolver do Nginx permite execução de código",
        "affected": "< 1.21.0",
        "check": lambda v: v < (1, 21, 0),
        "cvss": "7.7",
        "severity": "high",
        "fix": "Atualize o Nginx para a versão 1.21.0 ou superior.",
    },
    {
        "tech": "php",
        "cve": "CVE-2024-4577",
        "description": "Injeção de argumentos no PHP CGI permite execução remota de código",
        "affected": "8.1.x < 8.1.29",
        "check": lambda v: (8, 1, 0) <= v < (8, 1, 29),
        "cvss": "9.8",
        "severity": "critical",
        "fix": "Atualize o PHP para a versão 8.1.29 ou superior. Considere migrar para PHP 8.3+.",
    },
    {
        "tech": "php",
        "cve": "CVE-2019-11043",
        "description": "Execução remota de código no PHP-FPM (FastCGI Process Manager)",
        "affected": "7.1.x a 7.3.x",
        "check": lambda v: (7, 1, 0) <= v < (7, 4, 0),
        "cvss": "9.8",
        "severity": "critical",
        "fix": "Atualize o PHP para a versão 7.4+ ou aplique o patch de segurança. Versões 7.x estão EOL.",
    },
    {
        "tech": "jquery",
        "cve": "CVE-2020-11022",
        "description": "XSS via jQuery.htmlPrefilter ao usar .html() com conteúdo não confiável",
        "affected": "< 3.5.0",
        "check": lambda v: v < (3, 5, 0),
        "cvss": "6.1",
        "severity": "high",
        "fix": "Atualize o jQuery para a versão 3.5.0 ou superior.",
    },
    {
        "tech": "jquery",
        "cve": "CVE-2020-11023",
        "description": "XSS no jQuery ao passar HTML contendo elementos <option> para métodos de manipulação DOM",
        "affected": "< 3.5.0",
        "check": lambda v: v < (3, 5, 0),
        "cvss": "6.1",
        "severity": "high",
        "fix": "Atualize o jQuery para a versão 3.5.0 ou superior.",
    },
    {
        "tech": "wordpress",
        "cve": "CVE-2023-2982",
        "description": "Bypass de autenticação no WordPress via Social Login",
        "affected": "< 6.2.1",
        "check": lambda v: v < (6, 2, 1),
        "cvss": "9.8",
        "severity": "critical",
        "fix": "Atualize o WordPress para a versão 6.2.1 ou superior.",
    },
    {
        "tech": "openssl",
        "cve": "CVE-2022-3602",
        "description": "Buffer overflow no OpenSSL ao processar certificados X.509 com endereços de e-mail",
        "affected": "3.0.x < 3.0.7",
        "check": lambda v: (3, 0, 0) <= v < (3, 0, 7),
        "cvss": "7.5",
        "severity": "high",
        "fix": "Atualize o OpenSSL para a versão 3.0.7 ou superior.",
    },
    {
        "tech": "drupal",
        "cve": "CVE-2018-7600",
        "description": "Drupalgeddon2 — Execução remota de código sem autenticação",
        "affected": "< 7.58 / < 8.5.1",
        "check": lambda v: v < (7, 58, 0) or ((8, 0, 0) <= v < (8, 5, 1)),
        "cvss": "9.8",
        "severity": "critical",
        "fix": "Atualize o Drupal para 7.58+, 8.5.1+ ou versão mais recente.",
    },
    {
        "tech": "angularjs",
        "cve": "CVE-2020-7676",
        "description": "XSS no AngularJS via injeção de atributos em elementos SVG",
        "affected": "< 1.8.0",
        "check": lambda v: v < (1, 8, 0),
        "cvss": "5.4",
        "severity": "high",
        "fix": "Atualize o AngularJS para 1.8.0+ ou migre para Angular moderno (v2+).",
    },
    {
        "tech": "express",
        "cve": "CVE-2022-24999",
        "description": "Prototype Pollution via qs (usado no Express.js) permite negação de serviço",
        "affected": "Express com qs < 6.10.3",
        "check": lambda v: v > (0,),  # Difícil verificar a versão do qs via headers
        "cvss": "7.5",
        "severity": "high",
        "fix": "Atualize o Express.js e a dependência qs para qs >= 6.10.3.",
    },
]

# Aliases para normalizar nomes de tecnologias
TECH_ALIASES = {
    "apache": ["apache", "httpd"],
    "nginx": ["nginx"],
    "php": ["php"],
    "jquery": ["jquery"],
    "wordpress": ["wordpress", "wp"],
    "openssl": ["openssl"],
    "drupal": ["drupal"],
    "angularjs": ["angularjs", "angular.js", "angular"],
    "express": ["express", "express.js"],
}


def _parse_version(version_str: str) -> tuple:
    """Converte string de versão em tupla numérica para comparação."""
    try:
        # Remover sufixos como -beta, -rc, etc.
        version_str = re.split(r"[-+_]", version_str)[0]
        parts = version_str.strip().split(".")
        return tuple(int(p) for p in parts if p.isdigit())
    except (ValueError, AttributeError):
        return ()


def _normalize_tech_name(name: str) -> str:
    """Normaliza o nome da tecnologia para comparação com a base de CVEs."""
    name_lower = name.lower().strip()
    for canonical, aliases in TECH_ALIASES.items():
        if name_lower in aliases:
            return canonical
    return name_lower


def _build_cpe_string(tech: str, version: str) -> str:
    """Constrói uma string CPE 2.3 simplificada a partir da tecnologia e versão."""
    tech_clean = re.sub(r"[^a-z0-9_]", "_", tech.lower().strip())
    version_clean = re.sub(r"[^a-z0-9.]", "", version.lower().strip())
    return f"cpe:2.3:a:*:{tech_clean}:{version_clean}:*:*:*:*:*:*:*"


def _map_cvss_severity(score: float) -> str:
    """Mapeia pontuação CVSS para nível de severidade."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _query_nvd_api(cpe_keyword: str, max_results: int = 10) -> list:
    """Consulta a API NVD v2.0 para buscar CVEs por palavra-chave.

    Retorna lista de dicts com cve_id, description, cvss, severity.
    Em caso de falha, retorna lista vazia.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": cpe_keyword,
        "resultsPerPage": max_results,
    }

    try:
        resp = requests.get(url, params=params, timeout=10, headers=HEADERS)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return []

    results = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")

        # Extrair descrição (preferir pt, senão en)
        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "pt":
                description = desc.get("value", "")
                break
            if desc.get("lang") == "en":
                description = desc.get("value", "")

        # Extrair CVSS — tentar v3.1, depois v3.0, depois v2.0
        cvss_score = 0.0
        metrics = cve.get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                break

        severity = _map_cvss_severity(cvss_score)

        results.append({
            "cve_id": cve_id,
            "description": description,
            "cvss": cvss_score,
            "severity": severity,
        })

    # Respeitar rate limit da API pública
    time.sleep(1)

    return results


def _build_headers(auth=None):
    h = dict(HEADERS)
    if auth and auth.get('auth_headers'):
        h.update(auth['auth_headers'])
    if auth and auth.get('cookies'):
        h['Cookie'] = auth['cookies']
    return h


def _detect_basic_tech(url: str, auth=None) -> dict:
    """Detecção básica de tecnologia quando tech_data não é fornecido."""
    versions = {}
    try:
        resp = requests.get(
            url, timeout=10, verify=False, headers=_build_headers(auth),
            allow_redirects=True,
        )
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Server header
        server = headers.get("server", "")
        if server:
            match = re.search(r"(Apache|nginx|IIS|LiteSpeed)[/ ]?([\d.]+)?", server, re.IGNORECASE)
            if match and match.group(2):
                versions[match.group(1).lower()] = match.group(2)

        # X-Powered-By
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            match = re.search(r"(PHP|ASP\.NET|Express)[/ ]?([\d.]+)?", powered_by, re.IGNORECASE)
            if match and match.group(2):
                versions[match.group(1).lower()] = match.group(2)

        # X-AspNet-Version
        aspnet = headers.get("x-aspnet-version", "")
        if aspnet:
            versions["asp.net"] = aspnet

    except Exception:
        pass

    return versions


def check_cves(url: str, tech_data: dict = None, auth=None) -> dict:
    """Verifica CVEs conhecidos com base nas tecnologias e versões detectadas."""
    findings = []
    if not url.startswith("http"):
        url = "https://" + url

    try:
        # Obter versões detectadas
        if tech_data and "versions" in tech_data:
            versions = dict(tech_data["versions"])
        else:
            versions = _detect_basic_tech(url, auth)

        if not versions:
            findings.append({
                "severity": "info",
                "title": "Nenhuma versão detectada para verificar CVEs",
                "detail": (
                    "Não foi possível detectar versões de software no alvo. "
                    "Isso pode significar que o servidor oculta informações de "
                    "versão (boa prática) ou que a detecção não encontrou "
                    "padrões reconhecidos."
                ),
                "fix": "",
            })
            return {"module": "CVE Lookup", "icon": "ti-database-search", "findings": findings}

        # Listar tecnologias detectadas
        tech_list = ", ".join(f"{k}: {v}" for k, v in versions.items())
        findings.append({
            "severity": "info",
            "title": "Tecnologias com versão detectada",
            "detail": f"Versões encontradas: {tech_list}",
            "fix": "",
        })

        # Verificar cada CVE
        cves_found = 0
        for cve_entry in CVE_DATABASE:
            tech_name = cve_entry["tech"]

            # Encontrar versão correspondente
            matched_version = None
            matched_tech_key = None
            for detected_tech, detected_ver in versions.items():
                normalized = _normalize_tech_name(detected_tech)
                if normalized == tech_name:
                    matched_version = detected_ver
                    matched_tech_key = detected_tech
                    break

            if matched_version is None:
                continue

            version_tuple = _parse_version(matched_version)
            if not version_tuple:
                continue

            try:
                if cve_entry["check"](version_tuple):
                    cves_found += 1
                    findings.append({
                        "severity": cve_entry["severity"],
                        "title": f"{cve_entry['cve']} — {cve_entry['description']}",
                        "detail": (
                            f"Tecnologia: {matched_tech_key} | "
                            f"Versão detectada: {matched_version} | "
                            f"Faixa afetada: {cve_entry['affected']} | "
                            f"CVSS: {cve_entry['cvss']}"
                        ),
                        "fix": cve_entry["fix"],
                    })
            except Exception:
                continue

        # ── Consulta à API NVD v2.0 ─────────────────────────────────────
        nvd_cves_found = 0
        techs_with_version = [
            (tech, ver) for tech, ver in versions.items() if ver
        ]

        if techs_with_version:
            for tech, ver in techs_with_version:
                keyword = f"{tech} {ver}"
                nvd_results = _query_nvd_api(keyword, max_results=5)

                for nvd_entry in nvd_results:
                    if not nvd_entry.get("cve_id"):
                        continue
                    nvd_cves_found += 1
                    cves_found += 1
                    cpe_str = _build_cpe_string(tech, ver)
                    findings.append({
                        "severity": nvd_entry["severity"],
                        "title": (
                            f"{nvd_entry['cve_id']} [NVD] — "
                            f"{nvd_entry['description'][:120]}"
                        ),
                        "detail": (
                            f"Tecnologia: {tech} | "
                            f"Versão detectada: {ver} | "
                            f"CVSS: {nvd_entry['cvss']} | "
                            f"CPE: {cpe_str} | "
                            f"Fonte: NVD (National Vulnerability Database)"
                        ),
                        "fix": (
                            f"Consulte https://nvd.nist.gov/vuln/detail/"
                            f"{nvd_entry['cve_id']} para detalhes e "
                            f"recomendações de correção."
                        ),
                    })

        if cves_found == 0:
            findings.append({
                "severity": "info",
                "title": "Nenhum CVE conhecido encontrado",
                "detail": (
                    "As versões detectadas não correspondem a CVEs críticos "
                    "conhecidos na base de dados interna nem na API NVD. "
                    "Isso NÃO garante ausência de vulnerabilidades — apenas "
                    "que não há correspondência com as CVEs verificadas."
                ),
                "fix": "",
            })
        else:
            detail_parts = [
                f"Foram encontrados {cves_found} CVE(s) no total"
            ]
            if nvd_cves_found > 0:
                detail_parts.append(
                    f" ({nvd_cves_found} via API NVD)"
                )
            detail_parts.append(
                ". Verifique cada um e aplique as correções recomendadas."
            )
            findings.append({
                "severity": "info",
                "title": f"Total de CVEs encontrados: {cves_found}",
                "detail": "".join(detail_parts),
                "fix": "",
            })

    except Exception as e:
        findings.append({
            "severity": "info",
            "title": "Erro ao verificar CVEs",
            "detail": str(e),
            "fix": "",
        })

    return {"module": "CVE Lookup", "icon": "ti-database-search", "findings": findings}
