"""
IDOR Checker — Insecure Direct Object Reference
Testa se a aplicação permite acessar recursos de outros usuários
manipulando IDs em URLs, parâmetros e headers.
"""

import requests
import urllib3
import re
import difflib
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from modules.rate_limiter import get_limiter

urllib3.disable_warnings()
HEADERS = {"User-Agent": "Mozilla/5.0 VulnScanner/4.0"}


def _build_headers(auth=None):
    h = dict(HEADERS)
    if auth:
        if auth.get("auth_headers"):
            h.update(auth["auth_headers"])
        if auth.get("cookies"):
            h["Cookie"] = auth["cookies"]
    return h


def _similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a[:4000], b[:4000]).ratio()


def _looks_like_id(value: str) -> bool:
    """Verifica se um valor parece ser um ID (numérico, UUID, hash curta)."""
    value = value.strip()
    if re.match(r"^\d+$", value) and 1 <= int(value) <= 9999999:
        return True
    if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                value, re.IGNORECASE):
        return True
    if re.match(r"^[0-9a-f]{16,32}$", value, re.IGNORECASE):
        return True
    return False


def _increment_id(value: str) -> list[str]:
    """Gera variações do ID para testar IDOR."""
    variants = []
    if re.match(r"^\d+$", value):
        n = int(value)
        for delta in [-1, 1, 2, -2, 100, -100]:
            candidate = n + delta
            if candidate > 0:
                variants.append(str(candidate))
    elif re.match(r"^[0-9a-f-]{36}$", value, re.IGNORECASE):
        # UUID: modifica o último segmento
        parts = value.split("-")
        if len(parts) == 5:
            last = parts[-1]
            # Incrementa o último caractere hex
            try:
                num = int(last, 16)
                variants.append("-".join(parts[:-1]) + f"-{(num+1) % 0xffffffffffff:012x}")
                variants.append("-".join(parts[:-1]) + f"-{(num-1) % 0xffffffffffff:012x}")
            except Exception:
                pass
    return variants[:3]


def _check_url_idor(url: str, auth=None, limiter=None) -> list[dict]:
    """Testa IDOR em parâmetros de query string e path da URL."""
    findings = []
    h = _build_headers(auth)
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    for param_name, values in params.items():
        original_value = values[0] if values else ""
        if not _looks_like_id(original_value):
            continue

        # Baseline
        try:
            if limiter:
                limiter.wait()
            baseline = requests.get(url, timeout=10, verify=False, headers=h)
            if baseline.status_code in (401, 403, 404):
                continue
            baseline_text = baseline.text
        except Exception:
            continue

        for variant in _increment_id(original_value):
            try:
                new_params = dict(params)
                new_params[param_name] = [variant]
                new_query = urlencode(new_params, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))

                if limiter:
                    limiter.wait()
                resp = requests.get(new_url, timeout=10, verify=False, headers=h)

                if resp.status_code in (401, 403):
                    continue  # Acesso bloqueado = protegido

                if resp.status_code == 200:
                    sim = _similarity(baseline_text, resp.text)
                    # Resposta diferente mas bem-sucedida = pode ser outro objeto
                    if sim < 0.70 and len(resp.text) > 200:
                        findings.append({
                            "severity": "high",
                            "title": f"Possível IDOR no parâmetro '{param_name}'",
                            "detail": (
                                f"Alterando '{param_name}' de '{original_value}' para '{variant}' "
                                f"retornou HTTP 200 com conteúdo diferente (similaridade: {sim:.0%}). "
                                f"URL testada: {new_url[:120]}"
                            ),
                            "fix": (
                                "Implemente verificação de autorização em nível de objeto. "
                                "Valide que o usuário autenticado tem permissão para acessar "
                                "o recurso solicitado. Considere usar UUIDs não sequenciais."
                            ),
                            "cvss": "7.5",
                        })
                        break  # Um finding por parâmetro é suficiente

            except Exception:
                continue

    return findings


def _check_path_idor(base_url: str, crawl_urls: list, auth=None, limiter=None) -> list[dict]:
    """Testa IDOR em IDs embutidos no path da URL (ex: /users/123/profile)."""
    findings = []
    h = _build_headers(auth)

    # Padrões de path com IDs
    id_patterns = [
        re.compile(r"(/\w+/)(\d+)(/|$)"),
        re.compile(r"(/\w+/)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(/|$)", re.I),
    ]

    tested_patterns = set()

    for crawl_url in crawl_urls[:30]:
        parsed = urlparse(crawl_url)
        path = parsed.path

        for pattern in id_patterns:
            match = pattern.search(path)
            if not match:
                continue

            id_value = match.group(2)
            prefix = match.group(1)
            pattern_key = f"{prefix}*"

            if pattern_key in tested_patterns:
                continue
            tested_patterns.add(pattern_key)

            # Baseline
            try:
                if limiter:
                    limiter.wait()
                baseline = requests.get(crawl_url, timeout=10, verify=False, headers=h)
                if baseline.status_code in (401, 403, 404):
                    continue
                baseline_text = baseline.text
            except Exception:
                continue

            for variant in _increment_id(id_value):
                try:
                    new_path = path.replace(id_value, variant, 1)
                    new_url = urlunparse(parsed._replace(path=new_path))

                    if limiter:
                        limiter.wait()
                    resp = requests.get(new_url, timeout=10, verify=False, headers=h)

                    if resp.status_code in (401, 403, 404):
                        continue

                    if resp.status_code == 200:
                        sim = _similarity(baseline_text, resp.text)
                        if sim < 0.70 and len(resp.text) > 200:
                            findings.append({
                                "severity": "high",
                                "title": f"Possível IDOR no path: {prefix}{{id}}",
                                "detail": (
                                    f"Alterando o ID de '{id_value}' para '{variant}' no path "
                                    f"retornou HTTP 200 com conteúdo diferente (sim: {sim:.0%}). "
                                    f"URL original: {crawl_url[:100]} | "
                                    f"URL testada: {new_url[:100]}"
                                ),
                                "fix": (
                                    "Implemente verificação de autorização em nível de objeto. "
                                    "Use UUIDs aleatórios em vez de IDs sequenciais. "
                                    "Valide permissões antes de retornar qualquer objeto."
                                ),
                                "cvss": "7.5",
                            })
                            break

                except Exception:
                    continue

    return findings


def _check_api_idor(base_url: str, crawl_urls: list, auth=None, limiter=None) -> list[dict]:
    """Testa IDOR em endpoints de API REST (/api/v1/users/123)."""
    findings = []
    h = _build_headers(auth)

    api_pattern = re.compile(r"(/api/[^?#]*/)(\d+)(/|$)", re.IGNORECASE)

    tested = set()
    for crawl_url in crawl_urls:
        parsed = urlparse(crawl_url)
        match = api_pattern.search(parsed.path)
        if not match:
            continue

        id_value = match.group(2)
        prefix = match.group(1)

        if prefix in tested:
            continue
        tested.add(prefix)

        try:
            if limiter:
                limiter.wait()
            baseline = requests.get(crawl_url, timeout=10, verify=False, headers=h)
            if baseline.status_code not in (200,):
                continue
            baseline_text = baseline.text
        except Exception:
            continue

        for variant in _increment_id(id_value):
            try:
                new_path = parsed.path.replace(id_value, variant, 1)
                new_url = urlunparse(parsed._replace(path=new_path))

                if limiter:
                    limiter.wait()
                resp = requests.get(new_url, timeout=10, verify=False, headers=h)

                if resp.status_code == 200:
                    sim = _similarity(baseline_text, resp.text)
                    if sim < 0.65 and len(resp.text) > 50:
                        findings.append({
                            "severity": "critical",
                            "title": f"IDOR em API REST: {prefix}{{id}}",
                            "detail": (
                                f"Endpoint de API retornou dados ao alterar ID de '{id_value}' "
                                f"para '{variant}' (HTTP 200, sim: {sim:.0%}). "
                                f"Endpoint: {new_url[:120]}"
                            ),
                            "fix": (
                                "Implemente autorização em nível de recurso na API. "
                                "Valide que o token/sessão do usuário tem acesso ao objeto solicitado. "
                                "Use UUIDs não previsíveis."
                            ),
                            "cvss": "9.1",
                        })
                        break

            except Exception:
                continue

    return findings


def check_idor(url: str, crawl_data: dict = None, auth=None,
               rate_profile: str = "normal") -> dict:
    """Detecta vulnerabilidades IDOR na aplicação."""
    findings = []
    if not url.startswith("http"):
        url = "https://" + url

    limiter = get_limiter(rate_profile)
    crawl_urls = crawl_data.get("urls", []) if crawl_data else [url]

    total_found = 0

    # 1. IDOR em query params das URLs crawleadas
    for crawl_url in crawl_urls[:20]:
        parsed = urlparse(crawl_url)
        if parsed.query:
            results = _check_url_idor(crawl_url, auth=auth, limiter=limiter)
            findings.extend(results)
            total_found += len(results)

    # 2. IDOR em path da URL
    path_results = _check_path_idor(url, crawl_urls, auth=auth, limiter=limiter)
    findings.extend(path_results)
    total_found += len(path_results)

    # 3. IDOR em APIs REST
    api_results = _check_api_idor(url, crawl_urls, auth=auth, limiter=limiter)
    findings.extend(api_results)
    total_found += len(api_results)

    # Summary
    if total_found == 0:
        findings.append({
            "severity": "info",
            "title": "Nenhum IDOR detectado",
            "detail": (
                f"Testados {len(crawl_urls)} endpoints. "
                "Nenhuma manipulação de ID retornou dados diferentes de outro objeto."
            ),
            "fix": "",
        })
    else:
        findings.append({
            "severity": "info",
            "title": f"IDOR: {total_found} possível(is) vulnerabilidade(s) encontrada(s)",
            "detail": "Confirme manualmente — IDOR requer contexto de autenticação para ser validado.",
            "fix": "",
        })

    return {"module": "IDOR", "icon": "ti-lock-open", "findings": findings}
