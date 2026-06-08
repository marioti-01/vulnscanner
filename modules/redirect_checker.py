import requests
import urllib3
from urllib.parse import urlparse, urljoin, urlencode, parse_qs

urllib3.disable_warnings()

HEADERS = {"User-Agent": "Mozilla/5.0 VulnScanner/2.0"}


def _build_headers(auth=None):
    h = dict(HEADERS)
    if auth:
        if auth.get('auth_headers'):
            h.update(auth['auth_headers'])
        if auth.get('cookies'):
            h['Cookie'] = auth['cookies']
    return h
MAX_HOPS = 10
EVIL_DOMAIN = "https://evil.com"

OPEN_REDIRECT_PARAMS = [
    "url", "redirect", "next", "return", "dest", "redir",
    "return_url", "redirect_url", "redirect_uri", "continue",
    "target", "to", "out", "view", "goto", "link", "forward",
]


def _follow_redirect_chain(url: str, auth=None) -> dict:
    """Segue a cadeia de redirecionamentos manualmente, retornando a cadeia e status."""
    chain = []
    visited = set()
    current = url
    loop_detected = False

    for _ in range(MAX_HOPS + 1):
        if current in visited:
            loop_detected = True
            chain.append({"url": current, "status": "LOOP"})
            break
        visited.add(current)

        try:
            resp = requests.get(
                current, timeout=10, verify=False, headers=_build_headers(auth),
                allow_redirects=False,
            )
        except Exception as e:
            chain.append({"url": current, "status": f"ERRO: {e}"})
            break

        chain.append({"url": current, "status": resp.status_code})

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            if not location:
                break
            current = urljoin(current, location)
        else:
            break

    return {"chain": chain, "loop": loop_detected}


def check_redirects(url: str, auth=None) -> dict:
    """Analisa redirecionamentos, HTTPS e open redirects no alvo."""
    findings = []
    if not url.startswith("http"):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc
    base_url = f"{parsed.scheme}://{domain}"

    # ── 1. Teste de redirect HTTP → HTTPS ────────────────────────────────
    try:
        http_url = f"http://{domain}"
        result = _follow_redirect_chain(http_url, auth=auth)
        chain = result["chain"]

        # Verificar se a cadeia chega a HTTPS
        reaches_https = any(
            urlparse(step["url"]).scheme == "https"
            for step in chain
            if isinstance(step["status"], int)
        )

        if reaches_https:
            findings.append({
                "severity": "info",
                "title": "Redirecionamento HTTP → HTTPS presente",
                "detail": (
                    f"O domínio redireciona de HTTP para HTTPS corretamente. "
                    f"Cadeia: {' → '.join(s['url'] for s in chain)}"
                ),
                "fix": "",
            })
        else:
            findings.append({
                "severity": "high",
                "title": "Sem redirecionamento HTTP → HTTPS",
                "detail": (
                    f"O domínio {domain} não redireciona automaticamente de "
                    f"HTTP para HTTPS. Conexões sem criptografia permitem "
                    f"ataques man-in-the-middle e interceptação de dados."
                ),
                "fix": (
                    "Configure redirecionamento 301 de HTTP para HTTPS no "
                    "servidor web. Habilite HSTS para reforçar a política."
                ),
            })
    except Exception as e:
        findings.append({
            "severity": "info",
            "title": "Erro ao testar redirect HTTP → HTTPS",
            "detail": str(e),
            "fix": "",
        })

    # ── 2. Análise da cadeia de redirecionamentos ────────────────────────
    try:
        result = _follow_redirect_chain(url, auth=auth)
        chain = result["chain"]

        # Loop detectado
        if result["loop"]:
            loop_urls = " → ".join(s["url"] for s in chain)
            findings.append({
                "severity": "high",
                "title": "Loop de redirecionamento detectado",
                "detail": (
                    f"Foi detectado um loop infinito de redirecionamento. "
                    f"Cadeia: {loop_urls}"
                ),
                "fix": (
                    "Corrija a configuração de redirecionamento do servidor "
                    "para evitar ciclos. Verifique regras de rewrite conflitantes."
                ),
            })
        # Cadeia muito longa
        elif len(chain) > 5:
            chain_str = " → ".join(f"{s['url']} ({s['status']})" for s in chain)
            findings.append({
                "severity": "medium",
                "title": f"Cadeia de redirecionamento longa ({len(chain)} saltos)",
                "detail": (
                    f"A URL requer {len(chain)} redirecionamentos até o destino "
                    f"final. Isso impacta performance e experiência do usuário. "
                    f"Cadeia: {chain_str}"
                ),
                "fix": (
                    "Reduza a cadeia de redirecionamentos para no máximo 2-3 "
                    "saltos. Redirecione diretamente para o destino final."
                ),
            })
        elif len(chain) > 1:
            chain_str = " → ".join(f"{s['url']} ({s['status']})" for s in chain)
            findings.append({
                "severity": "info",
                "title": f"Cadeia de redirecionamento ({len(chain)} saltos)",
                "detail": f"Cadeia: {chain_str}",
                "fix": "",
            })
        else:
            findings.append({
                "severity": "info",
                "title": "Sem redirecionamento na URL principal",
                "detail": f"A URL {url} responde diretamente sem redirecionamentos.",
                "fix": "",
            })
    except Exception as e:
        findings.append({
            "severity": "info",
            "title": "Erro ao analisar cadeia de redirecionamento",
            "detail": str(e),
            "fix": "",
        })

    # ── 3. Teste de Open Redirect ────────────────────────────────────────
    open_redirect_found = False
    for param in OPEN_REDIRECT_PARAMS:
        try:
            test_url = f"{base_url}/?{param}={EVIL_DOMAIN}"
            resp = requests.get(
                test_url, timeout=10, verify=False, headers=_build_headers(auth),
                allow_redirects=False,
            )

            # Verificar se há redirecionamento 3xx para o domínio evil
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if "evil.com" in location.lower():
                    findings.append({
                        "severity": "critical",
                        "title": f"Open Redirect detectado no parâmetro '{param}'",
                        "detail": (
                            f"O servidor redireciona (HTTP {resp.status_code}) para "
                            f"'{location}' quando o parâmetro '{param}' contém uma "
                            f"URL externa. Atacantes podem usar isso para phishing."
                        ),
                        "fix": (
                            "Valide todas as URLs de redirecionamento contra uma "
                            "lista branca de domínios permitidos. Nunca redirecione "
                            "diretamente para URLs fornecidas pelo usuário."
                        ),
                    })
                    open_redirect_found = True
                    continue

            # Verificar se o domínio evil aparece no corpo da resposta
            # (pode ser um redirect via JavaScript ou meta refresh)
            if resp.status_code == 200:
                body_lower = resp.text.lower()
                if "evil.com" in body_lower:
                    # Verificar se não é parte de uma mensagem de erro genérica
                    findings.append({
                        "severity": "medium",
                        "title": f"Possível Open Redirect (reflexão) no parâmetro '{param}'",
                        "detail": (
                            f"O domínio externo '{EVIL_DOMAIN}' aparece no corpo da "
                            f"resposta quando enviado pelo parâmetro '{param}'. "
                            f"Pode indicar redirect via JavaScript ou meta refresh."
                        ),
                        "fix": (
                            "Valide e sanitize URLs de redirecionamento. Não reflita "
                            "URLs externas no corpo da página sem validação."
                        ),
                    })
                    open_redirect_found = True

        except Exception:
            continue

    if not open_redirect_found:
        findings.append({
            "severity": "info",
            "title": "Nenhum Open Redirect detectado",
            "detail": (
                f"Nenhum dos {len(OPEN_REDIRECT_PARAMS)} parâmetros testados "
                f"({', '.join(OPEN_REDIRECT_PARAMS[:5])}...) resultou em "
                f"redirecionamento para domínio externo."
            ),
            "fix": "",
        })

    return {"module": "Redirects", "icon": "ti-arrows-right", "findings": findings}
