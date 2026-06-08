import requests
import urllib3
import re
import time
from urllib.parse import urljoin, urlparse, urlencode
from collections import deque
from bs4 import BeautifulSoup

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
MAX_PAGES = 30
MAX_DEPTH = 3
DELAY = 0.5

SENSITIVE_ACTIONS = [
    "login", "signin", "sign-in", "password", "passwd", "senha",
    "register", "signup", "sign-up", "cadastro", "auth", "account",
    "checkout", "pagamento", "payment", "transfer", "delete", "remove",
]

CSRF_TOKEN_NAMES = [
    "csrf", "_token", "authenticity_token", "csrfmiddlewaretoken",
    "__requestverificationtoken", "antiforgery", "xsrf",
]


def _is_same_domain(base_domain: str, url: str) -> bool:
    """Verifica se a URL pertence ao mesmo domínio base."""
    try:
        parsed = urlparse(url)
        return parsed.netloc == "" or parsed.netloc == base_domain
    except Exception:
        return False


def _extract_links(soup: BeautifulSoup, current_url: str, base_domain: str) -> list:
    """Extrai todos os links da mesma origem."""
    links = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        full_url = urljoin(current_url, href)
        # Remover fragmentos
        full_url = full_url.split("#")[0]
        if _is_same_domain(base_domain, full_url):
            links.append(full_url)
    return links


def _extract_forms(soup: BeautifulSoup, current_url: str) -> list:
    """Extrai formulários com seus campos, ação e método."""
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "").strip()
        method = (form.get("method", "GET")).upper().strip()
        full_action = urljoin(current_url, action) if action else current_url

        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            inp_name = inp.get("name", "")
            inp_type = inp.get("type", "text")
            if inp_name:
                inputs.append({"name": inp_name, "type": inp_type})

        has_csrf = any(
            any(tok in (inp.get("name", "").lower()) for tok in CSRF_TOKEN_NAMES)
            for inp in form.find_all("input", attrs={"name": True})
        )

        forms.append({
            "action": full_action,
            "method": method,
            "inputs": inputs,
            "has_csrf": has_csrf,
            "source_page": current_url,
        })
    return forms


def _extract_params(url: str) -> list:
    """Extrai parâmetros da query string de uma URL."""
    parsed = urlparse(url)
    if not parsed.query:
        return []
    params = []
    for pair in parsed.query.split("&"):
        parts = pair.split("=", 1)
        if parts[0]:
            params.append(parts[0])
    return params


def crawl_site(url: str, auth=None) -> dict:
    """Realiza crawling do site alvo, descobrindo links, formulários e parâmetros."""
    findings = []
    if not url.startswith("http"):
        url = "https://" + url

    base_parsed = urlparse(url)
    base_domain = base_parsed.netloc

    visited = set()
    all_forms = []
    all_urls = []
    all_params = set()

    # Fila: (url, profundidade)
    queue = deque()
    queue.append((url, 0))

    try:
        while queue and len(visited) < MAX_PAGES:
            current_url, depth = queue.popleft()

            # Normalizar URL
            current_url = current_url.split("#")[0]
            if current_url in visited:
                continue

            visited.add(current_url)
            all_urls.append(current_url)

            # Extrair parâmetros da URL
            for p in _extract_params(current_url):
                all_params.add(p)

            try:
                resp = requests.get(
                    current_url, timeout=8, verify=False,
                    headers=_build_headers(auth), allow_redirects=True,
                )
            except Exception:
                continue

            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type.lower():
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            # Extrair formulários
            page_forms = _extract_forms(soup, current_url)
            all_forms.extend(page_forms)

            # Extrair links e enfileirar
            if depth < MAX_DEPTH:
                links = _extract_links(soup, current_url, base_domain)
                for link in links:
                    if link not in visited:
                        queue.append((link, depth + 1))

            time.sleep(DELAY)

        # ── Gerar findings ───────────────────────────────────────────────────

        # Resumo de crawling
        findings.append({
            "severity": "info",
            "title": "Resumo do crawling",
            "detail": (
                f"Páginas rastreadas: {len(visited)} | "
                f"Links únicos encontrados: {len(all_urls)} | "
                f"Formulários descobertos: {len(all_forms)} | "
                f"Parâmetros únicos: {len(all_params)}"
            ),
            "fix": "",
        })

        if all_params:
            findings.append({
                "severity": "info",
                "title": "Parâmetros descobertos",
                "detail": f"Parâmetros encontrados nas URLs: {', '.join(sorted(all_params))}",
                "fix": "",
            })

        # Findings para cada formulário
        for form in all_forms:
            input_names = ", ".join(
                f"{i['name']} ({i['type']})" for i in form["inputs"]
            ) or "nenhum campo encontrado"

            findings.append({
                "severity": "info",
                "title": f"Formulário encontrado: {form['method']} {form['action'][:80]}",
                "detail": (
                    f"Método: {form['method']} | "
                    f"Ação: {form['action']} | "
                    f"Campos: {input_names} | "
                    f"Página: {form['source_page']}"
                ),
                "fix": "",
            })

            # Formulário POST sem CSRF
            if form["method"] == "POST" and not form["has_csrf"]:
                findings.append({
                    "severity": "medium",
                    "title": "Formulário POST sem token CSRF",
                    "detail": (
                        f"O formulário em {form['source_page']} com ação "
                        f"'{form['action'][:80]}' usa POST mas não possui "
                        f"campo de token CSRF visível."
                    ),
                    "fix": (
                        "Implemente tokens CSRF em todos os formulários POST. "
                        "Frameworks modernos como Django, Laravel e Rails "
                        "oferecem proteção CSRF nativa."
                    ),
                })

            # Formulário GET para ações sensíveis
            if form["method"] == "GET":
                action_lower = form["action"].lower()
                input_lower = " ".join(i["name"].lower() for i in form["inputs"])
                check_str = action_lower + " " + input_lower
                for keyword in SENSITIVE_ACTIONS:
                    if keyword in check_str:
                        findings.append({
                            "severity": "low",
                            "title": f"Formulário GET para ação sensível: '{keyword}'",
                            "detail": (
                                f"O formulário em {form['source_page']} usa método GET "
                                f"para uma ação que parece sensível ('{keyword}'). "
                                f"Dados enviados via GET ficam visíveis na URL e no "
                                f"histórico do navegador."
                            ),
                            "fix": (
                                "Use o método POST para formulários que envolvem "
                                "autenticação, dados pessoais ou ações destrutivas."
                            ),
                        })
                        break

        if not all_forms:
            findings.append({
                "severity": "info",
                "title": "Nenhum formulário encontrado",
                "detail": "O crawling não encontrou formulários HTML no site.",
                "fix": "",
            })

    except Exception as e:
        findings.append({
            "severity": "info",
            "title": "Erro durante o crawling",
            "detail": str(e),
            "fix": "",
        })

    crawl_data = {
        "forms": all_forms,
        "urls": all_urls,
        "params": list(all_params),
    }

    return {
        "module": "Crawler / Spider",
        "icon": "ti-spider",
        "findings": findings,
        "crawl_data": crawl_data,
    }
