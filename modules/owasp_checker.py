import requests
import re
import time
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

HEADERS = {"User-Agent": "Mozilla/5.0 VulnScanner/2.0"}


def _build_headers(auth=None):
    h = dict(HEADERS)
    if auth and auth.get('auth_headers'):
        h.update(auth['auth_headers'])
    if auth and auth.get('cookies'):
        h['Cookie'] = auth['cookies']
    return h


def check_owasp(url: str, crawl_data: dict = None, auth=None) -> dict:
    findings = []
    if not url.startswith("http"):
        url = "https://" + url

    base = url.rstrip("/")
    headers = _build_headers(auth)

    # ── 1. XSS Refletido ────────────────────────────────────────────────────
    xss_payloads = ['"><script>alert(1)</script>', "'><img src=x onerror=alert(1)>"]
    xss_params = ["q", "search", "query", "s", "keyword", "id", "page", "name", "user", "email"]
    xss_found = False
    for param in xss_params:
        if xss_found:
            break
        for payload in xss_payloads:
            try:
                test_url = base + f"/?{param}=" + requests.utils.quote(payload)
                r = requests.get(test_url, timeout=8, verify=False, headers=headers)
                if payload.lower() in r.text.lower():
                    findings.append({
                        "severity": "critical",
                        "title": "XSS Refletido detectado",
                        "detail": f"Payload refletido no parâmetro '{param}': {payload[:60]}",
                        "fix": "Escape todos os inputs do usuário antes de renderizar. Use CSP e bibliotecas como DOMPurify.",
                    })
                    xss_found = True
                    break
            except:
                pass

    # Detectar parâmetros na página e testar XSS neles
    if not xss_found:
        try:
            r_page = requests.get(base, timeout=8, verify=False, headers=headers)
            page_params = set(re.findall(r'name=["\']([a-zA-Z0-9_]+)["\']', r_page.text))
            page_params |= set(re.findall(r'[?&]([a-zA-Z0-9_]+)=', r_page.text))
            for param in list(page_params)[:15]:
                if xss_found:
                    break
                for payload in xss_payloads:
                    try:
                        test_url = base + f"/?{param}=" + requests.utils.quote(payload)
                        r = requests.get(test_url, timeout=8, verify=False, headers=headers)
                        if payload.lower() in r.text.lower():
                            findings.append({
                                "severity": "critical",
                                "title": "XSS Refletido detectado",
                                "detail": f"Payload refletido no parâmetro '{param}' encontrado na página: {payload[:60]}",
                                "fix": "Escape todos os inputs do usuário antes de renderizar. Use CSP e bibliotecas como DOMPurify.",
                            })
                            xss_found = True
                            break
                    except:
                        pass
        except:
            pass

    # ── 1b. XSS em forms e params descobertos pelo crawler ────────────────
    if not xss_found and crawl_data:
        crawl_params = crawl_data.get('params', [])
        crawl_forms = crawl_data.get('forms', [])
        crawl_urls = crawl_data.get('urls', [])

        # Testar XSS nos parâmetros descobertos pelo crawler
        for param in crawl_params[:20]:
            if xss_found:
                break
            for payload in xss_payloads:
                try:
                    test_url = base + f"/?{param}=" + requests.utils.quote(payload)
                    r = requests.get(test_url, timeout=8, verify=False, headers=headers)
                    if payload.lower() in r.text.lower():
                        findings.append({
                            "severity": "critical",
                            "title": "XSS Refletido detectado (via crawler)",
                            "detail": f"Payload refletido no parâmetro '{param}' descoberto pelo crawler: {payload[:60]}",
                            "fix": "Escape todos os inputs do usuário antes de renderizar. Use CSP e bibliotecas como DOMPurify.",
                        })
                        xss_found = True
                        break
                except:
                    pass

        # Testar XSS nos formulários descobertos pelo crawler
        for form in crawl_forms[:10]:
            if xss_found:
                break
            form_inputs = [i for i in form.get('inputs', []) if i.get('type') not in ('hidden', 'submit', 'button', 'checkbox', 'radio')]
            for inp in form_inputs[:5]:
                if xss_found:
                    break
                param_name = inp.get('name', '')
                if not param_name:
                    continue
                for payload in xss_payloads:
                    try:
                        if form.get('method', 'GET').upper() == 'GET':
                            test_url = form['action'] + f"?{param_name}=" + requests.utils.quote(payload)
                            r = requests.get(test_url, timeout=8, verify=False, headers=headers)
                        else:
                            form_data = {param_name: payload}
                            r = requests.post(form['action'], data=form_data, timeout=8, verify=False, headers=headers)
                        if payload.lower() in r.text.lower():
                            findings.append({
                                "severity": "critical",
                                "title": "XSS Refletido em formulário detectado",
                                "detail": f"Payload refletido no campo '{param_name}' do form {form.get('method', '?')} {form['action'][:80]}",
                                "fix": "Escape todos os inputs do usuário antes de renderizar. Use CSP e DOMPurify.",
                            })
                            xss_found = True
                            break
                    except:
                        pass

        # Testar XSS em URLs com query params descobertas pelo crawler
        for crawl_url in crawl_urls[:15]:
            if xss_found:
                break
            parsed = urlparse(crawl_url)
            if not parsed.query:
                continue
            url_params = parse_qs(parsed.query)
            for param_name in list(url_params.keys())[:5]:
                if xss_found:
                    break
                for payload in xss_payloads:
                    try:
                        test_url = crawl_url.split('?')[0] + f"?{param_name}=" + requests.utils.quote(payload)
                        r = requests.get(test_url, timeout=8, verify=False, headers=headers)
                        if payload.lower() in r.text.lower():
                            findings.append({
                                "severity": "critical",
                                "title": "XSS Refletido detectado em URL crawled",
                                "detail": f"Payload refletido no parâmetro '{param_name}' da URL {crawl_url[:80]}",
                                "fix": "Escape todos os inputs do usuário. Use CSP e DOMPurify.",
                            })
                            xss_found = True
                            break
                    except:
                        pass

    if not xss_found:
        findings.append({"severity": "info", "title": "XSS básico não detectado", "detail": "Payloads simples não foram refletidos nos parâmetros testados (fixos + crawler).", "fix": ""})

    # ── 2. SQL Injection básico ──────────────────────────────────────────────
    sqli_payloads = ["'", "' OR '1'='1", "\" OR \"1\"=\"1"]
    sqli_errors = ["sql syntax", "mysql_fetch", "ora-", "pg_query", "sqlite3",
                   "syntax error", "unclosed quotation", "you have an error in your sql"]
    sqli_found = False
    for payload in sqli_payloads:
        try:
            test_url = base + "/?id=" + requests.utils.quote(payload)
            r = requests.get(test_url, timeout=8, verify=False, headers=headers)
            body_lower = r.text.lower()
            for err in sqli_errors:
                if err in body_lower:
                    findings.append({
                        "severity": "critical",
                        "title": "Possível SQL Injection detectado",
                        "detail": f"Erro de banco de dados visível na resposta com payload: {payload}. Erro encontrado: '{err}'",
                        "fix": "Use prepared statements / parameterized queries. NUNCA concatene inputs em queries SQL.",
                    })
                    sqli_found = True
                    break
        except:
            pass
    # ── 2a.b SQL Injection em params/forms do crawler ─────────────────────
    if not sqli_found and crawl_data:
        crawl_params = crawl_data.get('params', [])
        crawl_forms = crawl_data.get('forms', [])

        # Testar SQLi nos parâmetros do crawler
        for param in crawl_params[:15]:
            if sqli_found:
                break
            for payload in sqli_payloads:
                try:
                    test_url = base + f"/?{param}=" + requests.utils.quote(payload)
                    r = requests.get(test_url, timeout=8, verify=False, headers=headers)
                    body_lower = r.text.lower()
                    for err in sqli_errors:
                        if err in body_lower:
                            findings.append({
                                "severity": "critical",
                                "title": "SQL Injection detectado (via crawler)",
                                "detail": f"Erro de banco visível no parâmetro '{param}' (crawler) com payload: {payload}. Erro: '{err}'",
                                "fix": "Use prepared statements / parameterized queries. NUNCA concatene inputs em queries SQL.",
                            })
                            sqli_found = True
                            break
                except:
                    pass

        # Testar SQLi nos forms do crawler
        for form in crawl_forms[:8]:
            if sqli_found:
                break
            form_inputs = [i for i in form.get('inputs', []) if i.get('type') not in ('hidden', 'submit', 'button', 'checkbox', 'radio')]
            for inp in form_inputs[:3]:
                if sqli_found:
                    break
                param_name = inp.get('name', '')
                if not param_name:
                    continue
                for payload in sqli_payloads:
                    try:
                        if form.get('method', 'GET').upper() == 'GET':
                            test_url = form['action'] + f"?{param_name}=" + requests.utils.quote(payload)
                            r = requests.get(test_url, timeout=8, verify=False, headers=headers)
                        else:
                            form_data = {param_name: payload}
                            r = requests.post(form['action'], data=form_data, timeout=8, verify=False, headers=headers)
                        body_lower = r.text.lower()
                        for err in sqli_errors:
                            if err in body_lower:
                                findings.append({
                                    "severity": "critical",
                                    "title": "SQL Injection em formulário detectado",
                                    "detail": f"Erro de banco no campo '{param_name}' do form {form.get('method', '?')} {form['action'][:80]} com payload: {payload}",
                                    "fix": "Use prepared statements / parameterized queries. NUNCA concatene inputs em queries SQL.",
                                })
                                sqli_found = True
                                break
                    except:
                        pass

    if not sqli_found:
        findings.append({"severity": "info", "title": "SQLi básico não detectado", "detail": "Erros de SQL não encontrados nas respostas (params fixos + crawler).", "fix": ""})

    # ── 2b. SQL Injection time-based ────────────────────────────────────────
    sqli_time_params = ["id", "user", "page", "cat", "category", "item", "product", "article", "news"]
    sqli_time_payload = "1' AND SLEEP(5)--"
    sqli_time_found = False
    for param in sqli_time_params:
        if sqli_time_found:
            break
        try:
            test_url = base + f"/?{param}=" + requests.utils.quote(sqli_time_payload)
            start_time = time.time()
            requests.get(test_url, timeout=12, verify=False, headers=headers)
            elapsed = time.time() - start_time
            if elapsed > 4.0:
                findings.append({
                    "severity": "critical",
                    "title": f"SQL Injection time-based detectado (parâmetro: {param})",
                    "detail": f"Payload SLEEP(5) no parâmetro '{param}' causou atraso de {elapsed:.1f}s na resposta, indicando injeção SQL.",
                    "fix": "Use prepared statements / parameterized queries. NUNCA concatene inputs em queries SQL.",
                })
                sqli_time_found = True
        except requests.exceptions.Timeout:
            findings.append({
                "severity": "critical",
                "title": f"SQL Injection time-based detectado (parâmetro: {param})",
                "detail": f"Payload SLEEP(5) no parâmetro '{param}' causou timeout na resposta, indicando possível injeção SQL.",
                "fix": "Use prepared statements / parameterized queries. NUNCA concatene inputs em queries SQL.",
            })
            sqli_time_found = True
        except:
            pass

    # ── 3. Directory traversal / arquivos sensíveis ──────────────────────────
    sensitive_paths = [
        "/.env", "/.git/config", "/config.php", "/wp-config.php",
        "/admin", "/phpmyadmin", "/.htaccess", "/backup.zip",
        "/database.sql", "/config.yml", "/secrets.json",
        "/.DS_Store", "/server-status", "/robots.txt",
        # Expanded paths
        "/.well-known/security.txt", "/swagger-ui.html", "/api/docs",
        "/graphql", "/api/graphql",
        "/.npmrc", "/docker-compose.yml", "/docker-compose.yaml", "/.dockerenv",
        "/actuator", "/actuator/health", "/actuator/env",
        "/server-info", "/elmah.axd", "/trace.axd",
        "/.svn/entries", "/.hg/", "/CVS/Root",
        "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/wp-login.php", "/administrator/", "/wp-json/wp/v2/users",
    ]
    exposed = []
    for path in sensitive_paths:
        try:
            r = requests.get(base + path, timeout=5, verify=False, headers=headers, allow_redirects=False)
            if r.status_code in (200, 403):
                exposed.append((path, r.status_code))
        except:
            pass

    critical_paths = {"/.env", "/.git/config", "/wp-config.php", "/database.sql",
                      "/.npmrc", "/actuator/env", "/docker-compose.yml", "/docker-compose.yaml"}
    for path, code in exposed:
        severity = "critical" if path in critical_paths else "high" if code == 200 else "medium"
        findings.append({
            "severity": severity,
            "title": f"Arquivo sensível acessível: {path}",
            "detail": f"HTTP {code} retornado. Pode expor credenciais, configurações ou código-fonte.",
            "fix": f"Bloqueie o acesso a {path} no servidor web. Nunca suba arquivos .env para produção.",
        })

    # ── 4. Informações de versão em erros ────────────────────────────────────
    try:
        r = requests.get(base + "/thispagedoesnotexist12345", timeout=8, verify=False, headers=headers)
        version_patterns = [
            r"Apache/[\d.]+", r"nginx/[\d.]+", r"PHP/[\d.]+",
            r"Express [\d.]+", r"Rails [\d.]+", r"Django/[\d.]+",
        ]
        for pattern in version_patterns:
            match = re.search(pattern, r.text, re.IGNORECASE)
            if match:
                findings.append({
                    "severity": "medium",
                    "title": f"Versão exposta em página de erro: {match.group()}",
                    "detail": "Versões específicas de software em páginas de erro facilitam ataques direcionados.",
                    "fix": "Configure páginas de erro customizadas. Desabilite exibição de versão no servidor.",
                })
    except:
        pass

    # ── 5. Formulários sem CSRF token ────────────────────────────────────────
    try:
        r = requests.get(base, timeout=8, verify=False, headers=headers)
        forms = re.findall(r'<form[^>]*>.*?</form>', r.text, re.DOTALL | re.IGNORECASE)
        csrf_tokens = ["csrf", "_token", "authenticity_token", "csrfmiddlewaretoken"]
        for form in forms:
            if any(m in form.lower() for m in ["post", "method"]):
                has_csrf = any(t in form.lower() for t in csrf_tokens)
                if not has_csrf:
                    findings.append({
                        "severity": "high",
                        "title": "Formulário POST sem CSRF token detectado",
                        "detail": "Formulários sem proteção CSRF permitem que sites maliciosos façam requisições em nome do usuário.",
                        "fix": "Implemente CSRF tokens em todos os formulários POST. Frameworks como Django, Laravel e Rails fazem isso automaticamente.",
                    })
                    break
    except:
        pass

    # ── 6. Clickjacking via iFrame ───────────────────────────────────────────
    try:
        r = requests.get(base, timeout=8, verify=False, headers=headers)
        has_xframe = "x-frame-options" in {k.lower() for k in r.headers}
        has_csp_frame = "frame-ancestors" in r.headers.get("content-security-policy", "").lower()
        if not has_xframe and not has_csp_frame:
            findings.append({
                "severity": "medium",
                "title": "Site vulnerável a Clickjacking",
                "detail": "O site pode ser embutido em iframes de outros domínios.",
                "fix": "Adicione X-Frame-Options: DENY ou use CSP com frame-ancestors 'none'.",
            })
    except:
        pass

    # ── 7. HTTP Method testing ────────────────────────────────────────────────
    try:
        r = requests.options(base, timeout=8, verify=False, headers=headers)
        allow_header = r.headers.get("Allow", "")
        if allow_header:
            methods = [m.strip().upper() for m in allow_header.split(",")]
            dangerous_methods = [m for m in methods if m in ("PUT", "DELETE", "TRACE")]
            if dangerous_methods:
                findings.append({
                    "severity": "medium",
                    "title": f"Métodos HTTP perigosos habilitados: {', '.join(dangerous_methods)}",
                    "detail": f"O servidor aceita os métodos: {allow_header}. Métodos como PUT, DELETE e TRACE podem ser explorados.",
                    "fix": "Desabilite métodos HTTP desnecessários no servidor web. Mantenha apenas GET, POST e HEAD.",
                })
    except:
        pass

    # ── 8. Mixed content detection ───────────────────────────────────────────
    if base.startswith("https://"):
        try:
            r = requests.get(base, timeout=8, verify=False, headers=headers)
            mixed_patterns = [
                (r'<script[^>]+src=["\']http://[^"\'>]+', "script"),
                (r'<link[^>]+href=["\']http://[^"\'>]+', "stylesheet"),
                (r'<iframe[^>]+src=["\']http://[^"\'>]+', "iframe"),
            ]
            for pattern, resource_type in mixed_patterns:
                matches = re.findall(pattern, r.text, re.IGNORECASE)
                for match in matches[:3]:  # Limitar a 3 por tipo
                    findings.append({
                        "severity": "medium",
                        "title": f"Mixed content detectado ({resource_type})",
                        "detail": f"Página HTTPS carrega recurso HTTP inseguro: {match[:120]}",
                        "fix": f"Altere todos os recursos {resource_type} para usar HTTPS. Use URLs relativas ao protocolo ou force HTTPS.",
                    })
        except:
            pass

    return {"module": "OWASP Web", "icon": "ti-bug", "findings": findings}
