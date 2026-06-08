import requests

HEADERS_CHECKS = [
    {
        "header": "Strict-Transport-Security",
        "missing_severity": "high",
        "missing_title": "HSTS ausente",
        "missing_detail": "Sem HSTS, um atacante pode forçar conexões HTTP não criptografadas (downgrade attack).",
        "missing_fix": "Adicione: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "present_check": lambda v: ("high", "HSTS com max-age muito baixo", "max-age deve ser >= 31536000 (1 ano).", "Aumente o max-age para pelo menos 31536000.")
            if "max-age" in v and any(int(x.split("=")[1]) < 31536000 for x in v.split(";") if "max-age" in x) else None,
    },
    {
        "header": "Content-Security-Policy",
        "missing_severity": "high",
        "missing_title": "CSP ausente",
        "missing_detail": "Sem Content-Security-Policy, o site é vulnerável a ataques XSS e injeção de conteúdo.",
        "missing_fix": "Implemente uma CSP restritiva: Content-Security-Policy: default-src 'self'",
        "present_check": lambda v: ("medium", "CSP contém 'unsafe-inline'", "'unsafe-inline' permite execução de scripts inline, enfraquecendo proteção XSS.", "Remova 'unsafe-inline' e use nonces ou hashes.")
            if "unsafe-inline" in v else None,
    },
    {
        "header": "X-Frame-Options",
        "missing_severity": "medium",
        "missing_title": "X-Frame-Options ausente",
        "missing_detail": "Sem este header, o site pode ser embutido em iframes maliciosos (clickjacking).",
        "missing_fix": "Adicione: X-Frame-Options: DENY  ou use CSP frame-ancestors.",
        "present_check": None,
    },
    {
        "header": "X-Content-Type-Options",
        "missing_severity": "medium",
        "missing_title": "X-Content-Type-Options ausente",
        "missing_detail": "Sem este header, browsers podem interpretar mal o tipo de conteúdo (MIME sniffing).",
        "missing_fix": "Adicione: X-Content-Type-Options: nosniff",
        "present_check": None,
    },
    {
        "header": "Referrer-Policy",
        "missing_severity": "low",
        "missing_title": "Referrer-Policy ausente",
        "missing_detail": "Sem este header, URLs com dados sensíveis podem vazar para sites externos.",
        "missing_fix": "Adicione: Referrer-Policy: strict-origin-when-cross-origin",
        "present_check": None,
    },
    {
        "header": "Permissions-Policy",
        "missing_severity": "low",
        "missing_title": "Permissions-Policy ausente",
        "missing_detail": "Sem este header, funcionalidades como câmera e microfone não estão explicitamente restritas.",
        "missing_fix": "Adicione: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "present_check": None,
    },
]

DANGEROUS_HEADERS = [
    ("Server", "medium", "Header 'Server' expõe tecnologia",
     "O header Server revela informações do servidor web ao atacante.",
     "Configure o servidor para não expor a versão: ServerTokens Prod (Apache) ou server_tokens off (Nginx)."),
    ("X-Powered-By", "medium", "Header 'X-Powered-By' expõe tecnologia",
     "Revela a tecnologia backend (ex: PHP/7.4.3), facilitando ataques direcionados.",
     "Remova o header X-Powered-By. Em PHP: expose_php = Off"),
    ("X-AspNet-Version", "medium", "Header 'X-AspNet-Version' expõe versão .NET",
     "Revela a versão do ASP.NET, permitindo ataques direcionados a versões vulneráveis.",
     "Adicione ao web.config: <httpRuntime enableVersionHeader='false'/>"),
]

HEADERS_BASE = {"User-Agent": "Mozilla/5.0 VulnScanner/1.0"}


def _build_headers(auth=None):
    h = dict(HEADERS_BASE)
    if auth and auth.get('auth_headers'):
        h.update(auth['auth_headers'])
    if auth and auth.get('cookies'):
        h['Cookie'] = auth['cookies']
    return h


def check_headers(url: str, auth=None) -> dict:
    findings = []
    if not url.startswith("http"):
        url = "https://" + url

    try:
        resp = requests.get(url, timeout=10, verify=False, allow_redirects=True,
                            headers=_build_headers(auth))
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Verificar headers de segurança obrigatórios
        for chk in HEADERS_CHECKS:
            hval = headers.get(chk["header"].lower())
            if hval is None:
                findings.append({
                    "severity": chk["missing_severity"],
                    "title": chk["missing_title"],
                    "detail": chk["missing_detail"],
                    "fix": chk["missing_fix"],
                })
            else:
                findings.append({
                    "severity": "info",
                    "title": f"{chk['header']} presente",
                    "detail": f"Valor: {hval[:120]}",
                    "fix": "",
                })
                if chk["present_check"]:
                    extra = chk["present_check"](hval)
                    if extra:
                        sev, title, detail, fix = extra
                        findings.append({"severity": sev, "title": title, "detail": detail, "fix": fix})

        # Verificar headers que não deveriam existir
        for hname, severity, title, detail, fix in DANGEROUS_HEADERS:
            if hname.lower() in headers:
                val = headers[hname.lower()]
                findings.append({
                    "severity": severity,
                    "title": title,
                    "detail": f"{detail} Valor encontrado: {val}",
                    "fix": fix,
                })

        # Cookie sem flags de segurança
        set_cookie = resp.headers.get("Set-Cookie", "")
        if set_cookie:
            if "httponly" not in set_cookie.lower():
                findings.append({
                    "severity": "high",
                    "title": "Cookie sem flag HttpOnly",
                    "detail": "Cookies sem HttpOnly podem ser roubados via JavaScript (XSS).",
                    "fix": "Adicione a flag HttpOnly em todos os cookies de sessão.",
                })
            if "secure" not in set_cookie.lower():
                findings.append({
                    "severity": "medium",
                    "title": "Cookie sem flag Secure",
                    "detail": "Cookies sem Secure podem ser enviados por HTTP sem criptografia.",
                    "fix": "Adicione a flag Secure em todos os cookies.",
                })
            if "samesite" not in set_cookie.lower():
                findings.append({
                    "severity": "medium",
                    "title": "Cookie sem flag SameSite",
                    "detail": "Sem SameSite, cookies podem ser enviados em requisições cross-site (CSRF).",
                    "fix": "Adicione SameSite=Strict ou SameSite=Lax nos cookies.",
                })

    except Exception as e:
        findings.append({"severity": "info", "title": "Erro ao verificar headers", "detail": str(e), "fix": ""})

    return {"module": "Headers HTTP", "icon": "ti-world", "findings": findings}
