import requests
import urllib3
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup

urllib3.disable_warnings()

HEADERS_BASE = {"User-Agent": "Mozilla/5.0 VulnScanner/2.0"}


def _build_headers(auth=None):
    h = dict(HEADERS_BASE)
    if auth:
        if auth.get('auth_headers'):
            h.update(auth['auth_headers'])
        if auth.get('cookies'):
            h['Cookie'] = auth['cookies']
    return h

# ── Mapeamento de cookies → tecnologia ───────────────────────────────────────
COOKIE_TECH_MAP = {
    "phpsessid": "PHP",
    "jsessionid": "Java",
    "asp.net_sessionid": "ASP.NET",
    "csrftoken": "Django",
    "_rails_session": "Ruby on Rails",
    "laravel_session": "Laravel",
    "ci_session": "CodeIgniter",
    "connect.sid": "Express.js / Node.js",
    "wp-settings": "WordPress",
    "_ga": "Google Analytics",
}

# ── Mapeamento de caminhos → tecnologia ──────────────────────────────────────
PATH_TECH_MAP = [
    ("/wp-content/", "WordPress"),
    ("/wp-includes/", "WordPress"),
    ("/wp-admin/", "WordPress"),
    ("/static/admin/", "Django"),
    ("/sites/default/", "Drupal"),
    ("/misc/drupal.js", "Drupal"),
    ("/media/jui/", "Joomla"),
    ("/components/com_", "Joomla"),
    ("/assets/vendor/", "Laravel"),
    ("/bundles/", "Symfony"),
    ("/rails/", "Ruby on Rails"),
    ("/node_modules/", "Node.js"),
]

# ── Mapeamento de headers WAF ────────────────────────────────────────────────
WAF_HEADER_MAP = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "x-akamai-transformed": "Akamai",
    "x-cdn": "CDN genérico",
    "x-fw-hash": "Fortinet FortiWeb",
    "x-powered-by-plesk": "Plesk",
    "x-incapsula-key": "Imperva Incapsula",
    "x-iinfo": "Imperva Incapsula",
    "x-distil-cs": "Distil Networks",
    "x-protected-by": "WAF genérico",
    "server": None,  # Tratado separadamente para detecção de WAF por valor
}

WAF_SERVER_VALUES = [
    ("cloudflare", "Cloudflare"),
    ("sucuri", "Sucuri"),
    ("akamaighost", "Akamai"),
    ("bigip", "F5 BIG-IP"),
    ("barracuda", "Barracuda WAF"),
    ("mod_security", "ModSecurity"),
    ("imunify360", "Imunify360"),
]

# ── Padrões de página de bloqueio WAF ────────────────────────────────────────
WAF_BLOCK_PATTERNS = [
    ("cloudflare", "Cloudflare"),
    ("attention required!", "Cloudflare"),
    ("sucuri website firewall", "Sucuri"),
    ("access denied", "WAF genérico"),
    ("request blocked", "WAF genérico"),
    ("web application firewall", "WAF genérico"),
    ("mod_security", "ModSecurity"),
    ("not acceptable!", "ModSecurity"),
    ("wordfence", "Wordfence (WordPress)"),
]

# ── Bibliotecas JS vulneráveis ───────────────────────────────────────────────
VULNERABLE_JS = [
    {
        "lib": "jQuery",
        "pattern": re.compile(r"jquery[.-]?(\d+\.\d+\.\d+)", re.IGNORECASE),
        "vulnerable_below": (3, 5, 0),
        "detail": "Versões do jQuery anteriores a 3.5.0 possuem vulnerabilidades XSS conhecidas (CVE-2020-11022, CVE-2020-11023).",
        "fix": "Atualize o jQuery para a versão 3.5.0 ou superior.",
    },
    {
        "lib": "AngularJS",
        "pattern": re.compile(r"angular[.-]?(\d+\.\d+\.\d+)", re.IGNORECASE),
        "vulnerable_below": (1, 6, 0),
        "detail": "Versões do AngularJS anteriores a 1.6.0 possuem vulnerabilidades de sandbox escape e XSS.",
        "fix": "Migre para Angular moderno (v2+) ou atualize AngularJS para >= 1.6.0.",
    },
    {
        "lib": "Bootstrap",
        "pattern": re.compile(r"bootstrap[.-]?(\d+\.\d+\.\d+)", re.IGNORECASE),
        "vulnerable_below": (4, 3, 1),
        "detail": "Versões do Bootstrap anteriores a 4.3.1 possuem vulnerabilidades XSS em componentes como tooltip e popover.",
        "fix": "Atualize o Bootstrap para a versão 4.3.1 ou superior.",
    },
    {
        "lib": "Lodash",
        "pattern": re.compile(r"lodash[.-]?(\d+\.\d+\.\d+)", re.IGNORECASE),
        "vulnerable_below": (4, 17, 12),
        "detail": "Versões do Lodash anteriores a 4.17.12 possuem vulnerabilidades de prototype pollution.",
        "fix": "Atualize o Lodash para a versão 4.17.12 ou superior.",
    },
    {
        "lib": "Moment.js",
        "pattern": re.compile(r"moment[.-]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
        "vulnerable_below": None,  # Deprecado independente da versão
        "detail": "Moment.js está oficialmente deprecado. Possui vulnerabilidades de ReDoS e problemas de tamanho de bundle.",
        "fix": "Migre para alternativas modernas como date-fns, Luxon ou Day.js.",
    },
]


def _parse_version(version_str: str) -> tuple:
    """Converte string de versão em tupla para comparação."""
    try:
        parts = version_str.split(".")
        return tuple(int(p) for p in parts)
    except (ValueError, AttributeError):
        return (0, 0, 0)


def check_tech(url: str, auth=None) -> dict:
    """Detecta tecnologias, WAFs e bibliotecas JS vulneráveis."""
    findings = []
    if not url.startswith("http"):
        url = "https://" + url

    detected_techs = set()
    detected_wafs = set()
    tech_versions = {}  # {tech_name: version_string}

    try:
        resp = requests.get(
            url, timeout=10, verify=False, headers=_build_headers(auth),
            allow_redirects=True,
        )
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text
        soup = BeautifulSoup(body, "html.parser")

        # ── 1. Detecção por headers de resposta ──────────────────────────
        server_header = headers.get("server", "")
        if server_header:
            detected_techs.add(f"Server: {server_header}")
            # Extrair versão
            match = re.search(r"(Apache|nginx|IIS|LiteSpeed)[/ ]?([\d.]+)?", server_header, re.IGNORECASE)
            if match:
                tech_name = match.group(1)
                tech_ver = match.group(2) or ""
                if tech_ver:
                    tech_versions[tech_name.lower()] = tech_ver

        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            detected_techs.add(f"X-Powered-By: {powered_by}")
            match = re.search(r"(PHP|ASP\.NET|Express|JSP)[/ ]?([\d.]+)?", powered_by, re.IGNORECASE)
            if match:
                tech_name = match.group(1)
                tech_ver = match.group(2) or ""
                if tech_ver:
                    tech_versions[tech_name.lower()] = tech_ver

        aspnet_ver = headers.get("x-aspnet-version", "")
        if aspnet_ver:
            detected_techs.add(f"ASP.NET: {aspnet_ver}")
            tech_versions["asp.net"] = aspnet_ver

        generator_header = headers.get("x-generator", "")
        if generator_header:
            detected_techs.add(f"Generator: {generator_header}")

        # ── 2. Detecção por meta tags ────────────────────────────────────
        for meta in soup.find_all("meta", attrs={"name": True}):
            name = meta.get("name", "").lower()
            content = meta.get("content", "")
            if name == "generator" and content:
                detected_techs.add(f"Generator: {content}")
                match = re.search(r"(WordPress|Drupal|Joomla|Hugo|Jekyll|Ghost)[/ ]?([\d.]+)?", content, re.IGNORECASE)
                if match:
                    tech_versions[match.group(1).lower()] = match.group(2) or ""

        # ── 3. Detecção por comentários HTML ─────────────────────────────
        comments = soup.find_all(string=lambda text: isinstance(text, type(soup.new_string(""))) and "<!--" in str(text) if text else False)
        # Procurar padrões em comentários via regex no body
        comment_matches = re.findall(r"<!--.*?-->", body, re.DOTALL)
        tech_comment_patterns = [
            (r"WordPress", "WordPress"),
            (r"Drupal", "Drupal"),
            (r"Joomla", "Joomla"),
            (r"wp-content", "WordPress"),
            (r"django", "Django"),
        ]
        for comment in comment_matches[:50]:  # Limitar para performance
            for pattern, tech_name in tech_comment_patterns:
                if re.search(pattern, comment, re.IGNORECASE):
                    detected_techs.add(f"Comentário HTML: {tech_name}")

        # ── 4. Detecção por cookies ──────────────────────────────────────
        cookies = resp.headers.get("Set-Cookie", "")
        all_cookies = resp.cookies.keys() if resp.cookies else []
        cookie_str = cookies.lower() + " " + " ".join(all_cookies).lower()
        for cookie_name, tech in COOKIE_TECH_MAP.items():
            if cookie_name in cookie_str:
                detected_techs.add(f"Cookie: {tech}")

        # ── 5. Detecção por caminhos conhecidos ──────────────────────────
        for path, tech in PATH_TECH_MAP:
            if path in body:
                detected_techs.add(f"Caminho: {tech}")

        # ── 6. Detecção de WAF por headers ───────────────────────────────
        for header_name, waf_name in WAF_HEADER_MAP.items():
            if header_name in headers:
                if waf_name:
                    detected_wafs.add(waf_name)

        # WAF por valor do header Server
        for pattern, waf_name in WAF_SERVER_VALUES:
            if pattern in server_header.lower():
                detected_wafs.add(waf_name)

        # ── 7. Detecção de WAF por resposta a payload ────────────────────
        try:
            xss_test_url = url.rstrip("/") + "/?test=<script>alert(1)</script>"
            waf_resp = requests.get(
                xss_test_url, timeout=10, verify=False, headers=_build_headers(auth),
                allow_redirects=True,
            )

            if waf_resp.status_code in (403, 406, 429, 503):
                # Provável bloqueio de WAF
                waf_body = waf_resp.text.lower()
                waf_identified = False
                for pattern, waf_name in WAF_BLOCK_PATTERNS:
                    if pattern in waf_body:
                        detected_wafs.add(waf_name)
                        waf_identified = True
                if not waf_identified:
                    detected_wafs.add("WAF detectado (não identificado)")
        except Exception:
            pass

        # ── 8. Verificar bibliotecas JS vulneráveis ──────────────────────
        script_srcs = []
        for script in soup.find_all("script", src=True):
            script_srcs.append(script["src"])

        # Também verificar scripts inline com versões
        inline_scripts = " ".join(
            s.string for s in soup.find_all("script") if s.string
        )
        all_script_text = " ".join(script_srcs) + " " + inline_scripts

        for lib_info in VULNERABLE_JS:
            match = lib_info["pattern"].search(all_script_text)
            if not match:
                # Tentar encontrar nos src dos scripts
                for src in script_srcs:
                    match = lib_info["pattern"].search(src)
                    if match:
                        break

            if match:
                version_str = match.group(1) if match.lastindex and match.group(1) else None

                if lib_info["vulnerable_below"] is None:
                    # Deprecado (ex: Moment.js)
                    findings.append({
                        "severity": "medium",
                        "title": f"Biblioteca JS deprecada: {lib_info['lib']}",
                        "detail": (
                            f"Versão detectada: {version_str or 'desconhecida'}. "
                            f"{lib_info['detail']}"
                        ),
                        "fix": lib_info["fix"],
                    })
                elif version_str:
                    version_tuple = _parse_version(version_str)
                    if version_tuple < lib_info["vulnerable_below"]:
                        target_ver = ".".join(str(v) for v in lib_info["vulnerable_below"])
                        findings.append({
                            "severity": "medium",
                            "title": f"Biblioteca JS vulnerável: {lib_info['lib']} {version_str}",
                            "detail": (
                                f"Versão detectada: {version_str} (vulnerável abaixo de "
                                f"{target_ver}). {lib_info['detail']}"
                            ),
                            "fix": lib_info["fix"],
                        })

        # ── Gerar findings de tecnologias ────────────────────────────────
        if detected_techs:
            tech_list = "\n".join(f"  • {t}" for t in sorted(detected_techs))
            findings.append({
                "severity": "info",
                "title": "Tecnologias detectadas",
                "detail": f"Tecnologias identificadas no alvo:\n{tech_list}",
                "fix": "",
            })

        # ── Gerar findings de WAF ────────────────────────────────────────
        if detected_wafs:
            waf_list = ", ".join(sorted(detected_wafs))
            findings.append({
                "severity": "info",
                "title": f"WAF / CDN detectado: {waf_list}",
                "detail": (
                    f"Firewall de aplicação web detectado: {waf_list}. "
                    f"Isso pode influenciar os resultados de outros módulos de "
                    f"escaneamento, pois o WAF pode bloquear payloads de teste."
                ),
                "fix": "",
            })
        else:
            findings.append({
                "severity": "info",
                "title": "Nenhum WAF detectado",
                "detail": (
                    "Nenhum Web Application Firewall foi identificado nos testes. "
                    "O site pode não ter WAF ou utilizar um não reconhecido."
                ),
                "fix": "",
            })

        if not detected_techs and not detected_wafs:
            findings.append({
                "severity": "info",
                "title": "Nenhuma tecnologia identificada",
                "detail": "Não foi possível identificar tecnologias no alvo.",
                "fix": "",
            })

    except Exception as e:
        findings.append({
            "severity": "info",
            "title": "Erro ao detectar tecnologias",
            "detail": str(e),
            "fix": "",
        })

    return {
        "module": "Tecnologias / WAF",
        "icon": "ti-cpu",
        "findings": findings,
        "tech_data": {
            "technologies": list(detected_techs),
            "wafs": list(detected_wafs),
            "versions": tech_versions,
        },
    }
