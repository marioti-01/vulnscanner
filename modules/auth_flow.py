"""
Auth Flow — realiza login por formulário e retorna sessão autenticada.
Permite escanear áreas protegidas além de cookie/header estático.
"""

import requests
import urllib3
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

urllib3.disable_warnings()

HEADERS = {"User-Agent": "Mozilla/5.0 VulnScanner/4.0"}


def _find_login_form(soup: BeautifulSoup, page_url: str) -> dict | None:
    """Encontra o formulário de login na página."""
    password_input_names = ["password", "passwd", "pass", "senha", "pwd"]

    for form in soup.find_all("form"):
        inputs = form.find_all("input")
        input_types = [i.get("type", "text").lower() for i in inputs]
        input_names = [i.get("name", "").lower() for i in inputs]

        has_password = "password" in input_types or any(
            p in n for n in input_names for p in password_input_names
        )
        has_text = any(t in ("text", "email") for t in input_types)

        if has_password and has_text:
            action = form.get("action", "")
            method = form.get("method", "POST").upper()
            full_action = urljoin(page_url, action) if action else page_url

            field_map = {}
            for inp in inputs:
                name = inp.get("name", "")
                val = inp.get("value", "")
                itype = inp.get("type", "text").lower()
                if name:
                    field_map[name] = val  # Preserva tokens hidden

            return {
                "action": full_action,
                "method": method,
                "fields": field_map,
                "inputs": inputs,
            }
    return None


def _detect_field_names(form_data: dict, fields: dict) -> tuple[str, str]:
    """Tenta identificar os campos de username e password."""
    username_hints = ["user", "email", "login", "nome", "username", "identifier", "mail"]
    password_hints = ["pass", "pwd", "senha", "secret"]

    username_field = None
    password_field = None

    for name in fields:
        name_lower = name.lower()
        for hint in password_hints:
            if hint in name_lower:
                password_field = name
                break
        if password_field == name:
            continue
        for hint in username_hints:
            if hint in name_lower:
                username_field = name
                break

    # Fallback: primeiro campo de texto, segundo de password
    if not username_field or not password_field:
        text_fields = [k for k, v in form_data.get("field_types", {}).items()
                       if v in ("text", "email")]
        pwd_fields = [k for k, v in form_data.get("field_types", {}).items()
                      if v == "password"]
        if text_fields:
            username_field = username_field or text_fields[0]
        if pwd_fields:
            password_field = password_field or pwd_fields[0]

    return username_field, password_field


def login(
    login_url: str,
    username: str,
    password: str,
    username_field: str = None,
    password_field: str = None,
    extra_fields: dict = None,
) -> dict:
    """
    Realiza login por formulário.

    Retorna dict com:
    - success: bool
    - session: requests.Session (autenticada) ou None
    - cookies: str (para uso nos outros módulos)
    - auth_headers: dict
    - message: str (diagnóstico)
    """
    session = requests.Session()
    session.headers.update(HEADERS)

    result = {
        "success": False,
        "session": None,
        "cookies": "",
        "auth_headers": {},
        "message": "",
    }

    try:
        # 1. GET na página de login para pegar tokens CSRF
        resp = session.get(login_url, timeout=10, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")

        form = _find_login_form(soup, login_url)
        if not form:
            result["message"] = "Formulário de login não encontrado na URL informada."
            return result

        # 2. Montar payload com todos os campos do form (preserva CSRF tokens)
        payload = dict(form["fields"])  # Copia campos existentes (hidden tokens)

        # Adicionar campos extras
        if extra_fields:
            payload.update(extra_fields)

        # Identificar campos de user/pass se não informados
        field_types = {}
        for inp in form["inputs"]:
            name = inp.get("name", "")
            itype = inp.get("type", "text").lower()
            if name:
                field_types[name] = itype

        if not username_field or not password_field:
            u_field, p_field = _detect_field_names(
                {"field_types": field_types}, payload
            )
            username_field = username_field or u_field
            password_field = password_field or p_field

        if not username_field or not password_field:
            result["message"] = (
                f"Não foi possível identificar os campos de login. "
                f"Campos disponíveis: {list(payload.keys())}. "
                f"Use username_field e password_field para especificar manualmente."
            )
            return result

        payload[username_field] = username
        payload[password_field] = password

        # 3. Submete o formulário
        if form["method"] == "POST":
            login_resp = session.post(
                form["action"], data=payload, timeout=10, verify=False,
                allow_redirects=True,
            )
        else:
            login_resp = session.get(
                form["action"], params=payload, timeout=10, verify=False,
                allow_redirects=True,
            )

        # 4. Detectar se o login teve sucesso
        fail_indicators = [
            "invalid", "incorrect", "wrong", "failed", "error",
            "inválid", "incorret", "erro", "senha incorreta", "usuário não encontrado",
            "login failed", "authentication failed",
        ]
        success_indicators = [
            "dashboard", "logout", "sign out", "sair", "perfil", "profile",
            "welcome", "bem-vindo", "painel", "minha conta",
        ]

        body_lower = login_resp.text.lower()
        url_lower = login_resp.url.lower()

        has_fail = any(f in body_lower for f in fail_indicators)
        has_success = any(s in body_lower or s in url_lower for s in success_indicators)
        redirected_away_from_login = "login" not in url_lower and "signin" not in url_lower

        login_succeeded = (not has_fail and has_success) or (
            not has_fail and redirected_away_from_login and login_resp.status_code == 200
        )

        if login_succeeded:
            # Extrai cookies da sessão
            cookie_str = "; ".join(
                f"{c.name}={c.value}" for c in session.cookies
            )
            result["success"] = True
            result["session"] = session
            result["cookies"] = cookie_str
            result["auth_headers"] = dict(session.headers)
            result["message"] = (
                f"Login realizado com sucesso. "
                f"URL final: {login_resp.url}. "
                f"Cookies: {cookie_str[:100]}{'...' if len(cookie_str) > 100 else ''}"
            )
        else:
            result["message"] = (
                f"Login falhou ou não foi possível confirmar. "
                f"URL final: {login_resp.url}. "
                f"Status: {login_resp.status_code}. "
                f"Verifique as credenciais e os nomes dos campos."
            )

    except Exception as e:
        result["message"] = f"Erro durante o login: {str(e)}"

    return result


def check_auth_flow(url: str, auth=None) -> dict:
    """
    Módulo de integração — descobre e documenta o fluxo de autenticação do alvo.
    Não realiza login (isso é feito pela rota /login da API).
    Apenas analisa o formulário de login para o relatório.
    """
    findings = []
    if not url.startswith("http"):
        url = "https://" + url

    # Tentar encontrar a página de login
    login_paths = ["/login", "/signin", "/auth", "/account/login",
                   "/user/login", "/admin/login", "/wp-login.php", "/entrar"]
    login_url = None
    login_soup = None
    session = requests.Session()
    session.headers.update(HEADERS)
    if auth and auth.get("cookies"):
        session.headers["Cookie"] = auth["cookies"]
    if auth and auth.get("auth_headers"):
        session.headers.update(auth["auth_headers"])

    for path in login_paths:
        try:
            resp = session.get(url.rstrip("/") + path, timeout=6, verify=False,
                               allow_redirects=True)
            if resp.status_code == 200 and resp.url != url:
                soup = BeautifulSoup(resp.text, "html.parser")
                form = _find_login_form(soup, resp.url)
                if form:
                    login_url = resp.url
                    login_soup = soup
                    break
        except Exception:
            continue

    if not login_url:
        # Tenta a URL raiz
        try:
            resp = session.get(url, timeout=8, verify=False)
            soup = BeautifulSoup(resp.text, "html.parser")
            form = _find_login_form(soup, url)
            if form:
                login_url = url
                login_soup = soup
        except Exception:
            pass

    if login_url and login_soup:
        form = _find_login_form(login_soup, login_url)
        if form:
            # Verificar CSRF no form de login
            has_csrf = any(
                any(t in (inp.get("name", "").lower()) for t in
                    ["csrf", "_token", "authenticity_token", "csrfmiddlewaretoken"])
                for inp in form["inputs"]
            )

            findings.append({
                "severity": "info",
                "title": f"Formulário de login encontrado: {login_url}",
                "detail": (
                    f"Ação: {form['action']} | Método: {form['method']} | "
                    f"Campos: {', '.join(form['fields'].keys())} | "
                    f"CSRF token: {'✓ presente' if has_csrf else '✗ ausente'}"
                ),
                "fix": "",
            })

            if not has_csrf:
                findings.append({
                    "severity": "high",
                    "title": "Formulário de login sem CSRF token",
                    "detail": "O formulário de login não possui proteção CSRF, vulnerável a ataques de login forçado cross-site.",
                    "fix": "Adicione token CSRF ao formulário de login.",
                })

            # Verificar se login é via HTTP
            if login_url.startswith("http://"):
                findings.append({
                    "severity": "critical",
                    "title": "Login realizado via HTTP (sem criptografia)",
                    "detail": f"O formulário de login em {login_url} envia credenciais sem criptografia.",
                    "fix": "Force HTTPS para qualquer página que contenha formulário de login.",
                })
    else:
        findings.append({
            "severity": "info",
            "title": "Formulário de login não encontrado nos caminhos comuns",
            "detail": f"Caminhos testados: {', '.join(login_paths)}",
            "fix": "",
        })

    return {"module": "Auth Flow", "icon": "ti-login", "findings": findings}
