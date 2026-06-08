"""
False Positive Filter
Re-verifica findings de alta severidade antes de incluir no relatório,
reduzindo ruído e aumentando confiança nos resultados.
"""

import requests
import urllib3
import time
import difflib
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


def _recheck_xss(finding: dict, auth=None, limiter=None) -> tuple[bool, str]:
    """Re-verifica XSS refletido."""
    detail = finding.get("detail", "")

    # Extrai parâmetro e payload do detail
    import re
    param_match = re.search(r"parâmetro '([^']+)'", detail)
    payload_match = re.search(r"Payload.*?: (.+)$", detail, re.MULTILINE)
    url_match = re.search(r"URL.*?: (https?://\S+)", detail)

    if not (param_match and payload_match):
        return True, "Não foi possível re-verificar (dados insuficientes no finding)"

    param = param_match.group(1)
    payload = payload_match.group(1)[:100]

    # Re-testa 3 vezes para confirmar
    confirmations = 0
    for _ in range(3):
        try:
            if limiter:
                limiter.wait()
            url_base = url_match.group(1).split("?")[0] if url_match else ""
            if not url_base:
                return True, "URL não encontrada para re-verificação"

            resp = requests.get(
                f"{url_base}?{param}={requests.utils.quote(payload)}",
                timeout=8, verify=False, headers=_build_headers(auth)
            )
            # Verificar se payload está no body MAS não em comentário HTML
            body = resp.text
            if payload.lower() in body.lower():
                # Checar se está dentro de comentário (falso positivo comum)
                import re as re2
                comment_pattern = re2.compile(r'<!--.*?-->', re2.DOTALL)
                body_no_comments = comment_pattern.sub('', body)
                if payload.lower() in body_no_comments.lower():
                    confirmations += 1
        except Exception:
            pass
        time.sleep(0.3)

    if confirmations >= 2:
        return True, f"Confirmado em {confirmations}/3 tentativas"
    elif confirmations == 1:
        return True, "Confirmado parcialmente (1/3) — pode ser intermitente"
    else:
        return False, "Não confirmado em re-verificação — possível falso positivo"


def _recheck_sqli_time(finding: dict, auth=None, limiter=None) -> tuple[bool, str]:
    """Re-verifica SQLi time-based."""
    import re
    detail = finding.get("detail", "")
    title = finding.get("title", "")

    param_match = re.search(r"parâmetro[: ']*([a-zA-Z0-9_]+)", detail)
    url_match = re.search(r"(https?://\S+?)(?:\?|\s|$)", detail)

    if not param_match:
        return True, "Dados insuficientes para re-verificação"

    param = param_match.group(1)

    # Baseline
    try:
        if limiter:
            limiter.wait()
        base_url = url_match.group(1) if url_match else ""
        if not base_url:
            return True, "URL não encontrada"

        t0 = time.time()
        requests.get(f"{base_url}?{param}=1", timeout=10,
                     verify=False, headers=_build_headers(auth))
        baseline = time.time() - t0
    except Exception:
        return True, "Erro ao obter baseline"

    # Re-testa time-based
    sleep_payload = f"1' AND SLEEP(3)--"
    delays = []
    for _ in range(2):
        try:
            if limiter:
                limiter.wait()
            t0 = time.time()
            requests.get(
                f"{base_url}?{param}={requests.utils.quote(sleep_payload)}",
                timeout=10, verify=False, headers=_build_headers(auth)
            )
            delays.append(time.time() - t0)
        except requests.exceptions.Timeout:
            delays.append(10.0)
        except Exception:
            pass
        time.sleep(0.5)

    if not delays:
        return True, "Não foi possível re-testar"

    avg_delay = sum(delays) / len(delays)
    if avg_delay > baseline + 2.0:
        return True, f"Confirmado — delay médio: {avg_delay:.1f}s (baseline: {baseline:.1f}s)"
    else:
        return False, f"Não confirmado — delay: {avg_delay:.1f}s (baseline: {baseline:.1f}s)"


def _recheck_open_redirect(finding: dict, auth=None, limiter=None) -> tuple[bool, str]:
    """Re-verifica open redirect."""
    import re
    detail = finding.get("detail", "")
    param_match = re.search(r"parâmetro '([^']+)'", detail)
    if not param_match:
        return True, "Dados insuficientes"

    param = param_match.group(1)
    try:
        if limiter:
            limiter.wait()
        resp = requests.get(
            f"/?{param}=https://evil.com",
            timeout=8, verify=False, headers=_build_headers(auth),
            allow_redirects=False
        )
        if resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location", "")
            if "evil.com" in loc:
                return True, f"Confirmado — redireciona para: {loc}"
        return False, "Redirect não confirmado na re-verificação"
    except Exception as e:
        return True, f"Erro na re-verificação: {e}"


# Mapa de estratégias de re-verificação por tipo de finding
RECHECK_STRATEGIES = {
    "xss": _recheck_xss,
    "sqli time": _recheck_sqli_time,
    "blind sqli time": _recheck_sqli_time,
    "open redirect": _recheck_open_redirect,
}


def filter_false_positives(
    modules_results: list,
    auth=None,
    rate_profile: str = "normal",
    severities_to_check: tuple = ("critical", "high"),
) -> tuple[list, list]:
    """
    Re-verifica findings de alta severidade.

    Retorna:
    - modules_results atualizado (com findings marcados)
    - log de re-verificações
    """
    limiter = get_limiter(rate_profile)
    recheck_log = []
    fp_count = 0
    confirmed_count = 0

    for mod in modules_results:
        for finding in mod.get("findings", []):
            if finding.get("severity") not in severities_to_check:
                continue

            title_lower = finding.get("title", "").lower()

            # Encontra estratégia de re-verificação
            strategy = None
            for key, fn in RECHECK_STRATEGIES.items():
                if key in title_lower:
                    strategy = fn
                    break

            if not strategy:
                continue

            # Executa re-verificação
            try:
                confirmed, reason = strategy(finding, auth=auth, limiter=limiter)
            except Exception as e:
                confirmed, reason = True, f"Erro na re-verificação: {e}"

            finding["verified"] = confirmed
            finding["verification_note"] = reason

            if confirmed:
                confirmed_count += 1
                recheck_log.append({
                    "finding": finding["title"][:60],
                    "result": "✓ Confirmado",
                    "reason": reason,
                })
            else:
                fp_count += 1
                # Rebaixa severidade em vez de remover
                original_sev = finding["severity"]
                finding["severity"] = "info"
                finding["title"] = f"[FP?] {finding['title']}"
                finding["detail"] += f"\n\n⚠️ Re-verificação: {reason} — Severidade rebaixada de {original_sev} para info."
                recheck_log.append({
                    "finding": finding["title"][:60],
                    "result": "✗ Possível FP",
                    "reason": reason,
                })

    return modules_results, recheck_log, confirmed_count, fp_count
