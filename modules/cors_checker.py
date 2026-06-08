import requests
import urllib3
from urllib.parse import urlparse

urllib3.disable_warnings()

HEADERS_BASE = {"User-Agent": "Mozilla/5.0 VulnScanner/2.0"}


def _build_headers(auth=None):
    h = dict(HEADERS_BASE)
    if auth and auth.get('auth_headers'):
        h.update(auth['auth_headers'])
    if auth and auth.get('cookies'):
        h['Cookie'] = auth['cookies']
    return h


def check_cors(url: str, auth=None) -> dict:
    """Verifica a política CORS do alvo com diferentes cabeçalhos Origin."""
    findings = []
    if not url.startswith("http"):
        url = "https://" + url

    parsed = urlparse(url)
    target_domain = parsed.netloc

    # Origens de teste
    test_origins = [
        {
            "origin": "https://evil.com",
            "label": "domínio externo malicioso (evil.com)",
        },
        {
            "origin": "null",
            "label": "origin null (sandboxed iframe / data URI)",
        },
        {
            "origin": f"https://sub.{target_domain}",
            "label": f"subdomínio do alvo (sub.{target_domain})",
        },
    ]

    cors_tested = False

    try:
        # Primeiro, requisição sem Origin para baseline
        try:
            baseline = requests.get(
                url, timeout=10, verify=False, headers=_build_headers(auth),
                allow_redirects=True,
            )
            baseline_acao = baseline.headers.get("Access-Control-Allow-Origin", "")
        except Exception:
            baseline_acao = ""

        for test in test_origins:
            try:
                headers = {**_build_headers(auth), "Origin": test["origin"]}
                resp = requests.get(
                    url, timeout=10, verify=False, headers=headers,
                    allow_redirects=True,
                )

                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
                has_credentials = acac == "true"

                if not acao:
                    continue

                cors_tested = True

                # ── Wildcard * com credentials ───────────────────────────
                if acao == "*" and has_credentials:
                    findings.append({
                        "severity": "critical",
                        "title": "CORS: Wildcard (*) com Access-Control-Allow-Credentials",
                        "detail": (
                            f"O servidor retorna Access-Control-Allow-Origin: * junto com "
                            f"Access-Control-Allow-Credentials: true. Isso pode permitir "
                            f"que qualquer site leia respostas autenticadas da API. "
                            f"Origin de teste: {test['label']}."
                        ),
                        "fix": (
                            "Nunca combine '*' com credentials. Valide origens "
                            "permitidas contra uma lista branca e retorne apenas "
                            "origens explicitamente autorizadas."
                        ),
                    })
                    continue

                # ── Origem refletida sem validação ───────────────────────
                if acao == test["origin"] and test["origin"] == "https://evil.com":
                    severity = "critical" if has_credentials else "high"
                    findings.append({
                        "severity": severity,
                        "title": "CORS: Origem refletida sem validação",
                        "detail": (
                            f"O servidor refletiu a origem '{test['origin']}' no "
                            f"header Access-Control-Allow-Origin. "
                            f"Credentials: {acac or 'não enviado'}. "
                            f"Isso permite que domínios arbitrários acessem "
                            f"recursos do site."
                        ),
                        "fix": (
                            "Implemente uma lista branca de origens permitidas "
                            "no servidor. Não reflita o header Origin sem validação."
                        ),
                    })
                    continue

                # ── Null origin aceito ───────────────────────────────────
                if test["origin"] == "null" and acao == "null":
                    findings.append({
                        "severity": "high",
                        "title": "CORS: Origem 'null' permitida",
                        "detail": (
                            "O servidor aceita 'null' como origem válida. "
                            "Iframes sandboxed e redirecionamentos podem "
                            "explorar essa configuração para acessar dados "
                            f"do site. Credentials: {acac or 'não enviado'}."
                        ),
                        "fix": (
                            "Não inclua 'null' na lista de origens permitidas. "
                            "Bloqueie requisições com Origin: null."
                        ),
                    })
                    continue

                # ── Subdomínio aceito (pode ser permissivo demais) ───────
                if test["origin"].startswith("https://sub.") and acao == test["origin"]:
                    findings.append({
                        "severity": "medium",
                        "title": "CORS: Subdomínio aceito de forma ampla",
                        "detail": (
                            f"O servidor aceita a origem '{test['origin']}' "
                            f"(subdomínio inexistente). Se validação é por sufixo, "
                            f"um atacante com controle de subdomínio pode explorar "
                            f"o CORS. Credentials: {acac or 'não enviado'}."
                        ),
                        "fix": (
                            "Valide origens CORS contra uma lista branca exata. "
                            "Não use validação por sufixo ou regex permissiva."
                        ),
                    })
                    continue

                # ── Wildcard * sem credentials (geralmente aceitável) ────
                if acao == "*" and not has_credentials:
                    findings.append({
                        "severity": "info",
                        "title": "CORS: Wildcard (*) sem credentials",
                        "detail": (
                            f"O servidor retorna Access-Control-Allow-Origin: * "
                            f"sem credentials. Isso permite que qualquer site leia "
                            f"respostas públicas, o que pode ser intencional para "
                            f"APIs públicas. Origin de teste: {test['label']}."
                        ),
                        "fix": (
                            "Se a API não for pública, restrinja as origens "
                            "permitidas a domínios específicos."
                        ),
                    })
                    continue

            except Exception as e:
                findings.append({
                    "severity": "info",
                    "title": f"Erro ao testar CORS com origin {test['label']}",
                    "detail": str(e),
                    "fix": "",
                })

        # ── Se nenhum CORS configurado ───────────────────────────────────
        if not cors_tested and not findings:
            findings.append({
                "severity": "info",
                "title": "CORS não configurado",
                "detail": (
                    "O servidor não retornou headers Access-Control-Allow-Origin "
                    "para nenhuma das origens de teste. Isso pode indicar que CORS "
                    "não está habilitado ou que o site não é uma API."
                ),
                "fix": "",
            })

        # ── Caso todas as origens estejam corretas ───────────────────────
        if cors_tested and not any(
            f["severity"] in ("critical", "high", "medium") for f in findings
        ):
            findings.append({
                "severity": "info",
                "title": "Política CORS configurada corretamente",
                "detail": (
                    "O servidor não refletiu origens maliciosas e não apresentou "
                    "configurações permissivas nos testes realizados."
                ),
                "fix": "",
            })

    except Exception as e:
        findings.append({
            "severity": "info",
            "title": "Erro ao verificar CORS",
            "detail": str(e),
            "fix": "",
        })

    return {"module": "CORS Policy", "icon": "ti-shield-lock", "findings": findings}
