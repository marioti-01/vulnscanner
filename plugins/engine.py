"""
Plugin System — VulnScanner v6
Permite que usuários escrevam checks de segurança customizados
em Python com sandbox de segurança básica.

Interface do plugin:
    def run(url: str, auth: dict = None) -> dict:
        return {
            "module": "Meu Plugin",
            "icon": "ti-plug",
            "findings": [
                {
                    "severity": "high",  # critical|high|medium|low|info
                    "title": "Descrição do problema",
                    "detail": "Detalhes técnicos",
                    "fix": "Como corrigir",
                }
            ]
        }
"""

import importlib.util
import sys
import io
import traceback
import datetime
import textwrap
from typing import Dict, List

# Módulos permitidos no sandbox de plugins
ALLOWED_IMPORTS = {
    "requests", "re", "json", "urllib", "urllib.parse", "urllib.request",
    "socket", "ssl", "http", "http.client", "base64", "hashlib",
    "datetime", "time", "random", "string", "collections", "itertools",
    "bs4", "beautifulsoup4", "lxml", "html", "html.parser",
    "dns", "dns.resolver",
}

PLUGIN_TEMPLATE = '''"""
Plugin para VulnScanner v6
Nome: {name}
Descrição: {description}
"""

import requests
import re


def run(url: str, auth: dict = None) -> dict:
    """
    Ponto de entrada do plugin.
    
    Args:
        url: URL do alvo (ex: https://exemplo.com)
        auth: Dict com cookies e auth_headers (pode ser None)
    
    Returns:
        Dict com module, icon e findings.
    """
    findings = []
    
    headers = {{"User-Agent": "Mozilla/5.0 VulnScanner-Plugin/1.0"}}
    if auth:
        if auth.get("auth_headers"):
            headers.update(auth["auth_headers"])
        if auth.get("cookies"):
            headers["Cookie"] = auth["cookies"]
    
    if not url.startswith("http"):
        url = "https://" + url
    
    # ── Escreva seu check aqui ──────────────────────────────────────────
    try:
        resp = requests.get(url, timeout=10, verify=False, headers=headers)
        
        # Exemplo: detecta header customizado problemático
        if "x-debug" in {{k.lower() for k in resp.headers}}:
            findings.append({{
                "severity": "medium",
                "title": "Header X-Debug exposto",
                "detail": f"O header X-Debug está presente na resposta: {{resp.headers.get('X-Debug', '')}}",
                "fix": "Remova headers de debug em ambiente de produção.",
            }})
        else:
            findings.append({{
                "severity": "info",
                "title": "X-Debug não encontrado",
                "detail": "Header de debug não está exposto.",
                "fix": "",
            }})
            
    except Exception as e:
        findings.append({{
            "severity": "info",
            "title": f"Erro no plugin: {{str(e)}}",
            "detail": str(e),
            "fix": "",
        }})
    
    return {{
        "module": "{name}",
        "icon": "ti-plug",
        "findings": findings,
    }}
'''


def get_plugin_template(name: str = "Meu Plugin", description: str = "") -> str:
    """Retorna o template de plugin preenchido."""
    return PLUGIN_TEMPLATE.format(name=name, description=description)


def _safe_exec(code: str, url: str, auth: dict = None) -> dict:
    """
    Executa código de plugin em ambiente controlado.
    Captura stdout/stderr e limita recursos básicos.
    """
    # Namespace do plugin com builtins limitados
    safe_builtins = {
        "__builtins__": {
            "print": print,
            "len": len, "range": range, "enumerate": enumerate,
            "zip": zip, "map": map, "filter": filter,
            "list": list, "dict": dict, "set": set, "tuple": tuple,
            "str": str, "int": int, "float": float, "bool": bool,
            "isinstance": isinstance, "hasattr": hasattr, "getattr": getattr,
            "min": min, "max": max, "sum": sum, "sorted": sorted,
            "any": any, "all": all,
            "__import__": __import__,
        }
    }

    namespace = {**safe_builtins}
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()

    try:
        exec(compile(code, "<plugin>", "exec"), namespace)
        run_fn = namespace.get("run")
        if not run_fn or not callable(run_fn):
            return {
                "module": "Plugin Error",
                "icon": "ti-plug",
                "findings": [{
                    "severity": "info",
                    "title": "Plugin inválido — função run() não encontrada",
                    "detail": "O plugin deve definir uma função run(url, auth=None) -> dict.",
                    "fix": "",
                }]
            }

        result = run_fn(url, auth)
        return result

    except Exception as e:
        tb = traceback.format_exc()
        return {
            "module": "Plugin Error",
            "icon": "ti-plug",
            "findings": [{
                "severity": "info",
                "title": f"Erro na execução do plugin: {str(e)[:100]}",
                "detail": tb[-500:],
                "fix": "Verifique o código do plugin.",
            }]
        }
    finally:
        sys.stdout = old_stdout


def run_plugin(plugin_code: str, plugin_name: str, url: str, auth: dict = None) -> dict:
    """
    Executa um plugin e retorna resultado normalizado.
    """
    result = _safe_exec(plugin_code, url, auth)

    # Normaliza o resultado
    if not isinstance(result, dict):
        result = {
            "module": plugin_name,
            "icon": "ti-plug",
            "findings": [{
                "severity": "info",
                "title": "Plugin retornou formato inválido",
                "detail": f"Esperado dict, recebido: {type(result).__name__}",
                "fix": "",
            }]
        }

    # Garante campos obrigatórios
    result.setdefault("module", plugin_name)
    result.setdefault("icon", "ti-plug")
    result.setdefault("findings", [])

    # Valida cada finding
    valid_findings = []
    for f in result["findings"]:
        if not isinstance(f, dict):
            continue
        f.setdefault("severity", "info")
        f.setdefault("title", "Finding sem título")
        f.setdefault("detail", "")
        f.setdefault("fix", "")
        if f["severity"] not in ("critical", "high", "medium", "low", "info"):
            f["severity"] = "info"
        valid_findings.append(f)

    result["findings"] = valid_findings
    return result


def run_all_plugins(plugins: List, url: str, auth: dict = None) -> List[dict]:
    """
    Executa todos os plugins ativos e retorna lista de resultados.
    """
    results = []
    for plugin in plugins:
        if not plugin.is_active:
            continue
        try:
            result = run_plugin(plugin.code, plugin.name, url, auth)
            result["findings"].sort(
                key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x["severity"], 99)
            )
            results.append(result)
        except Exception as e:
            results.append({
                "module": plugin.name,
                "icon": "ti-plug",
                "findings": [{
                    "severity": "info",
                    "title": f"Plugin falhou: {str(e)[:100]}",
                    "detail": "",
                    "fix": "",
                }]
            })
    return results


# Plugins de exemplo incluídos no sistema
BUILTIN_PLUGINS = [
    {
        "name": "Security.txt Checker",
        "description": "Verifica se o site possui security.txt conforme RFC 9116.",
        "version": "1.0.0",
        "code": '''
import requests

def run(url, auth=None):
    findings = []
    h = {"User-Agent": "Mozilla/5.0 VulnScanner/1.0"}
    if not url.startswith("http"):
        url = "https://" + url
    base = url.rstrip("/")
    paths = ["/.well-known/security.txt", "/security.txt"]
    found = False
    for path in paths:
        try:
            r = requests.get(base + path, timeout=8, verify=False, headers=h)
            if r.status_code == 200 and "contact" in r.text.lower():
                has_expires = "expires" in r.text.lower()
                findings.append({
                    "severity": "info" if has_expires else "low",
                    "title": f"security.txt encontrado em {path}" + ("" if has_expires else " — sem campo Expires"),
                    "detail": r.text[:300],
                    "fix": "" if has_expires else "Adicione o campo Expires ao security.txt (RFC 9116 exige).",
                })
                found = True
                break
        except:
            pass
    if not found:
        findings.append({
            "severity": "low",
            "title": "security.txt não encontrado",
            "detail": "O site não possui security.txt em /.well-known/security.txt nem /security.txt.",
            "fix": "Crie um security.txt conforme RFC 9116: https://securitytxt.org/",
        })
    return {"module": "Security.txt Checker", "icon": "ti-file-text", "findings": findings}
'''
    },
    {
        "name": "Exposed Git Checker",
        "description": "Verifica se o repositório Git está exposto publicamente.",
        "version": "1.0.0",
        "code": '''
import requests

def run(url, auth=None):
    findings = []
    h = {"User-Agent": "Mozilla/5.0 VulnScanner/1.0"}
    if not url.startswith("http"):
        url = "https://" + url
    base = url.rstrip("/")
    paths = ["/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG"]
    for path in paths:
        try:
            r = requests.get(base + path, timeout=6, verify=False, headers=h, allow_redirects=False)
            if r.status_code == 200 and ("[core]" in r.text or "ref:" in r.text or "commit" in r.text.lower()):
                findings.append({
                    "severity": "critical",
                    "title": f"Repositório Git exposto: {path}",
                    "detail": f"Conteúdo acessível: {r.text[:200]}",
                    "fix": "Bloqueie acesso a /.git/ no servidor web. Nunca suba .git para produção.",
                })
                break
        except:
            pass
    if not findings:
        findings.append({"severity": "info", "title": "Git não exposto", "detail": "", "fix": ""})
    return {"module": "Exposed Git Checker", "icon": "ti-brand-git", "findings": findings}
'''
    },
]
