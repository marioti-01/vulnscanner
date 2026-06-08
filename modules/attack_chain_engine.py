"""
Attack Chain Engine
═══════════════════
O diferencial único do VulnScanner.

Após o scan completo, analisa TODOS os findings em conjunto e usa IA
para raciocinar sobre combinações exploráveis — descobrindo cadeias de
ataque que nenhuma ferramenta automatizada do mercado detecta.

Exemplo: XSS + CORS permissivo + Cookie sem HttpOnly + ausência de CSRF
= Account Takeover completo — reportado como cadeia única com PoC e
remediação integrada, não como 4 findings isolados.
"""

import json
import re
import requests as req
from typing import List, Dict

ANTHROPIC_API = "https://api.anthropic.com/v1/messages"
MODEL = "claude-opus-4-20250514"

# ── Regras de correlação estática (rápidas, sem API) ────────────────────────
# Cada regra define um conjunto de condições e o chain que elas formam.
# Usadas como "hints" para o LLM e como fallback offline.

STATIC_CHAIN_RULES = [
    {
        "id": "account_takeover_xss_cookie",
        "title": "Account Takeover via XSS + Cookie sem HttpOnly",
        "severity": "critical",
        "requires_any": [
            ["xss refletido", "xss detectado"],
            ["httponly", "sem flag httponly", "cookie sem"],
        ],
        "description": (
            "XSS refletido permite execução de JavaScript no contexto da vítima. "
            "Com cookies sem HttpOnly, o atacante pode roubar a sessão via document.cookie. "
            "Resultado: Account Takeover completo sem interação adicional do servidor."
        ),
    },
    {
        "id": "cors_csrf_data_exfil",
        "title": "Exfiltração de Dados via CORS Permissivo + Ausência de CSRF",
        "severity": "critical",
        "requires_any": [
            ["cors", "origin", "wildcard"],
            ["csrf", "sem csrf", "token ausente"],
        ],
        "description": (
            "CORS mal configurado permite que sites maliciosos façam requisições autenticadas. "
            "Sem CSRF token, ações sensíveis podem ser executadas cross-origin. "
            "Resultado: Exfiltração de dados e execução de ações em nome da vítima."
        ),
    },
    {
        "id": "info_disclosure_to_sqli",
        "title": "Escalada: Exposição de Versão → SQLi Direcionado",
        "severity": "high",
        "requires_any": [
            ["versão exposta", "server:", "x-powered-by", "php/", "mysql"],
            ["sql injection", "sqli", "blind sqli"],
        ],
        "description": (
            "A versão do banco/servidor exposta em headers ou páginas de erro permite "
            "ao atacante selecionar exploits específicos para aquela versão. "
            "Combinado com SQLi detectado, o ataque é trivialmente direcionado."
        ),
    },
    {
        "id": "subdomain_takeover_prep",
        "title": "Preparação para Subdomain Takeover",
        "severity": "high",
        "requires_any": [
            ["subdomínio", "subdomain", "dns"],
            ["cname", "registro", "zone transfer"],
        ],
        "description": (
            "Subdomínios expostos com registros DNS apontando para serviços descontinuados "
            "podem ser registrados por atacantes, permitindo phishing e roubo de cookies "
            "de subdomínio se os cookies não tiverem SameSite=Strict."
        ),
    },
    {
        "id": "ssrf_to_internal",
        "title": "SSRF → Acesso a Serviços Internos + Exfiltração",
        "severity": "critical",
        "requires_any": [
            ["ssrf", "server-side request"],
            ["redis", "mongodb", "elasticsearch", "docker api", "porta aberta"],
        ],
        "description": (
            "SSRF permite ao atacante fazer o servidor buscar URLs internas. "
            "Combinado com serviços internos sem autenticação detectados pelo port scanner, "
            "o atacante pode ler dados do Redis/MongoDB ou executar comandos via Docker API."
        ),
    },
    {
        "id": "xxe_to_ssrf_chain",
        "title": "XXE → SSRF → Metadados de Cloud",
        "severity": "critical",
        "requires_any": [
            ["xxe", "xml external", "entidade xml"],
            ["aws", "metadata", "169.254", "cloud"],
        ],
        "description": (
            "XXE pode ser usado como vetor de SSRF para acessar endpoints de metadados "
            "de cloud (AWS/GCP/Azure). Isso expõe credenciais IAM temporárias, "
            "permitindo acesso completo à infraestrutura cloud."
        ),
    },
    {
        "id": "idor_privilege_escalation",
        "title": "IDOR + Ausência de Rate Limiting → Enumeração e Escalada",
        "severity": "high",
        "requires_any": [
            ["idor", "insecure direct object"],
            ["rate limit", "brute force", "sem proteção"],
        ],
        "description": (
            "IDOR permite acessar objetos de outros usuários. Sem rate limiting, "
            "o atacante pode enumerar todos os IDs da aplicação, coletando dados "
            "de todos os usuários sistematicamente."
        ),
    },
    {
        "id": "http_downgrade_mitm",
        "title": "Downgrade HTTP + Ausência de HSTS → Man-in-the-Middle",
        "severity": "high",
        "requires_any": [
            ["hsts ausente", "strict-transport", "http"],
            ["redirect", "http para https", "sem https"],
        ],
        "description": (
            "Sem HSTS, um atacante em posição de MITM pode forçar downgrade para HTTP. "
            "Combinado com cookies sem flag Secure, credenciais e tokens de sessão "
            "são transmitidos em texto puro e capturáveis."
        ),
    },
    {
        "id": "full_recon_package",
        "title": "Reconhecimento Completo: Zone Transfer + Subdomínios + Versões",
        "severity": "high",
        "requires_any": [
            ["zone transfer", "axfr", "subdomínio"],
            ["versão", "server:", "tecnologia detectada", "fingerprint"],
        ],
        "description": (
            "Zone transfer expõe toda a infraestrutura DNS. Combinado com fingerprinting "
            "de tecnologias e versões, o atacante obtém um mapa completo para ataques "
            "direcionados sem precisar fazer varreduras adicionais."
        ),
    },
]


def _extract_findings_summary(modules_results: List[Dict]) -> List[Dict]:
    """Extrai findings relevantes (não-info) para análise da chain engine."""
    findings = []
    for mod in modules_results:
        for f in mod.get("findings", []):
            if f.get("severity") == "info":
                continue
            findings.append({
                "module": mod.get("module", ""),
                "severity": f.get("severity", ""),
                "title": f.get("title", ""),
                "detail": f.get("detail", "")[:200],
                "cvss": f.get("cvss", ""),
            })
    return findings


def _run_static_correlation(findings: List[Dict]) -> List[Dict]:
    """
    Correlação estática rápida — detecta chains por palavras-chave.
    Retorna chains detectados antes de enviar para o LLM.
    """
    all_text = " ".join(
        f"{f['title']} {f['detail']}".lower() for f in findings
    )

    detected = []
    for rule in STATIC_CHAIN_RULES:
        # Verifica se PELO MENOS UM item de cada grupo está presente
        all_groups_matched = True
        for group in rule["requires_any"]:
            group_matched = any(kw in all_text for kw in group)
            if not group_matched:
                all_groups_matched = False
                break

        if all_groups_matched:
            detected.append({
                "id": rule["id"],
                "title": rule["title"],
                "severity": rule["severity"],
                "description": rule["description"],
                "source": "static",
            })

    return detected


def _build_llm_prompt(url: str, findings: List[Dict], static_chains: List[Dict]) -> str:
    """Monta o prompt para o Claude raciocinar sobre as chains."""
    findings_json = json.dumps(findings, ensure_ascii=False, indent=2)
    static_json = json.dumps(
        [{"title": c["title"], "description": c["description"]} for c in static_chains],
        ensure_ascii=False, indent=2
    )

    return f"""Você é um penetration tester sênior analisando resultados de um scanner de vulnerabilidades.

Alvo: {url}

Findings encontrados (não-info):
{findings_json}

Chains já detectadas por correlação estática (use como contexto, mas vá além):
{static_json}

Sua tarefa:
1. Analise os findings acima e identifique CADEIAS DE ATAQUE (attack chains) — combinações de 2 ou mais vulnerabilidades que juntas criam um impacto maior do que individualmente.
2. Para cada chain, gere um PoC conceitual realista (não precisa ser código funcional, mas deve ser tecnicamente preciso).
3. Vá além das chains estáticas — descubra combinações não óbvias.
4. Seja conciso e técnico. Não inclua chains com menos de 2 findings reais dos resultados.
5. Máximo de 6 chains. Priorize pelo impacto real.

Responda SOMENTE com JSON válido neste formato (sem markdown, sem texto antes ou depois):
{{
  "chains": [
    {{
      "id": "chain_slug_unico",
      "title": "Título técnico da chain",
      "severity": "critical|high|medium",
      "cvss_estimate": "9.8",
      "findings_involved": ["título do finding 1", "título do finding 2"],
      "attack_narrative": "Descrição técnica passo a passo de como um atacante exploraria essa combinação.",
      "poc_conceptual": "PoC técnico conceitual — código, payloads ou sequência de passos concretos.",
      "impact": "Impacto real no negócio/dados.",
      "unified_fix": "Remediação integrada que resolve toda a chain."
    }}
  ],
  "overall_assessment": "Parágrafo com avaliação geral da postura de segurança considerando as chains encontradas.",
  "most_critical_chain": "id da chain mais crítica"
}}"""


def _call_claude_api(prompt: str) -> dict | None:
    """Chama a API do Claude para análise de chains."""
    try:
        response = req.post(
            ANTHROPIC_API,
            headers={"Content-Type": "application/json"},
            json={
                "model": MODEL,
                "max_tokens": 4000,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=60,
        )

        if response.status_code != 200:
            return None

        data = response.json()
        text = ""
        for block in data.get("content", []):
            if block.get("type") == "text":
                text += block.get("text", "")

        # Remove markdown fences se existirem
        text = re.sub(r"```json\s*", "", text)
        text = re.sub(r"```\s*", "", text)
        text = text.strip()

        return json.loads(text)

    except Exception:
        return None


def _build_chains_from_static(static_chains: List[Dict], findings: List[Dict]) -> List[Dict]:
    """
    Fallback: constrói chains a partir das regras estáticas quando
    a API não está disponível.
    """
    result = []
    for chain in static_chains:
        # Encontra findings relacionados
        involved = []
        chain_text = (chain["title"] + " " + chain["description"]).lower()
        keywords = chain_text.split()[:10]
        for f in findings:
            f_text = (f["title"] + " " + f["detail"]).lower()
            if any(kw in f_text for kw in keywords if len(kw) > 4):
                involved.append(f["title"])

        result.append({
            "id": chain["id"],
            "title": chain["title"],
            "severity": chain["severity"],
            "cvss_estimate": "9.0" if chain["severity"] == "critical" else "7.5",
            "findings_involved": involved[:4],
            "attack_narrative": chain["description"],
            "poc_conceptual": "Análise de PoC requer API key configurada.",
            "impact": "Veja a descrição da chain para detalhes de impacto.",
            "unified_fix": "Corrija individualmente cada finding envolvido para quebrar a chain.",
            "source": "static",
        })
    return result


def analyze_attack_chains(
    url: str,
    modules_results: List[Dict],
    use_ai: bool = True,
) -> Dict:
    """
    Ponto de entrada principal do Attack Chain Engine.

    Args:
        url: URL do alvo
        modules_results: Lista de resultados de todos os módulos
        use_ai: Se True, usa Claude API para análise profunda.
                Se False, usa apenas correlação estática.

    Returns:
        Dict com chains detectadas, avaliação geral e metadados.
    """
    findings = _extract_findings_summary(modules_results)

    if not findings:
        return {
            "module": "Attack Chain Engine",
            "icon": "ti-arrows-join",
            "chains": [],
            "overall_assessment": "Nenhum finding relevante para correlacionar.",
            "most_critical_chain": None,
            "ai_analysis": False,
            "findings": [{
                "severity": "info",
                "title": "Nenhuma chain detectada — sem findings relevantes",
                "detail": "Não há vulnerabilidades suficientes para formar cadeias de ataque.",
                "fix": "",
            }],
        }

    # 1. Correlação estática (sempre executa)
    static_chains = _run_static_correlation(findings)

    # 2. Análise com IA (se habilitado)
    ai_result = None
    if use_ai and len(findings) >= 2:
        prompt = _build_llm_prompt(url, findings, static_chains)
        ai_result = _call_claude_api(prompt)

    # 3. Monta resultado final
    if ai_result and ai_result.get("chains"):
        chains = ai_result["chains"]
        overall = ai_result.get("overall_assessment", "")
        most_critical = ai_result.get("most_critical_chain", "")
        ai_analysis = True

        # Marca chains que vieram da análise estática também
        static_ids = {c["id"] for c in static_chains}
        for chain in chains:
            chain["source"] = "ai+static" if chain.get("id") in static_ids else "ai"
    else:
        # Fallback para correlação estática
        chains = _build_chains_from_static(static_chains, findings)
        overall = (
            f"Análise baseada em correlação estática ({len(static_chains)} chains). "
            "Configure a API key do Claude para análise profunda com PoC e narrativas detalhadas."
        ) if static_chains else "Nenhuma chain detectada por correlação estática."
        most_critical = chains[0]["id"] if chains else None
        ai_analysis = False

    # 4. Converte chains para formato de findings (para integração com report)
    sev_order = {"critical": 0, "high": 1, "medium": 2}
    chains_sorted = sorted(chains, key=lambda c: sev_order.get(c.get("severity", "medium"), 99))

    findings_output = []
    for chain in chains_sorted:
        sev = chain.get("severity", "high")
        involved_str = " → ".join(chain.get("findings_involved", []))
        ai_badge = "🤖 IA" if chain.get("source", "").startswith("ai") else "⚡ Estático"

        findings_output.append({
            "severity": sev,
            "title": f"[CHAIN {ai_badge}] {chain['title']}",
            "detail": (
                f"**Findings envolvidos:** {involved_str}\n\n"
                f"**Narrativa de ataque:** {chain.get('attack_narrative', '')}\n\n"
                f"**PoC conceitual:** {chain.get('poc_conceptual', '')}\n\n"
                f"**Impacto:** {chain.get('impact', '')}"
            ),
            "fix": chain.get("unified_fix", ""),
            "cvss": chain.get("cvss_estimate", ""),
            "chain_data": chain,
        })

    if not findings_output:
        findings_output.append({
            "severity": "info",
            "title": "Nenhuma attack chain detectada",
            "detail": (
                f"Analisados {len(findings)} findings. "
                "Nenhuma combinação exploitável identificada."
            ),
            "fix": "",
        })

    return {
        "module": "Attack Chain Engine",
        "icon": "ti-arrows-join",
        "chains": chains_sorted,
        "overall_assessment": overall,
        "most_critical_chain": most_critical,
        "ai_analysis": ai_analysis,
        "chains_count": len(chains_sorted),
        "findings_analyzed": len(findings),
        "findings": findings_output,
    }
